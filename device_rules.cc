/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "config.h"

#include <chrono>
#include <fstream>
#include <sstream>
#include <unordered_set>

#include <dirent.h>
#include <fcntl.h>
#include <glob.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alertracker.h"
#include "configfile.h"
#include "device_rules.h"
#include "devicetracker_view_workers.h"
#include "entrytracker.h"
#include "messagebus.h"
#include "packetchain.h"
#include "timetracker.h"

namespace {

constexpr size_t max_rules_text = 256 * 1024;
constexpr size_t max_views = 256;
constexpr unsigned int max_nesting = 4;
constexpr const char *api_origin = "api";

using namespace devicerules;

tracker_element *deref_alias(tracker_element *e) {
    while (e != nullptr && e->get_type() == tracker_type::tracker_alias)
        e = static_cast<tracker_element_alias *>(e)->get().get();
    return e;
}

// Device field access over the tracked element tree; the device is locked by the caller
class kismet_env : public env {
public:
    tracker_element *root = nullptr;

    virtual bool load(const field_slot& f, value& out) override {
        auto e = walk(root, f, 0, f.path.size());
        if (e == nullptr)
            return false;
        return leaf(e, out);
    }

    virtual bool any(const field_slot& f, bool (*fn)(const value&, const void *), const void *arg) override {
        return fan(root, f, 0, fn, arg, nullptr);
    }

    virtual int64_t count(const field_slot& f) override {
        if (!f.multi) {
            auto e = walk(root, f, 0, f.path.size());
            if (e == nullptr)
                return 0;
            return container_size(e);
        }

        int64_t c = 0;
        fan(root, f, 0, nullptr, nullptr, &c);
        return c;
    }

    virtual bool exists(const field_slot& f) override {
        return found(root, f, 0);
    }

    virtual void reset() override {
        holds.clear();
    }

private:
    // Children of lazily built maps only live as long as we hold them
    std::vector<shared_tracker_element> holds;

    tracker_element *child(tracker_element *e, int id) {
        e = deref_alias(e);
        if (e == nullptr || e->get_type() != tracker_type::tracker_map)
            return nullptr;

        shared_tracker_element hold;
        auto c = static_cast<tracker_element_map *>(e)->peek_sub(id, hold);
        if (hold != nullptr)
            holds.push_back(std::move(hold));
        return deref_alias(c);
    }

    // Walk plain path elements [from, to)
    tracker_element *walk(tracker_element *e, const field_slot& f, size_t from, size_t to) {
        for (size_t i = from; i < to && e != nullptr; i++)
            e = child(e, f.path[i]);
        return e;
    }

    static bool leaf(tracker_element *e, value& out) {
        out = value{};

        switch (e->get_type()) {
            case tracker_type::tracker_string: {
                const auto& s = static_cast<tracker_element_string *>(e)->get();
                out.s = s.data();
                out.len = s.size();
                break;
            }
            case tracker_type::tracker_string_pointer: {
                auto s = static_cast<tracker_element_string_ptr *>(e)->get();
                if (s == nullptr)
                    return false;
                out.s = s->data();
                out.len = s->size();
                break;
            }
            case tracker_type::tracker_int8:
                out.i = static_cast<tracker_element_int8 *>(e)->get();
                break;
            case tracker_type::tracker_uint8:
                out.i = static_cast<tracker_element_uint8 *>(e)->get();
                break;
            case tracker_type::tracker_int16:
                out.i = static_cast<tracker_element_int16 *>(e)->get();
                break;
            case tracker_type::tracker_uint16:
                out.i = static_cast<tracker_element_uint16 *>(e)->get();
                break;
            case tracker_type::tracker_int32:
                out.i = static_cast<tracker_element_int32 *>(e)->get();
                break;
            case tracker_type::tracker_uint32:
                out.i = static_cast<tracker_element_uint32 *>(e)->get();
                break;
            case tracker_type::tracker_int64:
                out.i = static_cast<tracker_element_int64 *>(e)->get();
                break;
            case tracker_type::tracker_uint64: {
                auto u = static_cast<tracker_element_uint64 *>(e)->get();
                // Out of the signed range is treated as missing
                if (u > (uint64_t) INT64_MAX)
                    return false;
                out.i = (int64_t) u;
                break;
            }
            case tracker_type::tracker_float:
                out.f = static_cast<tracker_element_float *>(e)->get();
                break;
            case tracker_type::tracker_double:
                out.f = static_cast<tracker_element_double *>(e)->get();
                break;
            case tracker_type::tracker_mac_addr:
                out.m = static_cast<tracker_element_mac_addr *>(e)->get().longmac;
                break;
            default:
                return false;
        }

        out.valid = 1;
        return true;
    }

    template<typename C, typename F>
    static bool each_value(C *c, F fn) {
        for (const auto& i : *c)
            if (fn(i.second.get()))
                return true;
        return false;
    }

    // Call fn for each element of a container until it returns true
    template<typename F>
    static bool each(tracker_element *c, F fn) {
        switch (c->get_type()) {
            case tracker_type::tracker_vector:
                for (const auto& i : *static_cast<tracker_element_vector *>(c))
                    if (fn(i.get()))
                        return true;
                return false;
            case tracker_type::tracker_int_map:
                return each_value(static_cast<tracker_element_int_map *>(c), fn);
            case tracker_type::tracker_hashkey_map:
                return each_value(static_cast<tracker_element_hashkey_map *>(c), fn);
            case tracker_type::tracker_double_map:
                return each_value(static_cast<tracker_element_double_map *>(c), fn);
            case tracker_type::tracker_string_map:
                return each_value(static_cast<tracker_element_string_map *>(c), fn);
            case tracker_type::tracker_key_map:
                return each_value(static_cast<tracker_element_device_key_map *>(c), fn);
            case tracker_type::tracker_uuid_map:
                return each_value(static_cast<tracker_element_uuid_map *>(c), fn);
            case tracker_type::tracker_mac_map: {
                // Filter maps share the type tag with a different container
                if (auto m = dynamic_cast<tracker_element_mac_map *>(c))
                    return each_value(m, fn);
                if (auto m = dynamic_cast<tracker_element_macfilter_map *>(c))
                    return each_value(m, fn);
                return false;
            }
            default:
                return false;
        }
    }

    static bool is_container(tracker_element *c) {
        switch (c->get_type()) {
            case tracker_type::tracker_vector:
            case tracker_type::tracker_int_map:
            case tracker_type::tracker_hashkey_map:
            case tracker_type::tracker_double_map:
            case tracker_type::tracker_string_map:
            case tracker_type::tracker_key_map:
            case tracker_type::tracker_uuid_map:
            case tracker_type::tracker_mac_map:
                return true;
            default:
                return false;
        }
    }

    // each(), looking through containers held in a container, as in a map of lists
    template<typename F>
    static bool each_record(tracker_element *c, F fn, unsigned int depth = 0) {
        return each(c, [&](tracker_element *e) {
                e = deref_alias(e);
                if (e == nullptr)
                    return false;
                if (is_container(e))
                    return depth < max_nesting && each_record(e, fn, depth + 1);
                return fn(e);
            });
    }

    static int64_t container_size(tracker_element *c) {
        switch (c->get_type()) {
            case tracker_type::tracker_vector:
                return static_cast<tracker_element_vector *>(c)->size();
            case tracker_type::tracker_vector_string:
                return static_cast<tracker_element_vector_string *>(c)->size();
            case tracker_type::tracker_vector_double:
                return static_cast<tracker_element_vector_double *>(c)->size();
            default: {
                int64_t n = 0;
                each(c, [&n](tracker_element *) { n++; return false; });
                return n;
            }
        }
    }

    // Leaves of a multi path from path element i of e
    bool fan(tracker_element *e, const field_slot& f, size_t i,
            bool (*fn)(const value&, const void *), const void *arg, int64_t *cnt) {
        while (i < f.path.size()) {
            e = child(e, f.path[i]);
            if (e == nullptr)
                return false;

            if (f.fanout[i]) {
                return each_record(e, [&](tracker_element *c) {
                        return fan(c, f, i + 1, fn, arg, cnt);
                    });
            }

            i++;
        }

        // Lists of plain values at the end of the path
        if (e->get_type() == tracker_type::tracker_vector_string) {
            for (const auto& s : *static_cast<tracker_element_vector_string *>(e)) {
                if (cnt != nullptr) {
                    (*cnt)++;
                    continue;
                }
                value v{};
                v.s = s.data();
                v.len = s.size();
                v.valid = 1;
                if (fn(v, arg))
                    return true;
            }
            return false;
        }

        if (e->get_type() == tracker_type::tracker_vector_double) {
            for (const auto& d : *static_cast<tracker_element_vector_double *>(e)) {
                if (cnt != nullptr) {
                    (*cnt)++;
                    continue;
                }
                value v{};
                v.f = d;
                v.valid = 1;
                if (fn(v, arg))
                    return true;
            }
            return false;
        }

        if (cnt != nullptr) {
            (*cnt)++;
            return false;
        }

        value v;
        if (!leaf(e, v))
            return false;
        return fn(v, arg);
    }

    bool found(tracker_element *e, const field_slot& f, size_t i) {
        while (i < f.path.size()) {
            e = child(e, f.path[i]);
            if (e == nullptr)
                return false;

            if (f.fanout[i])
                return each_record(e, [&](tracker_element *c) {
                        return found(c, f, i + 1);
                    });

            i++;
        }

        return true;
    }
};

class kismet_resolver : public resolver {
public:
    kismet_resolver(std::shared_ptr<entry_tracker> et) :
        entrytracker{et} { }

    virtual int resolve(const std::string& name, ftype& t) override {
        auto id = entrytracker->get_field_id(name);
        if (id == 0)
            return -1;

        auto inst = entrytracker->get_shared_instance(id);
        if (inst == nullptr)
            return -1;

        switch (inst->get_type()) {
            case tracker_type::tracker_string:
            case tracker_type::tracker_string_pointer:
                t = ftype::string;
                break;
            case tracker_type::tracker_int8:
            case tracker_type::tracker_uint8:
            case tracker_type::tracker_int16:
            case tracker_type::tracker_uint16:
            case tracker_type::tracker_int32:
            case tracker_type::tracker_uint32:
            case tracker_type::tracker_int64:
                t = ftype::integer;
                break;
            case tracker_type::tracker_uint64:
                t = ftype::uinteger;
                break;
            case tracker_type::tracker_float:
            case tracker_type::tracker_double:
                t = ftype::real;
                break;
            case tracker_type::tracker_mac_addr:
                t = ftype::mac;
                break;
            case tracker_type::tracker_map:
                t = ftype::map;
                break;
            case tracker_type::tracker_vector:
            case tracker_type::tracker_int_map:
            case tracker_type::tracker_hashkey_map:
            case tracker_type::tracker_double_map:
            case tracker_type::tracker_string_map:
            case tracker_type::tracker_key_map:
            case tracker_type::tracker_uuid_map:
            case tracker_type::tracker_mac_map:
                t = ftype::container;
                break;
            case tracker_type::tracker_vector_string:
                t = ftype::string_list;
                break;
            case tracker_type::tracker_vector_double:
                t = ftype::real_list;
                break;
            default:
                t = ftype::unsupported;
                break;
        }

        return id;
    }

private:
    std::shared_ptr<entry_tracker> entrytracker;
};

}

// Evaluation state for the timer pass
struct device_rules::pass_state {
    uint32_t gen = 0;
    devicerules::eval_ctx ctx;
    kismet_env env;
    std::vector<uint8_t> out, prev;
};

namespace {

// Reads rules from files, directories and config lines into one ruleset.  Only rules
// read from disk at startup may use 'include'; rules from the API never can.
class rules_loader {
public:
    // Rules are parsed into rs, and what was read is recorded in out
    rules_loader(devicerules::ruleset& in_rs, std::vector<device_rules::rules_chunk>& in_out) :
        rs{in_rs}, out{in_out}, total{0} { }

    // A missing file is skipped when it's optional, and logged otherwise
    void load_file(const std::string& path, bool required) {
        load_path(path, required, 0, out);
    }

    void load_dir(const std::string& path) {
        DIR *dir;
        struct dirent *de;
        struct stat st;
        std::vector<std::string> names;
        constexpr std::string_view ext{".rules"};

        if ((dir = opendir(path.c_str())) == nullptr) {
            if (errno == ENOENT)
                _MSG_INFO("Optional device rules directory not present: {}", path);
            else
                _MSG_ERROR("Could not read device rules directory '{}': {}", path, kis_strerror_r(errno));
            return;
        }

        const auto prefix = (path.length() > 0 && path.back() == '/') ? path : path + "/";

        while ((de = readdir(dir)) != nullptr) {
            std::string_view name{de->d_name};

            // Skip hidden files, which also covers editor swap files
            if (name.length() <= ext.length() || name[0] == '.')
                continue;
            if (name.substr(name.length() - ext.length()) != ext)
                continue;
            if (stat((prefix + de->d_name).c_str(), &st) != 0 || !S_ISREG(st.st_mode))
                continue;

            names.emplace_back(name);
        }

        closedir(dir);

        std::sort(names.begin(), names.end(),
                [](const std::string& a, const std::string& b) {
                    return natural_compare(a, b) < 0;
                });

        if (names.size() > max_dir_files) {
            _MSG_ERROR("Device rules directory '{}' has {} files, only loading the first {}",
                    path, names.size(), max_dir_files);
            names.resize(max_dir_files);
        }

        for (const auto& n : names)
            load_path(prefix + n, true, 0, out);
    }

    // One rule or sort from a config line, without its leading keyword
    void load_line(const config_file::sourced_value& v, devicerules::parse_source::block kind) {
        charge(v.value.size());

        device_rules::rules_chunk chunk;
        chunk.text = v.value;
        chunk.origin = v.file;
        chunk.line_base = v.line > 0 ? v.line - 1 : 0;
        chunk.col_base = v.col > 0 ? v.col - 1 : 0;
        chunk.only = kind;

        devicerules::parse_source src;
        src.origin = chunk.origin;
        src.line_base = chunk.line_base;
        src.col_base = chunk.col_base;
        src.only = kind;
        rs.parse(chunk.text, src);

        out.push_back(std::move(chunk));
    }

private:
    static constexpr size_t max_dir_files = 256;
    static constexpr int max_include_depth = 8;

    devicerules::ruleset& rs;
    std::vector<device_rules::rules_chunk>& out;
    size_t total;
    std::unordered_set<std::string> loaded;

    void charge(size_t n) {
        total += n;
        if (total > max_rules_text)
            throw devicerules::parse_error("rules are larger than " + std::to_string(max_rules_text) +
                    " bytes in all", 0, 0);
    }

    static bool has_glob(const std::string& p) {
        return p.find_first_of("*?[") != std::string::npos;
    }

    void load_path(const std::string& path, bool required, int depth,
            std::vector<device_rules::rules_chunk>& into) {
        std::string text;
        std::string real;

        int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) {
            if (errno == ENOENT && !required)
                return;
            if (errno == ENOENT && depth == 0) {
                _MSG_ERROR("Device rules file '{}' not found, skipping it", path);
                return;
            }
            throw devicerules::parse_error("can't open device rules file '" + path + "': " +
                    kis_strerror_r(errno), 0, 0);
        }

        try {
            // Check the file we opened, not the name, and never read devices or fifos
            struct stat st;
            if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
                throw devicerules::parse_error("device rules file '" + path + "' isn't a regular file", 0, 0);

            char *rp = realpath(path.c_str(), nullptr);
            real = rp != nullptr ? rp : path;
            free(rp);

            if (!loaded.insert(real).second) {
                _MSG_INFO("Device rules file '{}' is already loaded, skipping it", path);
                close(fd);
                return;
            }

            if ((uint64_t) st.st_size > max_rules_text)
                throw devicerules::parse_error("device rules file '" + path + "' is too large", 0, 0);

            // Read no more than the remaining budget, whatever the size claimed
            char buf[16384];
            ssize_t r;
            while ((r = read(fd, buf, sizeof(buf))) > 0) {
                charge(r);
                text.append(buf, r);
            }
            if (r < 0)
                throw devicerules::parse_error("can't read device rules file '" + path + "': " +
                        kis_strerror_r(errno), 0, 0);
        } catch (...) {
            close(fd);
            throw;
        }

        close(fd);

        device_rules::rules_chunk chunk;
        chunk.text = std::move(text);
        chunk.origin = path;
        chunk.line_base = 0;
        chunk.col_base = 0;
        chunk.only = devicerules::parse_source::block::any;

        // Every include is recorded, even one that reads nothing, so a replay lines up
        devicerules::parse_source src;
        src.origin = path;
        src.include = [this, &path, &chunk, depth](const std::string& inc, size_t line, size_t col) {
            chunk.includes.emplace_back();
            include(path, inc, depth, line, col, chunk.includes.back());
        };

        rs.parse(chunk.text, src);

        into.push_back(std::move(chunk));
    }

    void include(const std::string& from, const std::string& inc, int depth, size_t line, size_t col,
            std::vector<device_rules::rules_chunk>& into) {
        if (depth + 1 > max_include_depth)
            throw devicerules::parse_error("includes nest more than " + std::to_string(max_include_depth) +
                    " deep", line, col);

        auto target = Globalreg::globalreg->kismet_config->expand_log_path(inc);
        if (target.empty() || target[0] != '/') {
            auto slash = from.find_last_of('/');
            target = (slash == std::string::npos ? std::string{"."} : from.substr(0, slash)) + "/" + target;
        }

        if (!has_glob(target)) {
            if (access(target.c_str(), F_OK) != 0)
                throw devicerules::parse_error("can't find included file '" + target + "'", line, col);
            load_path(target, true, depth + 1, into);
            return;
        }

        glob_t g;
        memset(&g, 0, sizeof(g));
        int gr = glob(target.c_str(), GLOB_NOSORT, nullptr, &g);
        if (gr == GLOB_NOMATCH) {
            globfree(&g);
            return;
        }
        if (gr != 0) {
            globfree(&g);
            throw devicerules::parse_error("can't expand include '" + target + "'", line, col);
        }

        std::vector<std::string> names;
        for (size_t i = 0; i < g.gl_pathc; i++)
            names.emplace_back(g.gl_pathv[i]);
        globfree(&g);

        std::sort(names.begin(), names.end(),
                [](const std::string& a, const std::string& b) {
                    return natural_compare(a, b) < 0;
                });

        if (names.size() > max_dir_files)
            throw devicerules::parse_error("include '" + target + "' matches more than " +
                    std::to_string(max_dir_files) + " files", line, col);

        for (const auto& n : names) {
            struct stat st;
            if (stat(n.c_str(), &st) != 0 || !S_ISREG(st.st_mode))
                continue;
            load_path(n, true, depth + 1, into);
        }
    }
};

// Parse recorded chunks again, feeding each include what it read the first time
void replay_chunks(devicerules::ruleset& rs, const std::vector<device_rules::rules_chunk>& chunks) {
    for (const auto& c : chunks) {
        devicerules::parse_source src;
        src.origin = c.origin;
        src.line_base = c.line_base;
        src.col_base = c.col_base;
        src.only = c.only;

        size_t next = 0;
        if (c.only == devicerules::parse_source::block::any)
            src.include = [&rs, &c, &next](const std::string&, size_t line, size_t col) {
                if (next >= c.includes.size())
                    throw devicerules::parse_error("include out of step with the rules as read", line, col);
                replay_chunks(rs, c.includes[next++]);
            };

        rs.parse(c.text, src);
    }
}

// Read a whole regular file of at most max bytes; missing is set when it doesn't exist
bool read_small_file(const std::string& path, size_t max, std::string& out, std::string& err, bool& missing) {
    missing = false;

    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        missing = errno == ENOENT;
        err = kis_strerror_r(errno);
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        err = "not a regular file";
        return false;
    }

    char buf[16384];
    ssize_t r;
    out.clear();
    while ((r = read(fd, buf, sizeof(buf))) > 0) {
        if (out.size() + r > max) {
            close(fd);
            err = "larger than " + std::to_string(max) + " bytes";
            return false;
        }
        out.append(buf, r);
    }

    int read_errno = errno;
    close(fd);

    if (r < 0) {
        err = kis_strerror_r(read_errno);
        return false;
    }

    return true;
}

// Per-thread evaluation state for live rules
struct live_ctx {
    std::shared_ptr<device_rules::active_set> set;
    uint32_t gen = 0;
    devicerules::eval_ctx ctx;
    kismet_env env;
    std::vector<uint8_t> out, prev;
    std::vector<device_rules::pending_change> changes;
};

}

device_rules::device_rules() :
    lifetime_global(),
    deferred_startup(),
    next_gen{1},
    rule_state_id{-1},
    alert_ref{-1},
    timer_id{-1},
    pchain_id{-1},
    pass_count{0},
    last_pass{0},
    full_pending{true},
    stat_passes{0},
    stat_devices{0},
    stat_last_us{0},
    pass{std::make_unique<pass_state>()} {

    mutex.set_name("device_rules");
    alert_mutex.set_name("device_rules_alerts");
    view_apply_mutex.set_name("device_rules_view_apply");
    set_mutex.set_name("device_rules_set");

    devicetracker = Globalreg::fetch_mandatory_global_as<device_tracker>();
    entrytracker = Globalreg::fetch_mandatory_global_as<entry_tracker>();

    rule_state_id =
        entrytracker->register_field("kismet.device.base.rules",
                tracker_element_factory<device_rule_state>(),
                "device rule results");

    auto conf = Globalreg::globalreg->kismet_config;
    use_jit = conf->fetch_opt_bool("device_rules_jit", true);
    pass_interval = std::max(1U, conf->fetch_opt_uint("device_rules_interval", 1));
    full_interval = conf->fetch_opt_uint("device_rules_full_interval", 10);
    alert_backlog_max = conf->fetch_opt_uint("device_rules_alert_backlog", 64);
    api_save = conf->fetch_opt_bool("device_rules_api_save", false);
    api_file = conf->fetch_opt_path("device_rules_api_file", "%h/.kismet/kismet_device_rules_api.txt");

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/devices/rules/rules", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection>) {
                    return rules_endpoint();
                }));

    httpd->register_route("/devices/rules/check", {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    check_endpoint(con);
                }));

    httpd->register_route("/devices/rules/set", {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    set_endpoint(con);
                }));

    httpd->register_route("/devices/rules/test", {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    test_endpoint(con);
                }));
}

device_rules::~device_rules() {
    trigger_deferred_shutdown();
}

void device_rules::trigger_deferred_startup() {
    auto alertracker = Globalreg::fetch_mandatory_global_as<alert_tracker>();
    alert_ref =
        alertracker->activate_configured_alert("DEVICERULE", "SYSTEM", kis_alert_severity::info,
                "A device matched a device rule marked 'alert'.");

    auto packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();
    pack_comp_device = packetchain->register_packet_component("DEVICE");

    // Rules are compiled here so every phy and plugin field is registered
    {
        kis_lock_guard<kis_mutex> lk(set_mutex, "device_rules startup");

        try {
            load_configured();
            build_set("");
        } catch (const devicerules::parse_error& e) {
            _MSG_ERROR("Device rules from the config not loaded: {}", describe(e));
            config_chunks.clear();
        } catch (const std::exception& e) {
            _MSG_ERROR("Device rules from the config not loaded: {}", e.what());
            config_chunks.clear();
        }

        if (api_save) {
            std::string err;
            bool missing;
            if (!read_small_file(api_file, max_rules_text, api_text, err, missing)) {
                api_text.clear();
                if (!missing)
                    _MSG_ERROR("Could not read saved device rules from {}: {}", api_file, err);
            }
        }

        std::shared_ptr<active_set> as;

        if (!api_text.empty()) {
            try {
                as = build_set(api_text);
            } catch (const devicerules::parse_error& e) {
                _MSG_ERROR("Saved device rules in {} not loaded: {}", api_file, describe(e));
                api_text.clear();
            } catch (const std::exception& e) {
                _MSG_ERROR("Saved device rules in {} not loaded: {}", api_file, e.what());
                api_text.clear();
            }
        }

        try {
            if (as == nullptr)
                as = build_set("");

            for (const auto& r : as->rs->replaced)
                _MSG_INFO("Device rules: {}", r.text);

            install_set(as);
        } catch (const std::exception& e) {
            _MSG_ERROR("Device rules not loaded: {}", e.what());
        }
    }

    timer_id =
        Globalreg::fetch_mandatory_global_as<time_tracker>()->register_timer(
                SERVER_TIMESLICES_SEC * pass_interval, nullptr, 1, [this](int) -> int {
                    timer_pass();
                    return 1;
                });

    pchain_id =
        packetchain->register_handler([](void *auxdata, const std::shared_ptr<kis_packet>& in_pack) -> int {
                return static_cast<device_rules *>(auxdata)->packet_hook(in_pack);
            }, this, CHAINPOS_TRACKER, 0x7FFFFFFE);
}

void device_rules::trigger_deferred_shutdown() {
    if (timer_id >= 0) {
        auto timetracker = Globalreg::fetch_global_as<time_tracker>(time_tracker::global_name());
        if (timetracker != nullptr)
            timetracker->remove_timer(timer_id);
        timer_id = -1;
    }

    if (pchain_id >= 0) {
        auto packetchain = Globalreg::fetch_global_as<packet_chain>(packet_chain::global_name());
        if (packetchain != nullptr)
            packetchain->remove_handler(pchain_id, CHAINPOS_TRACKER);
        pchain_id = -1;
    }
}

std::shared_ptr<device_rules::active_set> device_rules::compile_set(const std::string& text) {
    if (text.size() > max_rules_text)
        throw devicerules::parse_error("rules are larger than " + std::to_string(max_rules_text) + " bytes", 0, 0);

    auto rs = std::make_unique<devicerules::ruleset>();
    rs->parse(text);

    return finish_set(std::move(rs), text);
}

std::shared_ptr<device_rules::active_set> device_rules::finish_set(std::unique_ptr<devicerules::ruleset> rs,
        const std::string& text) {
    auto as = std::make_shared<active_set>();
    as->rs = std::move(rs);
    as->text = text;
    as->jit = false;
    as->any_live = false;

    kismet_resolver r(entrytracker);
    as->rs->compile(r);

    if (use_jit) {
        as->jit = as->rs->jit(as->jit_error);
    } else {
        as->jit_error = "disabled by device_rules_jit";
    }

    size_t n = as->rs->size();
    as->live_want.assign(n, 0);
    as->views.assign(n, nullptr);

    for (size_t i = 0; i < n; i++) {
        const auto& rd = as->rs->rule(i);
        as->by_name[rd.name] = i;
        if (rd.live) {
            as->live_want[i] = 1;
            as->any_live = true;
        }
    }

    for (size_t i = 0; i < as->rs->sort_count(); i++)
        as->sorts_by_name[as->rs->sort(i).name] = i;

    return as;
}

bool device_rules::sort_devices(const std::string& sort, std::shared_ptr<tracker_element_vector>& devices,
        std::string& err) {
    auto as = get_current();

    if (as == nullptr) {
        err = "no device rules are loaded";
        return false;
    }

    auto si = as->sorts_by_name.find(sort);
    if (si == as->sorts_by_name.end()) {
        err = "no such sort";
        return false;
    }

    kismet_env env;
    devicerules::eval_ctx ctx;
    ctx.bind(as->rs.get(), &env);

    devicerules::sort_table table(*as->rs, si->second);
    table.reserve(devices->size());

    int64_t now = Globalreg::globalreg->last_tv_sec;

    for (const auto& d : *devices) {
        auto dev = std::static_pointer_cast<kis_tracked_device_base>(d);
        kis_device_lock dlk(dev, true);
        env.root = dev.get();
        ctx.next_device(now);
        table.add(ctx);
        env.reset();
        env.root = nullptr;
    }

    auto order = table.order();

    auto sorted = std::make_shared<tracker_element_vector>();
    sorted->reserve(order.size());
    for (auto r : order)
        sorted->push_back((*devices)[r]);
    devices = sorted;

    return true;
}

void device_rules::load_configured() {
    auto conf = Globalreg::globalreg->kismet_config;

    // Parsed here for the errors, with their files and lines; built later by build_set
    devicerules::ruleset rs;
    std::vector<rules_chunk> chunks;
    rules_loader loader(rs, chunks);

    // Files in config order, then directories, then rules written on config lines
    auto files = conf->fetch_opt_vec_sourced("device_rules_file");
    if (files.empty())
        loader.load_file(conf->expand_log_path("%E/kismet_device_rules.txt"), false);
    for (const auto& f : files)
        loader.load_file(conf->expand_log_path(f.value), true);

    for (const auto& d : conf->fetch_opt_vec_sourced("device_rules_dir"))
        loader.load_dir(conf->expand_log_path(d.value));

    for (const auto& v : conf->fetch_opt_vec_sourced("device_rule"))
        loader.load_line(v, devicerules::parse_source::block::rule);
    for (const auto& v : conf->fetch_opt_vec_sourced("device_sort"))
        loader.load_line(v, devicerules::parse_source::block::sort);

    rule_disables = conf->fetch_opt_vec("device_rule_disable");
    sort_disables = conf->fetch_opt_vec("device_sort_disable");

    for (const auto& n : rule_disables)
        if (!rs.remove_rule(n))
            _MSG_ERROR("device_rule_disable={} doesn't match any device rule", n);
    for (const auto& n : sort_disables)
        if (!rs.remove_sort(n))
            _MSG_ERROR("device_sort_disable={} doesn't match any device sort", n);

    config_chunks = std::move(chunks);
}

std::shared_ptr<device_rules::active_set> device_rules::build_set(const std::string& api) {
    if (api.size() > max_rules_text)
        throw devicerules::parse_error("rules are larger than " + std::to_string(max_rules_text) + " bytes", 0, 0);

    auto rs = std::make_unique<devicerules::ruleset>();

    replay_chunks(*rs, config_chunks);

    for (const auto& n : rule_disables)
        rs->remove_rule(n);
    for (const auto& n : sort_disables)
        rs->remove_sort(n);

    // Rules from the API never get to include files
    if (!api.empty()) {
        devicerules::parse_source src;
        src.origin = api_origin;
        rs->parse(api, src);
    }

    return finish_set(std::move(rs), api);
}

std::shared_ptr<device_rules::active_set> device_rules::set_api_rules(const std::string& text,
        bool& saved, std::string& save_err) {
    kis_lock_guard<kis_mutex> lk(set_mutex, "device_rules set_api_rules");

    auto as = build_set(text);
    install_set(as);
    api_text = text;

    saved = false;
    if (api_save) {
        saved = save_api(text, save_err);
        if (!saved)
            _MSG_ERROR("Could not save device rules to {}: {}", api_file, save_err);
    }

    return as;
}

bool device_rules::save_api(const std::string& text, std::string& err) {
    // Write beside the file and rename over it, so a crash never leaves half a file
    auto tmp = api_file + ".tmp";

    int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        err = kis_strerror_r(errno);
        return false;
    }

    auto fail = [&](int e) {
        err = kis_strerror_r(e);
        close(fd);
        unlink(tmp.c_str());
        return false;
    };

    if (fchmod(fd, 0600) != 0)
        return fail(errno);

    size_t off = 0;
    while (off < text.size()) {
        ssize_t w = write(fd, text.data() + off, text.size() - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return fail(errno);
        }
        off += w;
    }

    if (fsync(fd) != 0)
        return fail(errno);

    if (close(fd) != 0) {
        err = kis_strerror_r(errno);
        unlink(tmp.c_str());
        return false;
    }

    if (rename(tmp.c_str(), api_file.c_str()) != 0) {
        err = kis_strerror_r(errno);
        unlink(tmp.c_str());
        return false;
    }

    return true;
}

std::string device_rules::describe(const devicerules::parse_error& e) {
    if (e.line == 0)
        return e.what();
    if (e.origin.empty())
        return fmt::format("line {} column {}: {}", e.line, e.col, e.what());
    return fmt::format("{} line {} column {}: {}", e.origin, e.line, e.col, e.what());
}

void device_rules::install_set(std::shared_ptr<active_set> as) {
    kis_lock_guard<kis_mutex> lk(mutex, "device_rules install_set");

    size_t new_views = 0;
    for (size_t i = 0; i < as->rs->size(); i++)
        if (as->rs->rule(i).view && views.find(as->rs->rule(i).name) == views.end())
            new_views++;

    if (views.size() + new_views > max_views)
        throw devicerules::parse_error("rules would make more than " + std::to_string(max_views) +
                " views", 0, 0);

    for (size_t i = 0; i < as->rs->size(); i++) {
        const auto& rd = as->rs->rule(i);
        if (!rd.view)
            continue;

        auto vi = views.find(rd.name);
        if (vi == views.end()) {
            auto desc = rd.view_desc.empty() ? fmt::format("Devices matching rule {}", rd.name) : rd.view_desc;
            auto v = std::make_shared<device_tracker_view>(fmt::format("rule-{}", rd.name), desc,
                    nullptr, nullptr);
            devicetracker->add_view(v);
            vi = views.emplace(rd.name, v).first;
        }

        as->views[i] = vi->second;
    }

    for (const auto& v : views) {
        auto ri = as->by_name.find(v.first);
        if (ri == as->by_name.end() || as->views[ri->second] == nullptr)
            as->retired[v.first] = v.second;
    }

    as->gen = next_gen++;

    std::atomic_store(&current, as);
    full_pending = true;

    _MSG_INFO("Loaded {} device rule(s), evaluated by {}{}", as->rs->size(),
            as->jit ? "the JIT" : "the VM",
            as->jit ? "" : fmt::format(" ({})", as->jit_error));
}

void device_rules::eval_device(active_set& as, devicerules::eval_ctx& ctx,
        const std::shared_ptr<kis_tracked_device_base>& dev, const uint8_t *want,
        std::vector<uint8_t>& out, std::vector<uint8_t>& prev, std::vector<pending_change>& changes) {

    if (dev->get_removed())
        return;

    const size_t n = as.rs->size();
    out.resize(n);
    prev.assign(n, 0);

    auto env = static_cast<kismet_env *>(ctx.e);
    env->root = dev.get();
    ctx.next_device(Globalreg::globalreg->last_tv_sec);
    as.rs->eval_all(ctx, want, out.data());
    env->reset();
    env->root = nullptr;

    auto state = dev->get_sub_as<device_rule_state>(rule_state_id);

    if (state != nullptr) {
        if (state->gen == as.gen && state->hits.size() == n) {
            prev = state->hits;
        } else {
            // Rules carry over a reload by name
            for (const auto& m : *state->get_matched()) {
                auto ri = as.by_name.find(m);
                if (ri != as.by_name.end())
                    prev[ri->second] = 1;
            }
        }
    }

    if (want != nullptr)
        for (size_t r = 0; r < n; r++)
            if (!want[r])
                out[r] = prev[r];

    bool any = false;
    for (size_t r = 0; r < n; r++)
        any |= out[r] != 0;

    if (state == nullptr && !any)
        return;

    if (state != nullptr && state->gen == as.gen && out == prev)
        return;

    // After a reload a matching device joins its rule's view even when the rule
    // matched before, since the rule may only now have a view
    const bool reloaded = state == nullptr || state->gen != as.gen;

    for (size_t r = 0; r < n; r++) {
        const auto& rd = as.rs->rule(r);

        if (out[r] == prev[r]) {
            if (reloaded && out[r] && as.views[r] != nullptr)
                changes.push_back(pending_change{dev, as.views[r], rd.name, "", mac_addr{}});
            continue;
        }

        if (as.views[r] != nullptr)
            changes.push_back(pending_change{dev, as.views[r], rd.name, "", mac_addr{}});

        if (out[r] && rd.alert)
            changes.push_back(pending_change{dev, nullptr, "",
                    fmt::format("Device {} ({}) matched device rule '{}'", dev->get_macaddr(),
                            dev->get_commonname(), rd.name),
                    dev->get_macaddr()});
    }

    // Leave the views of rules that went away
    if (state != nullptr && state->gen != as.gen) {
        for (const auto& m : *state->get_matched()) {
            auto vi = as.retired.find(m);
            if (vi != as.retired.end())
                changes.push_back(pending_change{dev, vi->second, m, "", mac_addr{}});
        }
    }

    if (!any) {
        dev->erase(state);
        return;
    }

    if (state == nullptr) {
        state = entrytracker->get_shared_instance_as<device_rule_state>(rule_state_id);
        dev->insert(state);
    }

    state->gen = as.gen;
    state->hits = out;

    auto matched = state->get_matched();
    auto tags = state->get_tags();
    matched->clear();
    tags->clear();
    state->set_color("");

    bool have_color = false;

    for (size_t r = 0; r < n; r++) {
        if (!out[r])
            continue;

        const auto& rd = as.rs->rule(r);
        matched->push_back(rd.name);

        for (const auto& t : rd.tags)
            if (std::find(tags->begin(), tags->end(), t) == tags->end())
                tags->push_back(t);

        if (!have_color && !rd.color.empty()) {
            state->set_color(rd.color);
            have_color = true;
        }
    }
}

void device_rules::apply_changes(std::vector<pending_change>& changes) {
    if (changes.empty())
        return;

    for (auto& c : changes) {
        if (c.view != nullptr) {
            // The latest change for a device reads the newest state, whatever order
            // the threads queued them in
            kis_lock_guard<kis_mutex> lk(view_apply_mutex, "device_rules apply_changes");

            if (wants_view(c.device, c.view, c.rule))
                c.view->add_device_direct(c.device);
            else
                c.view->remove_device_direct(c.device);
        }

        if (!c.alert.empty() && alert_ref >= 0)
            raise_or_hold(c.mac, c.alert);
    }

    changes.clear();
}

bool device_rules::wants_view(const std::shared_ptr<kis_tracked_device_base>& dev,
        const std::shared_ptr<device_tracker_view>& view, const std::string& rule) {
    auto as = get_current();
    if (as == nullptr)
        return false;

    auto ri = as->by_name.find(rule);
    if (ri == as->by_name.end() || as->views[ri->second] != view)
        return false;

    kis_device_lock dlk(dev, true);

    auto state = dev->get_sub_as<device_rule_state>(rule_state_id);
    if (state == nullptr)
        return false;

    const auto matched = state->get_matched();
    return std::find(matched->begin(), matched->end(), rule) != matched->end();
}

void device_rules::raise_or_hold(const mac_addr& mac, const std::string& text) {
    auto alertracker = Globalreg::fetch_mandatory_global_as<alert_tracker>();

    kis_lock_guard<kis_mutex> lk(alert_mutex, "device_rules raise_or_hold");

    // Keep order behind anything already held back
    if (alert_backlog.empty()) {
        auto r = alertracker->raise_alert(alert_ref, nullptr, mac_addr{}, mac, mac_addr{}, mac_addr{}, "", text);
        if (r != 0)
            return;
    }

    if (alert_backlog_max == 0)
        return;

    if (alert_backlog.size() >= alert_backlog_max)
        alert_backlog.pop_front();
    alert_backlog.emplace_back(mac, text);
}

void device_rules::drain_alerts() {
    if (alert_ref < 0)
        return;

    auto alertracker = Globalreg::fetch_mandatory_global_as<alert_tracker>();

    kis_lock_guard<kis_mutex> lk(alert_mutex, "device_rules drain_alerts");

    while (!alert_backlog.empty()) {
        const auto& a = alert_backlog.front();
        auto r = alertracker->raise_alert(alert_ref, nullptr, mac_addr{}, a.first, mac_addr{}, mac_addr{}, "", a.second);
        if (r == 0)
            break;
        alert_backlog.pop_front();
    }
}

void device_rules::timer_pass() {
    drain_alerts();

    auto as = get_current();
    if (as == nullptr || as->rs->size() == 0)
        return;

    bool full;
    time_t since;

    {
        kis_lock_guard<kis_mutex> lk(mutex, "device_rules timer_pass");

        pass_count++;
        full = full_pending ||
            (as->rs->uses_now() && full_interval > 0 && pass_count % full_interval == 0);
        full_pending = false;
        since = last_pass;
        last_pass = Globalreg::globalreg->last_tv_sec;
    }

    // Timers don't overlap, so the pass state is only used here
    if (pass->gen != as->gen) {
        pass->ctx.bind(as->rs.get(), &pass->env);
        pass->gen = as->gen;
    }

    auto start = std::chrono::steady_clock::now();
    uint64_t evaluated = 0;
    std::vector<pending_change> changes;

    // Live rules are evaluated on packets; a reload evaluates everything once
    const uint8_t *want = nullptr;

    device_tracker_view_function_worker worker(
            [&](std::shared_ptr<kis_tracked_device_base> dev) -> bool {
                if (!full && (time_t) dev->get_mod_time() < since)
                    return false;
                eval_device(*as, pass->ctx, dev, want, pass->out, pass->prev, changes);
                evaluated++;
                return false;
            });

    devicetracker->do_device_work(worker);

    apply_changes(changes);

    stat_passes++;
    stat_devices += evaluated;
    stat_last_us = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start).count();
}

int device_rules::packet_hook(const std::shared_ptr<kis_packet>& in_pack) {
    auto as = get_current();
    if (as == nullptr || !as->any_live)
        return 1;

    auto devinfo = in_pack->fetch<kis_tracked_device_info>(pack_comp_device);
    if (devinfo == nullptr)
        return 1;

    thread_local live_ctx lc;

    if (lc.gen != as->gen) {
        lc.set = as;
        lc.ctx.bind(as->rs.get(), &lc.env);
        lc.gen = as->gen;
    }

    for (const auto& d : devinfo->devrefs) {
        if (d.second == nullptr)
            continue;
        kis_device_lock dlk(d.second, false);
        eval_device(*as, lc.ctx, d.second, as->live_want.data(), lc.out, lc.prev, lc.changes);
    }

    apply_changes(lc.changes);

    return 1;
}

std::shared_ptr<tracker_element> device_rules::rules_endpoint() {
    auto ret = std::make_shared<tracker_element_map>();

    auto f_backend = entrytracker->register_and_get_field_as<tracker_element_string>("kismet.devicerules.backend",
            tracker_element_factory<tracker_element_string>(), "how device rules are evaluated (jit or vm)");
    auto f_jiterr = entrytracker->register_and_get_field_as<tracker_element_string>("kismet.devicerules.jit_error",
            tracker_element_factory<tracker_element_string>(), "why device rules aren't using the jit");
    auto f_passes = entrytracker->register_and_get_field_as<tracker_element_uint64>("kismet.devicerules.passes",
            tracker_element_factory<tracker_element_uint64>(), "device rule passes run");
    auto f_devices = entrytracker->register_and_get_field_as<tracker_element_uint64>("kismet.devicerules.evaluated",
            tracker_element_factory<tracker_element_uint64>(), "devices evaluated by device rule passes");
    auto f_last = entrytracker->register_and_get_field_as<tracker_element_uint64>("kismet.devicerules.last_pass_us",
            tracker_element_factory<tracker_element_uint64>(), "duration of the last device rule pass, in microseconds");
    auto f_rules = entrytracker->register_and_get_field_as<tracker_element_vector>("kismet.devicerules.rules",
            tracker_element_factory<tracker_element_vector>(), "device rules");
    auto f_sorts = entrytracker->register_and_get_field_as<tracker_element_vector>("kismet.devicerules.sorts",
            tracker_element_factory<tracker_element_vector>(), "device sorts, for the rule_sort option of device views");
    auto f_api = entrytracker->register_and_get_field_as<tracker_element_string>("kismet.devicerules.api_rules",
            tracker_element_factory<tracker_element_string>(), "rules set with set.cmd, applied after the configured rules");
    auto f_api_save = entrytracker->register_and_get_field_as<tracker_element_uint8>("kismet.devicerules.api_save",
            tracker_element_factory<tracker_element_uint8>(), "rules set with set.cmd are saved and loaded at startup");

    ret->insert(f_backend);
    ret->insert(f_jiterr);
    ret->insert(f_passes);
    ret->insert(f_devices);
    ret->insert(f_last);
    ret->insert(f_rules);
    ret->insert(f_sorts);
    ret->insert(f_api);
    ret->insert(f_api_save);

    {
        kis_lock_guard<kis_mutex> lk(set_mutex, "device_rules rules_endpoint");
        f_api->set(api_text);
    }
    f_api_save->set(api_save);

    f_passes->set(stat_passes.load());
    f_devices->set(stat_devices.load());
    f_last->set(stat_last_us.load());

    auto as = get_current();
    if (as == nullptr) {
        f_backend->set("none");
        return ret;
    }

    f_backend->set(as->jit ? "jit" : "vm");
    f_jiterr->set(as->jit_error);

    for (size_t i = 0; i < as->rs->size(); i++) {
        const auto& rd = as->rs->rule(i);

        auto r = std::make_shared<tracker_element_map>();

        auto name = entrytracker->register_and_get_field_as<tracker_element_string>("kismet.devicerules.rule.name",
                tracker_element_factory<tracker_element_string>(), "rule name");
        auto source = entrytracker->register_and_get_field_as<tracker_element_string>("kismet.devicerules.rule.source",
                tracker_element_factory<tracker_element_string>(), "rule text");
        auto tags = entrytracker->register_and_get_field_as<tracker_element_vector_string>("kismet.devicerules.rule.tags",
                tracker_element_factory<tracker_element_vector_string>(), "tags set by the rule");
        auto color = entrytracker->register_and_get_field_as<tracker_element_string>("kismet.devicerules.rule.color",
                tracker_element_factory<tracker_element_string>(), "highlight color set by the rule");
        auto view = entrytracker->register_and_get_field_as<tracker_element_string>("kismet.devicerules.rule.view",
                tracker_element_factory<tracker_element_string>(), "view of devices matching the rule");
        auto alert = entrytracker->register_and_get_field_as<tracker_element_uint8>("kismet.devicerules.rule.alert",
                tracker_element_factory<tracker_element_uint8>(), "rule raises an alert");
        auto live = entrytracker->register_and_get_field_as<tracker_element_uint8>("kismet.devicerules.rule.live",
                tracker_element_factory<tracker_element_uint8>(), "rule is checked on every packet");
        auto origin = entrytracker->register_and_get_field_as<tracker_element_string>("kismet.devicerules.rule.origin",
                tracker_element_factory<tracker_element_string>(), "file and line the rule came from");

        name->set(rd.name);
        source->set(rd.source);
        for (const auto& t : rd.tags)
            tags->push_back(t);
        color->set(rd.color);
        if (rd.view)
            view->set(fmt::format("rule-{}", rd.name));
        alert->set(rd.alert);
        live->set(rd.live);
        if (!rd.origin.empty())
            origin->set(fmt::format("{}:{}", rd.origin, rd.line));

        r->insert(name);
        r->insert(source);
        r->insert(tags);
        r->insert(color);
        r->insert(view);
        r->insert(alert);
        r->insert(live);
        r->insert(origin);

        f_rules->push_back(r);
    }

    for (size_t i = 0; i < as->rs->sort_count(); i++) {
        const auto& sd = as->rs->sort(i);

        auto r = std::make_shared<tracker_element_map>();

        auto name = entrytracker->register_and_get_field_as<tracker_element_string>("kismet.devicerules.sort.name",
                tracker_element_factory<tracker_element_string>(), "sort name");
        auto source = entrytracker->register_and_get_field_as<tracker_element_string>("kismet.devicerules.sort.source",
                tracker_element_factory<tracker_element_string>(), "sort text");
        auto origin = entrytracker->register_and_get_field_as<tracker_element_string>("kismet.devicerules.sort.origin",
                tracker_element_factory<tracker_element_string>(), "file and line the sort came from");

        name->set(sd.name);
        source->set(sd.source);
        if (!sd.origin.empty())
            origin->set(fmt::format("{}:{}", sd.origin, sd.line));

        r->insert(name);
        r->insert(source);
        r->insert(origin);

        f_sorts->push_back(r);
    }

    return ret;
}

namespace {
    // Only what the API text replaced; the configured rules' own replacements are logged at startup
    std::vector<std::string> api_replaced(const devicerules::ruleset& rs) {
        std::vector<std::string> r;
        for (const auto& x : rs.replaced)
            if (x.by == api_origin)
                r.push_back(x.text);
        return r;
    }

    void json_error(std::ostream& stream, const devicerules::parse_error& e) {
        nlohmann::json j;
        j["ok"] = false;
        j["error"] = e.what();
        j["line"] = e.line;
        j["col"] = e.col;
        stream << j.dump();
    }

    std::string rules_param(std::shared_ptr<kis_net_beast_httpd_connection> con) {
        auto& j = con->json();
        if (!j.contains("rules") || !j["rules"].is_string())
            throw std::runtime_error("expected 'rules'");
        auto s = j["rules"].get<std::string>();
        if (s.size() > max_rules_text)
            throw std::runtime_error("rules are too large");
        return s;
    }
}

void device_rules::check_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream stream(&con->response_stream());
    con->set_mime_type("application/json");

    try {
        auto text = rules_param(con);

        // Checked as the API rules, after the configured rules, as set.cmd would load them
        std::shared_ptr<active_set> as;
        {
            kis_lock_guard<kis_mutex> lk(set_mutex, "device_rules check");
            as = build_set(text);
        }

        nlohmann::json j;
        j["ok"] = true;
        j["backend"] = as->jit ? "jit" : "vm";
        j["replaced"] = api_replaced(*as->rs);
        auto names = nlohmann::json::array();
        for (size_t i = 0; i < as->rs->size(); i++)
            names.push_back(as->rs->rule(i).name);
        j["rules"] = names;
        auto snames = nlohmann::json::array();
        for (size_t i = 0; i < as->rs->sort_count(); i++)
            snames.push_back(as->rs->sort(i).name);
        j["sorts"] = snames;
        stream << j.dump();
    } catch (const devicerules::parse_error& e) {
        json_error(stream, e);
    } catch (const std::exception& e) {
        con->set_status(400);
        stream << nlohmann::json{{"ok", false}, {"error", e.what()}}.dump();
    }
}

void device_rules::set_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream stream(&con->response_stream());
    con->set_mime_type("application/json");

    try {
        bool saved;
        std::string save_err;
        auto as = set_api_rules(rules_param(con), saved, save_err);

        nlohmann::json j{{"ok", true}, {"rules", as->rs->size()}, {"sorts", as->rs->sort_count()},
            {"backend", as->jit ? "jit" : "vm"}, {"replaced", api_replaced(*as->rs)}, {"saved", saved}};
        if (!save_err.empty())
            j["save_error"] = save_err;
        stream << j.dump();
    } catch (const devicerules::parse_error& e) {
        json_error(stream, e);
    } catch (const std::exception& e) {
        con->set_status(400);
        stream << nlohmann::json{{"ok", false}, {"error", e.what()}}.dump();
    }
}

void device_rules::test_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    std::ostream stream(&con->response_stream());
    con->set_mime_type("application/json");

    try {
        auto text = rules_param(con);
        auto& j = con->json();

        if (!j.contains("device") || !j["device"].is_string())
            throw std::runtime_error("expected 'device', a device key");

        auto key = device_key(j["device"].get<std::string>());
        if (key.get_error())
            throw std::runtime_error("invalid device key");

        auto dev = devicetracker->fetch_device(key);
        if (dev == nullptr) {
            con->set_status(404);
            stream << nlohmann::json{{"ok", false}, {"error", "no such device"}}.dump();
            return;
        }

        auto as = compile_set(text);

        kismet_env env;
        devicerules::eval_ctx ctx;
        ctx.bind(as->rs.get(), &env);
        std::vector<uint8_t> out(as->rs->size());

        {
            kis_device_lock dlk(dev, true);
            env.root = dev.get();
            ctx.next_device(Globalreg::globalreg->last_tv_sec);
            as->rs->eval_all(ctx, nullptr, out.data());
            env.reset();
        }

        nlohmann::json res;
        res["ok"] = true;
        auto m = nlohmann::json::object();
        for (size_t i = 0; i < as->rs->size(); i++)
            m[as->rs->rule(i).name] = out[i] != 0;
        res["matches"] = m;
        stream << res.dump();
    } catch (const devicerules::parse_error& e) {
        json_error(stream, e);
    } catch (const std::exception& e) {
        con->set_status(400);
        stream << nlohmann::json{{"ok", false}, {"error", e.what()}}.dump();
    }
}
