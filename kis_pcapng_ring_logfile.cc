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

#include <algorithm>
#include <chrono>
#include <future>
#include <memory>
#include <set>
#include <vector>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#include "fmt.h"

#include "configfile.h"
#include "kis_net_beast_httpd.h"
#include "kis_pcapng_ring_logfile.h"
#include "messagebus.h"
#include "nlohmann/json.hpp"

namespace {

// Buffer size used when concatenating ring slots into a snapshot file. 64 KiB
// balances syscall overhead against memory pressure on small/embedded targets.
constexpr size_t SNAPSHOT_COPY_BUFFER_BYTES = 64 * 1024;

// Maximum label length accepted by /snapshot. Long enough for a UUID + a
// short prefix; short enough to keep filesystem paths sane.
constexpr size_t SNAPSHOT_LABEL_MAX_LEN = 64;

// True if `c` is allowed in a snapshot label (alnum, dash, underscore, dot).
// Dot is allowed for caller-supplied extensions but never at position 0 (no
// hidden directories) and never as ".." (no traversal); that's enforced in
// validate_snapshot_label.
bool is_label_char(char c) {
    return (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') ||
           c == '-' || c == '_' || c == '.';
}

bool validate_snapshot_label(const std::string& label) {
    if (label.empty() || label.size() > SNAPSHOT_LABEL_MAX_LEN)
        return false;
    // Reject leading/trailing dots — leading would create a hidden directory
    // and trailing dots get silently stripped by Windows/SMB reshares, which
    // would collapse `foo` and `foo.` into the same snapshot dir.
    if (label.front() == '.' || label.back() == '.')
        return false;
    if (label.find("..") != std::string::npos)
        return false;
    for (char c : label) {
        if (!is_label_char(c))
            return false;
    }
    return true;
}

// mkdir -p equivalent. Returns 0 on success, -1 on error (errno preserved).
int mkdir_p(const std::string& path, mode_t mode) {
    if (path.empty())
        return 0;

    std::string cur;
    for (size_t i = 0; i <= path.size(); i++) {
        if (i == path.size() || path[i] == '/') {
            if (!cur.empty() && cur != "/") {
                if (mkdir(cur.c_str(), mode) != 0 && errno != EEXIST)
                    return -1;
            }
        }
        if (i < path.size())
            cur.push_back(path[i]);
    }
    return 0;
}

// Recursive rm -rf for a snapshot directory. POSIX-only, used by the prune
// thread. Errors are logged but do not abort the prune cycle.
void remove_dir_recursive(const std::string& path) {
    DIR *d = opendir(path.c_str());
    if (d == nullptr) {
        // ENOENT is not an error in this context — caller may race with prune.
        if (errno != ENOENT) {
            _MSG_ERROR("pcapng_ring: failed to open '{}' for removal - {}",
                    path, kis_strerror_r(errno));
        }
        return;
    }

    struct dirent *de;
    while ((de = readdir(d)) != nullptr) {
        std::string name(de->d_name);
        if (name == "." || name == "..")
            continue;

        std::string child = path + "/" + name;
        struct stat st;
        if (lstat(child.c_str(), &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            remove_dir_recursive(child);
        } else {
            if (unlink(child.c_str()) != 0 && errno != ENOENT) {
                _MSG_ERROR("pcapng_ring: failed to unlink '{}' - {}",
                        child, kis_strerror_r(errno));
            }
        }
    }
    closedir(d);

    if (rmdir(path.c_str()) != 0 && errno != ENOENT) {
        _MSG_ERROR("pcapng_ring: failed to rmdir '{}' - {}",
                path, kis_strerror_r(errno));
    }
}

// Recursive size in bytes (regular files only).
uint64_t dir_size_bytes(const std::string& path) {
    DIR *d = opendir(path.c_str());
    if (d == nullptr)
        return 0;

    uint64_t total = 0;
    struct dirent *de;
    while ((de = readdir(d)) != nullptr) {
        std::string name(de->d_name);
        if (name == "." || name == "..")
            continue;

        std::string child = path + "/" + name;
        struct stat st;
        if (lstat(child.c_str(), &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            total += dir_size_bytes(child);
        } else if (S_ISREG(st.st_mode)) {
            total += static_cast<uint64_t>(st.st_size);
        }
    }
    closedir(d);
    return total;
}

} // anonymous namespace

kis_pcapng_ring_logfile::kis_pcapng_ring_logfile(shared_log_builder in_builder) :
    kis_logfile(in_builder),
    pcapng{nullptr},
    ring_file{nullptr},
    shutting_down{false},
    active_slot{0},
    active_slot_bytes{0},
    force_rotate_pending{false},
    rotation_count{0} {

    auto cfg = Globalreg::globalreg->kismet_config;

    ring_dir = cfg->fetch_opt_dfl("pcapng_ring_dir", "/run/kismet/ring");
    persist_dir = cfg->fetch_opt_dfl("pcapng_ring_persist_dir",
            "/var/lib/kismet/captures");

    // 64 MB total (8 files * 8 MB) by default — chosen conservatively so
    // the ring fits comfortably on small/embedded targets. Bump on larger
    // sensors via the pcapng_ring_file_size_mb / _file_count config keys.
    auto file_size_mb = cfg->fetch_opt_ulong("pcapng_ring_file_size_mb", 8L);
    ring_file_size_bytes = static_cast<uint64_t>(file_size_mb) * 1024UL * 1024UL;

    ring_file_count = static_cast<unsigned int>(
            cfg->fetch_opt_ulong("pcapng_ring_file_count", 8L));
    if (ring_file_count < 2)
        ring_file_count = 2; // a one-file "ring" is just rotation; need >=2

    default_post_seconds = static_cast<unsigned int>(
            cfg->fetch_opt_ulong("pcapng_ring_default_post_seconds", 30L));

    auto persist_max_mb = cfg->fetch_opt_ulong("pcapng_ring_persist_max_total_mb",
            2048L);
    persist_max_total_bytes =
        static_cast<uint64_t>(persist_max_mb) * 1024UL * 1024UL;

    persist_max_age_days = static_cast<unsigned int>(
            cfg->fetch_opt_ulong("pcapng_ring_persist_max_age_days", 14L));

    auto persist_min_free_mb = cfg->fetch_opt_ulong(
            "pcapng_ring_persist_min_free_mb", 256L);
    persist_min_free_bytes =
        static_cast<uint64_t>(persist_min_free_mb) * 1024UL * 1024UL;

    persist_prune_interval = static_cast<unsigned int>(
            cfg->fetch_opt_ulong("pcapng_ring_persist_prune_interval", 60L));
    if (persist_prune_interval < 5)
        persist_prune_interval = 5;

    log_duplicate_packets = cfg->fetch_opt_bool(
            "pcapng_ring_log_duplicate_packets",
            cfg->fetch_opt_bool("pcapng_log_duplicate_packets", true));
    truncate_duplicate_packets = cfg->fetch_opt_bool(
            "pcapng_ring_truncate_duplicate_packets",
            cfg->fetch_opt_bool("pcapng_truncate_duplicate_packets", false));
    log_data_packets = cfg->fetch_opt_bool(
            "pcapng_ring_log_data_packets",
            cfg->fetch_opt_bool("pcapng_log_data_packets", true));

    auto packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>("PACKETCHAIN");
    pack_comp_l1data = packetchain->register_packet_component("L1RAW");
    pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");

    // Register the snapshot HTTP route here (logfile ctor), mirroring the
    // pattern used by kis_databaselogfile / wiglecsv. `this` capture is safe
    // because pcapng_ring_logfile_builder declares this log as a singleton —
    // exactly one instance lives for the duration of the Kismet process.
    // Kismet's beast HTTPD requires every route to have a `.<ext>` suffix
    // even when the extensions list is empty — the route-match regex always
    // appends \.([A-Za-z0-9]+). Declaring `cmd` here keeps the URL contract
    // explicit and matches the pattern used by every other POST command
    // endpoint in Kismet (see kis_databaselogfile.cc).
    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();
    httpd->register_route("/logging/pcapng_ring/snapshot/:label",
            {"POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    std::ostream ostream(&con->response_stream());

                    auto label = con->uri_params()[":label"];

                    // post_seconds may come in the JSON body; treat 0 or
                    // missing as "use the configured default".
                    unsigned int post_seconds = 0;
                    if (!con->json().is_null() &&
                            con->json().contains("post_seconds") &&
                            con->json()["post_seconds"].is_number_unsigned()) {
                        post_seconds =
                            con->json()["post_seconds"].get<unsigned int>();
                    }

                    try {
                        auto pre_path = snapshot(label, post_seconds);
                        // pre.pcapng / post.pcapng share the same directory,
                        // so derive post path by string substitution rather
                        // than recomputing.
                        auto post_path = pre_path;
                        auto slash = post_path.find_last_of('/');
                        if (slash != std::string::npos)
                            post_path = post_path.substr(0, slash + 1) + "post.pcapng";
                        nlohmann::json out;
                        out["label"] = label;
                        out["pre_path"] = pre_path;
                        out["post_path"] = post_path;
                        ostream << out.dump();
                    } catch (const std::runtime_error& e) {
                        std::string what(e.what());
                        // Storage-pressure errors deserve a distinct status;
                        // everything else is a bad request from the caller.
                        if (what.find("insufficient free space") != std::string::npos) {
                            con->set_status(507);
                        } else {
                            con->set_status(400);
                        }
                        nlohmann::json out;
                        out["error"] = what;
                        ostream << out.dump();
                    }
                }));
}

kis_pcapng_ring_logfile::~kis_pcapng_ring_logfile() {
    close_log();
    // `buffer` is a shared_ptr — refcount drops when this object is
    // destroyed; the buffer object itself is freed when the last
    // outstanding shared_ptr (e.g. one captured by an in-flight
    // force_rotate_now()) goes out of scope.
}

std::string kis_pcapng_ring_logfile::ring_slot_path(unsigned int idx) const {
    return fmt::format("{}/ring-{:04d}.pcapng", ring_dir, idx);
}

bool kis_pcapng_ring_logfile::open_log(const std::string& /*in_template*/,
        const std::string& /*in_path*/) {
    kis_lock_guard<kis_mutex> lk(log_mutex, "pcapng_ring open_log");

    // The ring directory MUST exist and be writable. Kismet (per docs) does
    // not create log directories implicitly — operators are expected to
    // provision /run/kismet/ring (tmpfs) at boot via systemd-tmpfiles or
    // equivalent. Same convention as log_prefix.
    if (mkdir_p(ring_dir, 0700) != 0) {
        _MSG_ERROR("pcapng_ring: failed to create ring directory '{}' - {}",
                ring_dir, kis_strerror_r(errno));
        return false;
    }

    // Truncate any pre-existing ring slots so an old run's leftovers don't
    // get mistaken for current data. Cheap because they're on tmpfs.
    for (unsigned int i = 0; i < ring_file_count; i++) {
        unlink(ring_slot_path(i).c_str());
    }

    active_slot = 0;
    active_slot_bytes = 0;

    auto first_path = ring_slot_path(active_slot);
    set_int_log_path(first_path);
    set_int_log_template("");

    ring_file = fopen(first_path.c_str(), "w");
    if (ring_file == nullptr) {
        _MSG_ERROR("pcapng_ring: failed to open ring slot '{}' - {}",
                first_path, kis_strerror_r(errno));
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(buffer_mutex);
        buffer = std::make_shared<future_chainbuf>(4096, 1024);
    }
    // pcapng_stream_packetchain stores a raw pointer to the buffer but does
    // not own it (no delete in its dtor — only `chainbuf->cancel()`). Our
    // shared_ptr keeps the buffer alive across the whole logfile lifetime.
    pcapng = new pcapng_stream_packetchain<pcapng_logfile_accept_ftor,
                                           pcapng_logfile_select_ftor>(
            buffer.get(),
            pcapng_logfile_accept_ftor(log_duplicate_packets, log_data_packets),
            pcapng_logfile_select_ftor(truncate_duplicate_packets),
            static_cast<size_t>(16384));

    _MSG_INFO("Opened pcapng_ring on '{}' ({} slots * {} MB = {} MB total)",
            ring_dir, ring_file_count, ring_file_size_bytes / (1024 * 1024),
            (ring_file_size_bytes * ring_file_count) / (1024 * 1024));

    set_int_log_open(true);

    auto thread_p = std::promise<void>();
    auto thread_f = thread_p.get_future();

    stream_t = std::thread([this, thread_p = std::move(thread_p)]() mutable {
        thread_p.set_value();

        // Capture buffer under buffer_mutex each iteration. The shared_ptr
        // local keeps it alive across the body even if rotate_ring (also
        // on this thread) swaps the member out from under us.
        while (true) {
            std::shared_ptr<future_chainbuf> buf;
            {
                std::lock_guard<std::mutex> lk(buffer_mutex);
                buf = buffer;
            }
            if (ring_file == nullptr || !buf ||
                    (!buf->running() && buf->size() == 0)) {
                return;
            }

            buf->wait();

            char *data;
            auto sz = buf->get(&data);

            if (sz > 0) {
                if (fwrite(data, sz, 1, ring_file) != 1) {
                    int e = errno;
                    bool ferr = ferror(ring_file);
                    _MSG_ERROR("pcapng_ring: error writing to ring slot '{}' - {}",
                            ring_slot_path(active_slot),
                            ferr ? kis_strerror_r(e) : "short write");
                    // Don't call close_log() from inside the writer thread —
                    // it joins this thread (UB / abort). Flag shutdown and
                    // exit the loop; the destructor or log_tracker will run
                    // close_log() from a safe thread.
                    shutting_down = true;
                    rotation_cv.notify_all();
                    return;
                }
            }

            buf->consume(sz);
            active_slot_bytes += sz;

            bool force = force_rotate_pending.exchange(false);
            bool natural = active_slot_bytes >= ring_file_size_bytes;

            if (force || natural) {
                rotate_ring();
                // Signal any snapshot thread blocked in force_rotate_now()
                // that a rotation completed. We count both forced and
                // natural rotations — a natural one in the middle of a
                // snapshot wait is just as good for freezing the boundary.
                {
                    std::lock_guard<std::mutex> lk(rotation_mutex);
                    rotation_count++;
                }
                rotation_cv.notify_all();
            }
        }
    });

    thread_f.wait();
    pcapng->start_stream();

    // Best-effort: ensure persist_dir exists so the first snapshot doesn't
    // fail just because nobody mkdir'd it. Failure here is logged but does
    // not abort logging — operators may correct it before the first alert.
    if (mkdir_p(persist_dir, 0700) != 0) {
        _MSG_ERROR("pcapng_ring: persist_dir '{}' is unusable, snapshots "
                "will fail until corrected - {}",
                persist_dir, kis_strerror_r(errno));
    }

    prune_t = std::thread([this]() { prune_loop(); });

    return true;
}

void kis_pcapng_ring_logfile::rotate_ring() {
    // Called from inside the writer thread, so the writer can't be touching
    // the old slot file while we're mid-rotate. Snapshot thread reads
    // `buffer` member via buffer_mutex; we hold buffer_mutex briefly during
    // the swap so a concurrent force_rotate_now() captures a coherent
    // shared_ptr value.

    if (shutting_down)
        return;

    std::shared_ptr<future_chainbuf> old_buffer;
    {
        std::lock_guard<std::mutex> lk(buffer_mutex);
        old_buffer = buffer;
    }

    auto old_file = ring_file;
    auto old_path = ring_slot_path(active_slot);

    // Swap to a new buffer; the new SHB lands in the new buffer immediately
    // so the next slot file starts with a valid pcapng section header. The
    // raw pointer goes to pcapng (which does not own it); our shared_ptr
    // member keeps it alive.
    auto new_buffer = std::make_shared<future_chainbuf>(4096, 1024);
    pcapng->restart_stream(new_buffer.get());
    {
        std::lock_guard<std::mutex> lk(buffer_mutex);
        buffer = new_buffer;
    }

    active_slot = (active_slot + 1) % ring_file_count;
    active_slot_bytes = 0;

    auto new_path = ring_slot_path(active_slot);
    set_int_log_path(new_path);

    // Truncate the slot we're about to overwrite. On a fresh start this is
    // a no-op; once the ring has cycled it discards the oldest data.
    FILE *new_file = fopen(new_path.c_str(), "w");
    if (new_file == nullptr) {
        _MSG_ERROR("pcapng_ring: failed to open next ring slot '{}' - {}; "
                "stopping ring", new_path, kis_strerror_r(errno));
        if (old_file != nullptr)
            fclose(old_file);
        // Flag shutdown; the writer loop's next iteration sees ring_file
        // is still the old (now closed) handle but will also see
        // shutting_down and return. We don't call close_log() here —
        // that would join this very thread (UB).
        ring_file = nullptr;
        shutting_down = true;
        rotation_cv.notify_all();
        return;
    }
    ring_file = new_file;

    // Drain the tail of the old buffer (anything still in flight before the
    // restart_stream swap) into the closing slot. pcapng has moved off the
    // old buffer, so no new bytes arrive — this loop terminates.
    while (old_buffer && old_buffer->size() > 0) {
        char *data;
        auto sz = old_buffer->get(&data);
        if (sz > 0) {
            if (fwrite(data, sz, 1, old_file) != 1) {
                int e = errno;
                _MSG_ERROR("pcapng_ring: error draining ring slot '{}' - {}",
                        old_path,
                        ferror(old_file) ? kis_strerror_r(e) : "short write");
                break;
            }
        }
        old_buffer->consume(sz);
    }

    fclose(old_file);
    // old_buffer's shared_ptr drops here; the buffer object lives until any
    // outstanding snapshot-thread copy (via force_rotate_now) also drops.
}

void kis_pcapng_ring_logfile::close_log() {
    kis_lock_guard<kis_mutex> lk(log_mutex, "pcapng_ring close_log");

    if (!get_log_open())
        return;

    set_int_log_open(false);
    shutting_down = true;
    // Wake any snapshot thread blocked in force_rotate_now() so it
    // returns false promptly instead of waiting the full 5s timeout.
    rotation_cv.notify_all();

    std::shared_ptr<future_chainbuf> buf;
    {
        std::lock_guard<std::mutex> blk(buffer_mutex);
        buf = buffer;
    }
    if (buf)
        buf->cancel();

    if (stream_t.joinable())
        stream_t.join();

    if (prune_t.joinable())
        prune_t.join();

    if (ring_file != nullptr) {
        fclose(ring_file);
        ring_file = nullptr;
    }

    if (pcapng != nullptr) {
        delete pcapng;
        pcapng = nullptr;
    }
}

std::vector<std::string>
kis_pcapng_ring_logfile::list_complete_ring_slots() const {
    // Snapshot reads ring slots from disk directly; the writer thread keeps
    // each slot self-contained (its own pcapng SHB) so concatenation yields
    // a valid multi-section pcapng. We exclude the currently-active slot
    // because it may be mid-write.

    std::vector<std::pair<std::string, time_t>> slots;
    auto active_path = ring_slot_path(active_slot);

    for (unsigned int i = 0; i < ring_file_count; i++) {
        auto path = ring_slot_path(i);
        if (path == active_path)
            continue;
        struct stat st;
        if (stat(path.c_str(), &st) != 0)
            continue;
        if (!S_ISREG(st.st_mode) || st.st_size == 0)
            continue;
        slots.emplace_back(path, st.st_mtime);
    }

    std::sort(slots.begin(), slots.end(),
            [](const std::pair<std::string, time_t>& a,
               const std::pair<std::string, time_t>& b) {
                return a.second < b.second;
            });

    std::vector<std::string> result;
    result.reserve(slots.size());
    for (auto& s : slots)
        result.push_back(std::move(s.first));
    return result;
}

void kis_pcapng_ring_logfile::concat_files(const std::vector<std::string>& sources,
        const std::string& dest, uint64_t *out_bytes) {
    *out_bytes = 0;

    // Skip writing an empty file when there's nothing to copy. The caller
    // checks *out_bytes == 0 and reports / warns as appropriate. Producing
    // a 0-byte file would mislead operators who try to open it in
    // wireshark (which would error with "not a valid pcapng").
    if (sources.empty())
        return;

    FILE *out = fopen(dest.c_str(), "w");
    if (out == nullptr) {
        int e = errno;
        throw std::runtime_error(fmt::format("failed to open '{}' for write: {}",
                    dest, kis_strerror_r(e)));
    }

    std::vector<char> buf(SNAPSHOT_COPY_BUFFER_BYTES);

    for (const auto& src : sources) {
        FILE *in = fopen(src.c_str(), "r");
        if (in == nullptr) {
            // A ring slot we listed a moment ago may have been overwritten by
            // a rotation in the interim — skip it rather than aborting the
            // whole snapshot.
            _MSG_INFO("pcapng_ring: ring slot '{}' vanished mid-snapshot, skipping",
                    src);
            continue;
        }

        while (true) {
            size_t n = fread(buf.data(), 1, buf.size(), in);
            if (n == 0) {
                if (ferror(in)) {
                    int e = errno;
                    _MSG_ERROR("pcapng_ring: read error on '{}': {}",
                            src, kis_strerror_r(e));
                }
                break;
            }
            size_t w = fwrite(buf.data(), 1, n, out);
            if (w != n) {
                int e = errno;
                bool ferr = ferror(out);
                fclose(in);
                fclose(out);
                throw std::runtime_error(fmt::format(
                        "short write to '{}' ({}/{} bytes): {}", dest, w, n,
                        ferr ? kis_strerror_r(e) : "no errno"));
            }
            *out_bytes += n;
        }
        fclose(in);
    }

    fclose(out);
}

bool kis_pcapng_ring_logfile::force_rotate_now(std::chrono::seconds timeout) {
    if (shutting_down)
        return false;

    uint64_t before;
    {
        std::lock_guard<std::mutex> lk(rotation_mutex);
        before = rotation_count;
    }

    force_rotate_pending = true;

    // Capture the current buffer via shared_ptr under buffer_mutex. The
    // copy keeps the buffer alive across our sync() call even if the
    // writer rotates and drops its own reference between our load and
    // our sync (which would have been a use-after-free with a raw ptr).
    // sync() sets the wait promise without flipping the buffer's
    // cancel_ flag (unlike cancel(), which would tear the writer down).
    std::shared_ptr<future_chainbuf> buf;
    {
        std::lock_guard<std::mutex> lk(buffer_mutex);
        buf = buffer;
    }
    if (buf)
        buf->sync();

    std::unique_lock<std::mutex> lk(rotation_mutex);
    return rotation_cv.wait_for(lk, timeout, [this, before]() {
        return rotation_count > before || shutting_down.load();
    });
}

uint64_t kis_pcapng_ring_logfile::persist_dir_free_bytes() const {
    struct statvfs st;
    if (statvfs(persist_dir.c_str(), &st) != 0) {
        _MSG_ERROR("pcapng_ring: statvfs('{}') failed - {}",
                persist_dir, kis_strerror_r(errno));
        return 0;
    }
    return static_cast<uint64_t>(st.f_bavail) *
           static_cast<uint64_t>(st.f_frsize);
}

std::string kis_pcapng_ring_logfile::snapshot(const std::string& label,
        unsigned int post_seconds) {
    if (!validate_snapshot_label(label))
        throw std::runtime_error("invalid snapshot label");

    if (post_seconds == 0)
        post_seconds = default_post_seconds;

    // Clamp post_seconds to bound how long the HTTPD worker thread is held.
    // The route handler runs on a beast worker; sleeping it for >60s would
    // back up unrelated UI requests behind this snapshot. Operators who
    // want longer post windows should fire a follow-up snapshot rather
    // than a single very long one. Documented in kismet_logging.conf.
    constexpr unsigned int MAX_POST_SECONDS = 60;
    if (post_seconds > MAX_POST_SECONDS) {
        _MSG_INFO("pcapng_ring: snapshot '{}' clamping post_seconds={} to {}",
                label, post_seconds, MAX_POST_SECONDS);
        post_seconds = MAX_POST_SECONDS;
    }

    kis_lock_guard<kis_mutex> lk(snapshot_mutex, "pcapng_ring snapshot");

    if (!get_log_open())
        throw std::runtime_error("pcapng_ring log is not open");

    // Safety floor: refuse rather than silently prune when disk is tight.
    auto free_bytes = persist_dir_free_bytes();
    if (free_bytes < persist_min_free_bytes) {
        throw std::runtime_error(fmt::format(
                "insufficient free space in '{}': have {} MB, need at least {} MB",
                persist_dir,
                free_bytes / (1024 * 1024),
                persist_min_free_bytes / (1024 * 1024)));
    }

    auto snap_dir = persist_dir + "/" + label;
    if (mkdir_p(snap_dir, 0700) != 0) {
        throw std::runtime_error(fmt::format(
                "failed to create snapshot dir '{}': {}",
                snap_dir, kis_strerror_r(errno)));
    }

    // Force a rotation so the currently-active ring slot (which holds all
    // packets captured up to this moment) is closed and becomes a
    // "complete" slot eligible for copy. Without this, low-traffic
    // captures produce 0-byte pre.pcapng because list_complete_ring_slots
    // excludes the active slot to avoid racing the writer's fwrite.
    if (!force_rotate_now(std::chrono::seconds(5))) {
        _MSG_ERROR("pcapng_ring: snapshot '{}' pre-rotate did not complete "
                "within 5s — forensic evidence may be incomplete", label);
    }

    auto pre_sources = list_complete_ring_slots();
    auto pre_path = snap_dir + "/pre.pcapng";
    uint64_t pre_bytes = 0;
    concat_files(pre_sources, pre_path, &pre_bytes);

    // Path-based dedup of pre vs post slots. Sufficient unless the ring
    // wraps during the post window (only happens under sustained heavy
    // traffic) — in that case some pre slots are overwritten and their
    // new content shows up in post too. Acceptable for forensic use.
    std::set<std::string> pre_slot_set(pre_sources.begin(), pre_sources.end());

    _MSG_INFO("pcapng_ring: snapshot '{}' pre={} bytes from {} slots, "
            "recording {}s post-trigger window",
            label, pre_bytes, pre_sources.size(), post_seconds);

    std::this_thread::sleep_for(std::chrono::seconds(post_seconds));

    // Second force rotation: the slot that filled during post_seconds was
    // the active one and thus excluded from list_complete_ring_slots; rotate
    // it out so it becomes selectable as a post source.
    if (!force_rotate_now(std::chrono::seconds(5))) {
        _MSG_ERROR("pcapng_ring: snapshot '{}' post-rotate did not complete "
                "within 5s — forensic evidence may be incomplete", label);
    }

    // Post sources = all complete slots NOT already in pre. After the
    // second force rotate, the slot that was active during the post window
    // is now complete and selectable.
    auto current_slots = list_complete_ring_slots();
    std::vector<std::string> post_sources;
    for (const auto& s : current_slots) {
        if (pre_slot_set.count(s) == 0)
            post_sources.push_back(s);
    }

    auto post_path = snap_dir + "/post.pcapng";
    uint64_t post_bytes = 0;
    concat_files(post_sources, post_path, &post_bytes);

    _MSG_INFO("pcapng_ring: snapshot '{}' complete, pre={} bytes post={} bytes",
            label, pre_bytes, post_bytes);

    if (pre_bytes == 0 && post_bytes == 0) {
        _MSG_ERROR("pcapng_ring: snapshot '{}' produced no data — verify "
                "Kismet has an active datasource and the ring is rotating",
                label);
    }

    return pre_path;
}

void kis_pcapng_ring_logfile::prune_loop() {
    // Spin in short sleeps so shutdown notices the shutting_down flag quickly.
    while (!shutting_down) {
        for (unsigned int i = 0; i < persist_prune_interval && !shutting_down; i++) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (shutting_down)
            return;
        prune_once();
    }
}

void kis_pcapng_ring_logfile::prune_once() {
    DIR *d = opendir(persist_dir.c_str());
    if (d == nullptr) {
        // Persist dir may not exist yet; not worth alerting every cycle.
        return;
    }

    struct SnapshotEntry {
        std::string path;
        time_t mtime;
        uint64_t size;
    };
    std::vector<SnapshotEntry> entries;

    struct dirent *de;
    while ((de = readdir(d)) != nullptr) {
        std::string name(de->d_name);
        if (name == "." || name == "..")
            continue;
        auto child = persist_dir + "/" + name;
        struct stat st;
        if (lstat(child.c_str(), &st) != 0)
            continue;
        if (!S_ISDIR(st.st_mode))
            continue;
        entries.push_back({child, st.st_mtime, dir_size_bytes(child)});
    }
    closedir(d);

    std::sort(entries.begin(), entries.end(),
            [](const SnapshotEntry& a, const SnapshotEntry& b) {
                return a.mtime < b.mtime;
            });

    auto now = time(nullptr);
    auto age_cutoff = static_cast<time_t>(persist_max_age_days) * 24 * 3600;

    uint64_t total = 0;
    for (auto& e : entries)
        total += e.size;

    for (auto& e : entries) {
        bool too_old = (now - e.mtime) > age_cutoff;
        bool over_cap = total > persist_max_total_bytes;
        if (!too_old && !over_cap)
            break;

        _MSG_INFO("pcapng_ring: pruning snapshot '{}' ({} bytes, age {} days)",
                e.path, e.size, (now - e.mtime) / (24 * 3600));
        remove_dir_recursive(e.path);
        total = (total > e.size) ? (total - e.size) : 0;
    }
}

