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

#ifndef __DATASOURCE_CELL_PATHS_H__
#define __DATASOURCE_CELL_PATHS_H__

#include "config.h"

#include <climits>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>

#include "fmt.h"
#include "globalregistry.h"
#include "trackedelement.h"
#include "util.h"

// The file options of a local cell source name a file in the Kismet log
// directory, never a path, so a definition or a runtime setting sent through
// the web UI cannot point a capture at any other file.  A bare name (with the
// captures' %i/%m/%t templates) is placed in the log directory, and "." lets a
// directory-capable option pick its own name there.  A value already placed
// there, as a reopen sends it, passes unchanged.  Remote sources are left to
// the capture host, whose operator chose their definition.

namespace cell_paths {
    struct file_opt {
        const char *key;
        bool dir_ok;
        bool off_ok;
    };

    constexpr size_t max_name = 255;

    inline std::string log_dir() {
        auto dir = Globalreg::globalreg->log_prefix;

        if (dir.empty())
            dir = "./";

        char real[PATH_MAX];
        if (realpath(dir.c_str(), real) != nullptr)
            dir = real;

        while (dir.size() > 1 && dir.back() == '/')
            dir.pop_back();

        return dir;
    }

    inline bool name_ok(const std::string& name) {
        if (name.empty() || name.size() > max_name || name == "." || name == "..")
            return false;

        for (unsigned char c : name) {
            if (c < 0x20 || c == 0x7f || c == '/' || c == '\\' || c == ',' || c == '"')
                return false;
        }

        return true;
    }

    inline const file_opt *find_opt(const std::vector<file_opt>& opts, const std::string& key) {
        auto k = str_lower(key);

        for (const auto& o : opts) {
            if (k == o.key)
                return &o;
        }

        return nullptr;
    }

    inline bool confine(const file_opt& opt, std::string& value, std::string& err) {
        if (opt.off_ok && (value == "off" || value == "none"))
            return true;

        auto dir = log_dir();
        auto base = dir == "/" ? dir : dir + "/";

        if (value.compare(0, base.size(), base) == 0) {
            auto rest = value.substr(base.size());

            if ((rest.empty() && opt.dir_ok) || name_ok(rest))
                return true;
        }

        if (opt.dir_ok && value == ".") {
            value = base;
            return true;
        }

        if (name_ok(value)) {
            value = base + value;
            return true;
        }

        err = fmt::format("{}= must be a file name in the Kismet log directory ({}), "
                "not a path", opt.key, dir);
        return false;
    }

    // One runtime setting or hop channel, "key=value"; anything else passes
    inline bool confine_setting(const std::vector<file_opt>& opts, std::string& setting,
            std::string& err) {
        auto eq = setting.find('=');

        if (eq == std::string::npos)
            return true;

        auto key = str_strip(setting.substr(0, eq));
        auto value = str_strip(setting.substr(eq + 1));

        auto opt = find_opt(opts, key);

        if (opt == nullptr)
            return true;

        if (!confine(*opt, value, err))
            return false;

        setting = key + "=" + value;
        return true;
    }

    // The parsed options of a definition, including settings carried in its
    // channel= and channels= lists
    inline bool confine_definition(const std::vector<file_opt>& opts,
            std::map<std::string, std::string>& def_opts, std::string& err) {
        for (auto& d : def_opts) {
            auto opt = find_opt(opts, d.first);

            if (opt != nullptr) {
                if (!confine(*opt, d.second, err))
                    return false;
            } else if (d.first == "channel") {
                if (!confine_setting(opts, d.second, err))
                    return false;
            } else if (d.first == "channels") {
                auto chans = str_tokenize(d.second, ",");

                for (auto& c : chans) {
                    if (!confine_setting(opts, c, err))
                        return false;
                }

                d.second = str_join(chans, ",");
            }
        }

        return true;
    }

    // A whole definition string, before it is opened, for an error the operator can read
    inline bool check_definition(const std::vector<file_opt>& opts, const std::string& definition,
            std::string& err) {
        auto cpos = definition.find(':');

        if (cpos == std::string::npos)
            return true;

        std::vector<opt_pair> parsed;

        if (string_to_opts(definition.substr(cpos + 1), ",", &parsed) < 0)
            return true;

        std::map<std::string, std::string> def_opts;

        for (const auto& p : parsed)
            def_opts[str_lower(p.opt)] = p.val;

        return confine_definition(opts, def_opts, err);
    }

    // A hop list, copied with its settings confined
    inline std::shared_ptr<tracker_element_vector_string> confine_hop(const std::vector<file_opt>& opts,
            const std::shared_ptr<tracker_element_vector_string>& chans, std::string& err) {
        if (chans == nullptr)
            return chans;

        auto out = std::make_shared<tracker_element_vector_string>(chans->get_id());

        for (const auto& c : *chans) {
            auto setting = c;

            if (!confine_setting(opts, setting, err))
                return nullptr;

            out->push_back(setting);
        }

        return out;
    }
}

#endif
