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

#include "messagebus.h"
#include "configfile.h"
#include "kis_httpd_registry.h"
#include "version.h"

namespace {
    constexpr uint64_t fnv_offset = 0xcbf29ce484222325ULL;
    constexpr uint64_t fnv_prime = 0x100000001b3ULL;

    constexpr uint64_t fnv1a(uint64_t h, const char *s, size_t len) {
        for (size_t i = 0; i < len; i++) {
            h ^= static_cast<uint8_t>(s[i]);
            h *= fnv_prime;
        }
        return h;
    }

    uint64_t fnv1a(uint64_t h, const std::string& s) {
        // Separator, so "ab"+"c" and "a"+"bc" differ
        return fnv1a(fnv1a(h, s.data(), s.length()), "\0", 1);
    }
}

kis_httpd_registry::kis_httpd_registry() :
    lifetime_global() {
    reg_lock.set_name("kis_httpd_registry");

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_unauth_route("/dynamic.json", {"GET"}, 
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    kis_lock_guard<kis_mutex> lk(reg_lock, "httpd_registry /dynamic.json");

                    nlohmann::json::object_t root;
                    nlohmann::json::array_t vec;

                    // The build token changes with the server build and its set of UI
                    // modules, so the web UI knows when its cached copies are stale
                    auto build = fnv_offset;
                    build = fnv1a(build, VERSION_MAJOR);
                    build = fnv1a(build, VERSION_MINOR);
                    build = fnv1a(build, VERSION_TINY);
                    build = fnv1a(build, VERSION_GIT_COMMIT);
                    build = fnv1a(build, VERSION_BUILD_TIME);

                    for (const auto& m : js_module_path_map) {
                        nlohmann::json::object_t rec;
                        rec["module"] = m.first;
                        rec["js"] = m.second;

                        auto u = ui2_module_path_map.find(m.first);
                        if (u != ui2_module_path_map.end())
                            rec["ui2"] = u->second;

                        build = fnv1a(fnv1a(build, m.first), m.second);
                        vec.push_back(rec);
                    }

                    for (const auto& u : ui2_module_path_map) {
                        build = fnv1a(fnv1a(build, u.first), u.second);

                        if (js_module_path_map.find(u.first) != js_module_path_map.end())
                            continue;

                        nlohmann::json::object_t rec;
                        rec["module"] = u.first;
                        rec["ui2"] = u.second;
                        vec.push_back(rec);
                    }

                    root["build"] = fmt::format("{:016x}", build);
                    root["dynamicjs"] = vec;

                    std::ostream os(&con->response_stream());
                    os << root;
                }));

	httpd->register_unauth_route("/dynamic.js", {"GET"},
			std::make_shared<kis_net_web_function_endpoint>(
				[this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
					kis_lock_guard<kis_mutex> lk(reg_lock, "httpd_registry /dyamic.js");
                    
					std::ostream os(&con->response_stream());

					os << "var local_uri_prefix = \"./\";" << std::endl;
					os << "if (typeof(KISMET_URI_PREFIX) !== 'undefined')" << std::endl;
    				os << "local_uri_prefix = KISMET_URI_PREFIX;" << std::endl;

					for (const auto& m : js_module_path_map) {
						os << "var " << m.first << ";" << std::endl;
					}

					os << "async function load_dynamics() {" << std::endl;

					for (const auto& m : js_module_path_map) {
						os << m.first << " = await import(`${local_uri_prefix}" << m.second << 
							"`);" << std::endl;
					}

					os << "}" << std::endl;
					
				}
				));
}

kis_httpd_registry::~kis_httpd_registry() {

}

bool kis_httpd_registry::register_js_module(std::string in_module, std::string in_path) {
    kis_lock_guard<kis_mutex> lk(reg_lock);

    if (js_module_path_map.find(in_module) != js_module_path_map.end()) {
        _MSG_ERROR("HTTPD Module Registry: Module '{}' already registered",
                in_module);
        return false;
    }

    // Hack around for re-homing kismet resources; alert on a leading '/' and fix it.
    if (in_path.length() == 0) {
        _MSG_ERROR("HTTPD Module Registry: Module {} with no path", in_module);
        return false;
    }

    /*
    if (in_path[0] == '/') {
        _MSG_ERROR("HTTPD Module Registry: Module {} starts with a '/', for newer "
                "Kismet systems this should be a relative path; check that your plugin "
                "is updated.  Kismet will automatically make this a relative path.",
                in_module);
        in_path = in_path.substr(1, in_path.length());
    }
    */

    js_module_path_map[in_module] = in_path;

    return true;
}

bool kis_httpd_registry::register_ui2_module(std::string in_module, std::string in_path) {
    kis_lock_guard<kis_mutex> lk(reg_lock);

    if (in_path.length() == 0 || in_path[0] == '/' || in_path.find("..") != std::string::npos) {
        _MSG_ERROR("HTTPD Module Registry: ui2 module {} needs a relative path", in_module);
        return false;
    }

    if (ui2_module_path_map.find(in_module) != ui2_module_path_map.end()) {
        _MSG_ERROR("HTTPD Module Registry: ui2 module '{}' already registered", in_module);
        return false;
    }

    ui2_module_path_map[in_module] = in_path;

    return true;
}
