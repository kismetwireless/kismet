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

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <getopt.h>

#include "configfile.h"
#include "globalregistry.h"
#include "messagebus.h"
#include "plugintracker.h"
#include "version.h"
#include "kis_httpd_registry.h"

void plugin_registration_data::activate_external_http() {
    // If we have a http proxy, instantiate and load it
    if (get_plugin_http_external() != "") {
        external_http = 
            std::make_shared<external_http_plugin_harness>(get_plugin_name(), get_plugin_http_external());
        external_http->start_external_plugin();
    }
}

plugin_tracker::plugin_tracker() :
    lifetime_global() {

    plugin_lock.set_name("plugin_tracker");

    httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    plugin_registry_vec = std::make_shared<tracker_element_vector>();

    int option_idx = 0;
    int cmdline_disable = 0;
    int config_disable = 0;

    // Longopts
    static struct option plugin_long_options[] = {
        {"disable-plugins", no_argument, 0, 10}, {0, 0, 0, 0}};

    optind = 0;

    while (1) {
        int r = getopt_long(Globalreg::globalreg->argc, Globalreg::globalreg->argv, "-",
                            plugin_long_options, &option_idx);

        if (r < 0) break;
        switch (r) {
            case 10:
                cmdline_disable = 1;
                break;
        }
    }

    if (Globalreg::globalreg->kismet_config->fetch_opt("allowplugins") == "true") {
        config_disable = 0;
    } else {
        config_disable = 1;
    }

    if (config_disable || cmdline_disable) {
        plugins_active = 0;
        _MSG(
            "Plugin system disabled by Kismet configuration file or "
            "command line",
            MSGFLAG_INFO);
        return;
    }

    plugins_active = 1;

    httpd->register_route("/plugins/all_plugins", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(plugin_registry_vec, plugin_lock));
}

plugin_tracker::~plugin_tracker() {
    // Call the main shutdown, which should kill the vector allocations
    shutdown_plugins();
}

void plugin_tracker::usage(char *name __attribute__((unused))) {
    printf(" *** Plugin Options ***\n");
    printf("     --disable-plugins		  Turn off the plugin "
           "system\n");
}

int plugin_tracker::scan_plugins() {
    kis_lock_guard<kis_mutex> lk(plugin_lock, "plugin_tracker scan_plugins");

    // Bail if plugins disabled
    if (plugins_active == 0) return 0;

    std::string plugin_path = std::string(LIB_LOC) + "/kismet/";
    DIR *plugdir;

    if ((plugdir = opendir(plugin_path.c_str())) == NULL) {
        _MSG("Could not open system plugin directory (" + plugin_path +
                 "), skipping: " + strerror(errno), MSGFLAG_INFO);
    } else {
        if (scan_directory(plugdir, plugin_path) < 0) return -1;
        closedir(plugdir);
    }

    std::string config_path;
    if ((config_path = Globalreg::globalreg->kismet_config->fetch_opt("configdir")) == "") {
        _MSG(
            "Failed to find a 'configdir' path in the Kismet config file, "
            "ignoring local plugins.",
            MSGFLAG_INFO);
        return 0;
    }

    plugin_path = Globalreg::globalreg->kismet_config->expand_log_path(
        config_path + "/plugins/", "", "", 0, 1);
    if ((plugdir = opendir(plugin_path.c_str())) == NULL) {
        _MSG("Did not find a user plugin directory (" + plugin_path +
                 "), skipping: " + strerror(errno), MSGFLAG_INFO);
    } else {
        if (scan_directory(plugdir, plugin_path) < 0) {
            closedir(plugdir);
            return -1;
        }
        closedir(plugdir);
    }

    return 1;
}

// Scans a directory for sub-directories
int plugin_tracker::scan_directory(DIR *in_dir, std::string in_path) {
    struct dirent *plugfile;

    while ((plugfile = readdir(in_dir)) != NULL) {
        if (plugfile->d_name[0] == '.') continue;

        struct stat sstat;

        // Is it a directory?
        if (stat(std::string(in_path + "/" + plugfile->d_name).c_str(), &sstat) < 0)
            continue;

        if (!S_ISDIR(sstat.st_mode))
            continue;

        // Load the plugin manifest
        config_file cf;

        std::string manifest = in_path + "/" + plugfile->d_name + "/manifest.conf";

        cf.parse_config(manifest.c_str());

        SharedPluginData preg(new plugin_registration_data());

        preg->set_plugin_path(in_path + "/" + plugfile->d_name + "/");
        preg->set_plugin_dirname(plugfile->d_name);

        std::string s;

        if ((s = cf.fetch_opt("name")) == "") {
            _MSG("Missing 'name=' in plugin manifest '" + manifest + "', "
                    "cannot load plugin", MSGFLAG_ERROR);
            continue;
        }

        preg->set_plugin_name(s);

        if ((s = cf.fetch_opt("description")) == "") {
            _MSG("Missing 'description=' in plugin manifest '" + manifest + "', "
                    "cannot load plugin", MSGFLAG_ERROR);
            continue;
        }

        preg->set_plugin_description(s);


        if ((s = cf.fetch_opt("author")) == "") {
            _MSG("Missing 'author=' in plugin manifest '" + manifest + "', "
                    "cannot load plugin", MSGFLAG_ERROR);
            continue;
        }

        preg->set_plugin_author(s);


        if ((s = cf.fetch_opt("version")) == "") {
            _MSG("Missing 'version=' in plugin manifest '" + manifest + "', "
                    "cannot load plugin", MSGFLAG_ERROR);
            continue;
        }

        preg->set_plugin_version(s);


        if ((s = cf.fetch_opt("object")) != "") {
            if (s.find("/") != std::string::npos) {
                _MSG("Found path in 'object=' in plugin manifest '" + manifest +
                        "', object= should define the file name only", MSGFLAG_ERROR);
                continue;
            }

            preg->set_plugin_so(s);
        }

        if ((s = cf.fetch_opt("httpexternal")) != "") {
            if (s.find("/") != std::string::npos) {
                _MSG_ERROR("Found path in 'httpexternal=' in plugin manifest '{}', "
                        "httpexternal= should define the binary name only.", manifest);
                continue;
            }

            preg->set_plugin_http_external(s);
        } else if ((s = cf.fetch_opt("kisexternal")) != "") {
            if (s.find("/") != std::string::npos) {
                _MSG_ERROR("Found path in 'kisexternal=' in plugin manifest '{}', "
                        "httpexternal= should define the binary name only.", manifest);
                continue;
            }

            preg->set_plugin_http_external(s);
        }

        if ((s = cf.fetch_opt("js")) != "") {
            if (s.find(",") == std::string::npos) {
                _MSG("Found an invalid 'js=' in plugin manifest '" + manifest +
                        "', js= should define module,path", MSGFLAG_ERROR);
                continue;
            }

            preg->set_plugin_js(s);
        }

        // Make sure we haven't already loaded another copy of the plugin
        // based on the so or the pluginname
        for (auto x : plugin_preload) {
            // Don't load the same plugin
            if (preg->get_plugin_so() != "" &&
                    x->get_plugin_so() == preg->get_plugin_so()) {
                continue;
            }

            if (x->get_plugin_name() == preg->get_plugin_name()) {
                continue;
            }
        }

        // We've gotten to here, it's valid, push it into the preload vector
        plugin_preload.push_back(preg);
    }

    return 1;
}

// Catch plugin failures so we can alert the user
std::string global_plugin_load;
void PluginServerSignalHandler(int sig __attribute__((unused))) {
    fprintf(stderr,
            "\n\n"
            "FATAL: Kismet crashed while loading a plugin...\n"
            "Plugin loading: %s\n\n"
            "This is either a bug in the plugin, or the plugin needs "
            "to be recompiled\n"
            "to match the version of Kismet you are using (especially "
            "if you are using\n"
            "development/git versions of Kismet or have recently "
            "upgraded.)\n\n"
            "Remove the plugin from the plugins directory, or start "
            "Kismet with \n"
            "plugins disabled (--no-plugins)\n\n",
            global_plugin_load.c_str());
    exit(1);
}

int plugin_tracker::activate_plugins() {
#ifdef SYS_CYGWIN
    _sig_func_ptr old_segv = SIG_DFL;
#else
    sig_t old_segv = SIG_DFL;
#endif

    kis_lock_guard<kis_mutex> lk(plugin_lock, "plugin_tracker activate_plugins");

    std::shared_ptr<kis_httpd_registry> httpdregistry =
        Globalreg::fetch_global_as<kis_httpd_registry>(Globalreg::globalreg, "WEBREGISTRY");

    // Set the new signal handler, remember the old one; if something goes
    // wrong loading the plugins we need to catch it and return a special
    // error
    old_segv = signal(SIGSEGV, PluginServerSignalHandler);

    for (auto x : plugin_preload) {
        // Does this plugin load a SO?
        if (x->get_plugin_so() != "") {
            global_plugin_load = x->get_plugin_path() + "/" + x->get_plugin_so();

            void *dlfile = dlopen(global_plugin_load.c_str(), RTLD_LAZY);

            if (dlfile == NULL) {
                _MSG("Failed to open plugin '" + x->get_plugin_path() +
                        "' as a shared library: " + kis_strerror_r(errno),
                        MSGFLAG_ERROR);
                continue;
            }

            x->set_plugin_dlfile(dlfile);

            // Find the symbol for kis_plugin_version_check
            plugin_version_check vcheck_sym = 
                (plugin_version_check) dlsym(dlfile, "kis_plugin_version_check");

            if (vcheck_sym == NULL) {
                _MSG("Failed to get plugin version check function from plugin '" +
                        x->get_plugin_path() +
                        "': Ensure that all plugins have "
                        "been recompiled for the proper version of Kismet, "
                        "especially if you're using a development or git version "
                        "of Kismet.", MSGFLAG_ERROR);
                continue;
            }

            struct plugin_server_info sinfo;
            sinfo.plugin_api_version = KIS_PLUGINTRACKER_VERSION;

            if ((*vcheck_sym)(&sinfo) < 0) {
                _MSG("Plugin '" + x->get_plugin_path() +
                        "' could not perform "
                        "a version check.  Ensure that all plugins have been "
                        "recompiled for the proper version of Kismet, especially "
                        "if you're using a development or git version of Kismet.",
                        MSGFLAG_ERROR);
                continue;
            }

            if (sinfo.plugin_api_version != KIS_PLUGINTRACKER_VERSION ||
                    sinfo.kismet_major != Globalreg::globalreg->version_major ||
                    sinfo.kismet_minor != Globalreg::globalreg->version_minor ||
                    sinfo.kismet_tiny != Globalreg::globalreg->version_tiny) {
                _MSG("Plugin '" + x->get_plugin_path() +
                        "' was compiled "
                        "with a different version of Kismet; Please recompile "
                        "the plugin and re-install it, or remove it entirely.",
                        MSGFLAG_ERROR);
                continue;
            }

            plugin_activation act_sym =
                (plugin_activation) dlsym(dlfile, "kis_plugin_activate");

            if (act_sym == NULL) {
                _MSG("Failed to get plugin registration function from plugin '" +
                        x->get_plugin_path() +
                        "': Ensure that all plugins have "
                        "been recompiled for the proper version of Kismet, "
                        "especially if you're using a development or git version "
                        "of Kismet.", MSGFLAG_ERROR);
                continue;
            }

            if ((act_sym)(Globalreg::globalreg) < 0) {
                _MSG("Plugin '" + x->get_plugin_path() + "' failed to activate, "
                        "skipping.", MSGFLAG_ERROR);
                continue;
            }
        }

        // If we have a JS module, load it
        if (x->get_plugin_js() != "") {
            std::string js = x->get_plugin_js();
            size_t cpos = js.find(",");

            if (cpos == std::string::npos || cpos >= js.length() - 2) {
                _MSG("Plugin '" + x->get_plugin_path() + "' could not parse "
                        "JS plugin module, expected modulename,path",
                        MSGFLAG_ERROR);
                continue;
            }

            std::string plugmod = js.substr(0, cpos);
            std::string path = js.substr(cpos + 1, js.length());

            if (path.length() == 0) {
                _MSG_ERROR("Plugin '{}' invalid JS plugin module, expected path",
                        x->get_plugin_path());
                continue;
            }

            if (path[0] == '/') {
                _MSG_ERROR("Plugin '{}' invalid JS plugin module, expected relative path "
                        "but got absolute path beginning with '/'", x->get_plugin_path());
                continue;
            }

            if (!httpdregistry->register_js_module(plugmod, path)) {
                _MSG("Plugin '" + x->get_plugin_path() + "' could not "
                        "register JS plugin module", MSGFLAG_ERROR);
                continue;
            }
        }

        // Activate external http if we have it
        x->activate_external_http();

        // Alias the plugin directory
        httpd->register_static_dir("/plugin/" + x->get_plugin_dirname() + "/",
                x->get_plugin_path() + "/httpd/");

        _MSG("Plugin '" + x->get_plugin_name() + "' loaded...", MSGFLAG_INFO);

        plugin_registry_vec->push_back(x);
    }

    // Reset the segv handler
    signal(SIGSEGV, old_segv);

    plugin_preload.clear();

    return 1;
}

int plugin_tracker::finalize_plugins() {
    // Look only at plugins that have a dl file, and attempt to run the finalize
    // function in each
    for (auto x : *plugin_registry_vec) {
        SharedPluginData pd = std::dynamic_pointer_cast<plugin_registration_data>(x);

        void *dlfile;

        if ((dlfile = pd->get_plugin_dlfile()) != NULL) {
            plugin_activation final_sym = 
                (plugin_activation) dlsym(dlfile, "kis_plugin_finalize");

            if (final_sym == NULL)
                continue;

            if ((final_sym)(Globalreg::globalreg) < 0) {
                _MSG("Plugin '" + pd->get_plugin_path() + "' failed to complete "
                        "activation...", MSGFLAG_ERROR);
                continue;
            }
        }
    }
    
    return 1;
}

int plugin_tracker::shutdown_plugins() {
    kis_lock_guard<kis_mutex> lk(plugin_lock, "plugin_tracker shutdow_plugins");

    _MSG("Shutting down plugins...", MSGFLAG_INFO);

    plugin_preload.clear();

    return 0;
}

