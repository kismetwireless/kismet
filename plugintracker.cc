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

#include "config.hpp"

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "configfile.h"
#include "getopt.h"
#include "globalregistry.h"
#include "messagebus.h"
#include "plugintracker.h"
#include "version.h"

Plugintracker::Plugintracker(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&plugin_lock, &mutexattr);

    int option_idx = 0;
    int cmdline_disable = 0;
    int config_disable = 0;

    // Longopts
    static struct option plugin_long_options[] = {
        {"disable-plugins", no_argument, 0, 10}, {0, 0, 0, 0}};

    optind = 0;

    while (1) {
        int r = getopt_long(globalreg->argc, globalreg->argv, "-",
                            plugin_long_options, &option_idx);

        if (r < 0) break;
        switch (r) {
            case 10:
                cmdline_disable = 1;
                break;
        }
    }

    if (globalreg->kismet_config->FetchOpt("allowplugins") == "true") {
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

    plugin_registry.reset(new TrackerElement(TrackerVector));
    plugin_registry_vec = TrackerElementVector(plugin_registry);
}

Plugintracker::~Plugintracker() {
    local_eol_locker lock(&plugin_lock);

    // Call the main shutdown, which should kill the vector allocations
    ShutdownPlugins();

    pthread_mutex_destroy(&plugin_lock);
}

void Plugintracker::Usage(char *name __attribute__((unused))) {
    printf(" *** Plugin Options ***\n");
    printf("     --disable-plugins		  Turn off the plugin "
           "system\n");
}

int Plugintracker::ScanPlugins() {
    local_locker lock(&plugin_lock);

    // Bail if plugins disabled
    if (plugins_active == 0) return 0;

    string plugin_path = string(LIB_LOC) + "/kismet/";
    DIR *plugdir;

    if ((plugdir = opendir(plugin_path.c_str())) == NULL) {
        _MSG("Failed to open primary plugin directory (" + plugin_path +
                 "): " + strerror(errno),
             MSGFLAG_ERROR);
    } else {
        if (ScanDirectory(plugdir, plugin_path) < 0) return -1;
        closedir(plugdir);
    }

    string config_path;
    if ((config_path = globalreg->kismet_config->FetchOpt("configdir")) == "") {
        _MSG(
            "Failed to find a 'configdir' path in the Kismet config file, "
            "ignoring local plugins.",
            MSGFLAG_ERROR);
        return 0;
    }

    plugin_path = globalreg->kismet_config->ExpandLogPath(
        config_path + "/plugins/", "", "", 0, 1);
    if ((plugdir = opendir(plugin_path.c_str())) == NULL) {
        _MSG("Failed to open user plugin directory (" + plugin_path +
                 "): " + strerror(errno),
             MSGFLAG_ERROR);
    } else {
        if (ScanDirectory(plugdir, plugin_path) < 0) return -1;
        closedir(plugdir);
    }

    return 1;
}

// Scan a directory for all .so files and query them
int Plugintracker::ScanDirectory(DIR *in_dir, string in_path) {
    struct dirent *plugfile;

    while ((plugfile = readdir(in_dir)) != NULL) {
        if (plugfile->d_name[0] == '.') continue;

        string fname = plugfile->d_name;

        // Found a .so
        if (fname.rfind(".so") == fname.length() - 3) {
            // Make sure we haven't already loaded another copy
            // of this plugin (based on the file name) - the same
            // copy could exist in the system and user plugin directories

            for (auto x = plugin_preload.begin(); x != plugin_preload.end();
                 ++x) {
                // Don't load the same plugin
                if ((*x)->get_plugin_so() == fname) {
                    continue;
                }
            }

            // Make a preload record
            SharedPluginData prereg(new PluginRegistrationData(globalreg, 0));

            prereg->set_plugin_so(fname);
            prereg->set_plugin_path(in_path + "/" + fname);

            plugin_preload.push_back(prereg);
        }
    }

    return 1;
}

// Catch plugin failures so we can alert the user
string global_plugin_load;
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

int Plugintracker::ActivatePlugins() {
#ifdef SYS_CYGWIN
    _sig_func_ptr old_segv = SIG_DFL;
#else
    sig_t old_segv = SIG_DFL;
#endif

    local_locker lock(&plugin_lock);

    // Set the new signal handler, remember the old one; if something goes
    // wrong loading the plugins we need to catch it and return a special
    // error
    old_segv = signal(SIGSEGV, PluginServerSignalHandler);

    for (auto x = plugin_preload.begin(); x != plugin_preload.end(); ++x) {
        global_plugin_load = (*x)->get_plugin_path();

        void *dlfile = dlopen((*x)->get_plugin_path().c_str(), RTLD_LAZY);

        if (dlfile == NULL) {
            _MSG("Failed to open plugin '" + (*x)->get_plugin_path() +
                     "' as "
                     "a shared library: " +
                     kis_strerror_r(errno),
                 MSGFLAG_ERROR);
            continue;
        }

        (*x)->set_plugin_dlfile(dlfile);

        // Find the symbol for kis_plugin_versioN_check
        plugin_version_check vcheck_sym = 
            (plugin_version_check) dlsym(dlfile, "kis_plugin_version_check");

        if (vcheck_sym == NULL) {
            _MSG("Failed to get plugin version check function from plugin '" +
                     (*x)->get_plugin_path() +
                     "': Ensure that all plugins have "
                     "been recompiled for the proper version of Kismet, "
                     "especially if you're using a development or git version "
                     "of Kismet.",
                 MSGFLAG_ERROR);
            continue;
        }

        struct plugin_server_info sinfo;
        sinfo.plugin_api_version = KIS_PLUGINTRACKER_VERSION;

        if ((*vcheck_sym)(&sinfo) < 0) {
            _MSG("Plugin '" + (*x)->get_plugin_path() +
                     "' could not perform "
                     "a version check.  Ensure that all plugins have been "
                     "recompiled for the proper version of Kismet, especially "
                     "if you're using a development or git version of Kismet.",
                 MSGFLAG_ERROR);
            continue;
        }

        if (sinfo.plugin_api_version != KIS_PLUGINTRACKER_VERSION ||
            sinfo.kismet_major != globalreg->version_major ||
            sinfo.kismet_minor != globalreg->version_minor ||
            sinfo.kismet_tiny != globalreg->version_tiny) {
            _MSG("Plugin '" + (*x)->get_plugin_path() +
                     "' was compiled "
                     "with a different version of Kismet; Please recompile the "
                     "plugin and re-install it, or remove it entirely.",
                 MSGFLAG_ERROR);
            continue;
        }

        plugin_register reg_sym =
            (plugin_register) dlsym(dlfile, "kis_plugin_register");

        if (reg_sym == NULL) {
            _MSG("Failed to get plugin registration function from plugin '" +
                     (*x)->get_plugin_path() +
                     "': Ensure that all plugins have "
                     "been recompiled for the proper version of Kismet, "
                     "especially if you're using a development or git version "
                     "of Kismet.",
                 MSGFLAG_ERROR);
            continue;
        }

        if ((reg_sym)(globalreg, (*x)) < 0) {
            _MSG("Plugin '" + (*x)->get_plugin_path() +
                     "' could not perform "
                     "a version check.  Ensure that all plugins have been "
                     "recompiled for the proper version of Kismet, especially "
                     "if you're using a development or git version of Kismet.",
                 MSGFLAG_ERROR);
            continue;
        }

        _MSG("Plugin '" + (*x)->get_plugin_name() + "' loaded...",
                MSGFLAG_INFO);

        plugin_registry_vec.push_back(*x);

    }

    // Reset the segv handler
    signal(SIGSEGV, old_segv);

    plugin_preload.clear();

    return 1;
}

int Plugintracker::ShutdownPlugins() {
    local_locker lock(&plugin_lock);

    _MSG("Shutting down plugins...", MSGFLAG_INFO);

    plugin_registry_vec.clear();
    plugin_preload.clear();

    return 0;
}

bool Plugintracker::Httpd_VerifyPath(const char *path, const char *method) {
    return false;
}

void Plugintracker::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

}
