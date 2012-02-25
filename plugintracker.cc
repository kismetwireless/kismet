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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <dlfcn.h>
#include <dirent.h>
#include <signal.h>

#include "globalregistry.h"
#include "configfile.h"
#include "getopt.h"
#include "messagebus.h"
#include "plugintracker.h"
#include "kis_netframe.h"
#include "version.h"

// Plugin protocol stuff
enum PLUGIN_fields {
	PLUGIN_fname, PLUGIN_name, PLUGIN_version, 
	PLUGIN_description, PLUGIN_unloadable, PLUGIN_root,
	PLUGIN_maxfield
};

const char *PLUGIN_fields_text[] = {
	"filename", "name", "version", "description", 
	"unloadable", "root", NULL
};

int Protocol_PLUGIN(PROTO_PARMS) {
	Plugintracker::plugin_meta *meta = (Plugintracker::plugin_meta *) data;

	for (unsigned int x = 0; x < field_vec->size(); x++) {
		unsigned int fnum = (*field_vec)[x];
		if (fnum >= PLUGIN_maxfield) {
			out_string = "Unknown field requests";
			return -1;
		}

		switch (fnum) {
			case PLUGIN_fname:
				out_string += "\001" + MungeToPrintable(meta->objectname) + "\001";
				break;
			case PLUGIN_name:
				out_string += "\001" +
					MungeToPrintable(meta->usrdata.pl_name) + "\001";
				break;
			case PLUGIN_version:
				out_string += "\001" +
					MungeToPrintable(meta->usrdata.pl_version) + "\001";
				break;
			case PLUGIN_description:
				out_string += "\001" + 
					MungeToPrintable(meta->usrdata.pl_description) + "\001";
				break;
			case PLUGIN_unloadable:
				if (meta->usrdata.pl_unloadable)
					out_string += "1";
				else
					out_string += "0";
				break;
			case PLUGIN_root:
				if (meta->root)
					out_string += "1";
				else
					out_string += "0";
				break;
		}

		out_string += " ";
	}

	return 1;
}

void Protocol_PLUGIN_enable(PROTO_ENABLE_PARMS) {
	Plugintracker *ptrak = (Plugintracker *) data;

	ptrak->BlitPlugins(in_fd);

	return;
}

Plugintracker::Plugintracker() {
	fprintf(stderr, "FATAL OOPS:  Plugintracker() called with no globalreg\n");
	exit(1);
}

Plugintracker::Plugintracker(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	if (globalreg->kismet_config == NULL) {
		fprintf(stderr, "FATAL OOPS:  Plugintracker called while config is NULL\n");
		exit(1);
	}

	if (globalreg->kisnetserver == NULL) {
		fprintf(stderr, "FATAL OOPS:  Plugintracker called while netframe is NULL\n");
		exit(1);
	}

	int option_idx = 0;
	int cmdline_disable = 0;
	int config_disable = 0;

	// Longopts
	static struct option plugin_long_options[] = {
		{ "disable-plugins", no_argument, 0, 10 },
		{ 0, 0, 0, 0 }
	};

	optind = 0;

	while (1) {
		int r = getopt_long(globalreg->argc, globalreg->argv,
							"-",
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

	plugins_protoref = 
		globalreg->kisnetserver->RegisterProtocol("PLUGIN", 0, 0,
												  PLUGIN_fields_text,
												  &Protocol_PLUGIN,
												  &Protocol_PLUGIN_enable,
												  this);

	if (config_disable || cmdline_disable) {
		plugins_active = 0;
		_MSG("Plugin system disabled by Kismet configuration file or command line",
			 MSGFLAG_INFO);
		return;
	}

	plugins_active = 1;

}

Plugintracker::~Plugintracker() {
	// Call the main shutdown, which should kill the vector allocations
	ShutdownPlugins();

	globalreg->kisnetserver->RemoveProtocol(plugins_protoref);
}

void Plugintracker::Usage(char *name) {
	printf(" *** Plugin Options ***\n");
	printf("     --disable-plugins		  Turn off the plugin system\n");
}

int Plugintracker::ScanRootPlugins() {
	// Bail if plugins disabled
	if (plugins_active == 0)
		return 0;

	// Fetch the list of root plugins
	vector<string> root_plugin_names = 
		globalreg->kismet_config->FetchOptVec("rootplugin");

	if (root_plugin_names.size() == 0)
		return 0;

	// Don't even bother doing anything special if we're not root, just
	// msg and drop out, they'll get loaded as userpriv and fail or succeed as 
	// they will.
	if (getuid() != 0) {
		_MSG("Not running as root, skipping root plugin load process.  Any plugins "
			 "which require root privs will not load properly.", MSGFLAG_ERROR);
		return 0;
	}

	string plugin_path = string(LIB_LOC) + "/kismet/";

	// Stat the directory holding the plugins
	struct stat filestat; 

	if (stat(plugin_path.c_str(), &filestat) < 0) {
		_MSG("Failed to stat the primary plugin directory (" + plugin_path + "): " +
			 strerror(errno), MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	// Make sure its owned by root
	if (filestat.st_uid != 0 || filestat.st_gid != 0) {
		_MSG("The primary plugin directory (" + plugin_path + ") is not owned by "
			 "root:root.  For security, Kismet requires that the directory be owned "
			 "by root if plugins are loaded before the privdrop.  See the "
			 "'Installation & Security' and 'Configuration' sections of the README "
			 "file for more information about the security measures used by Kismet "
			 "and the proper permissions for the plugin directory.",
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	if ((filestat.st_mode & (S_IWGRP | S_IWOTH))) {
		_MSG("The primary plugin directory (" + plugin_path +") does not have secure "
			 "file permissions.  This could allow modification of plugins which load "
			 "before the privdrop.  See the 'Installation & Security' and "
			 "'Configuration' sections of the README file for more information about "
			 "the security measures used by Kismet and the proper permissions for "
			 "the plugin directory.", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	// Start checking the plugins
	for (unsigned int x = 0; x < root_plugin_names.size(); x++) {
		string rootplugname = plugin_path + root_plugin_names[x];

		if (stat(rootplugname.c_str(), &filestat) < 0) {
			_MSG("Failed to stat specified root plugin '" + root_plugin_names[x] + 
				 "': " + strerror(errno), MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
		}

		if ((filestat.st_mode & (S_IWGRP | S_IWOTH))) {
			_MSG("The plugin '" + root_plugin_names[x] + "' does not have secure "
				 "file permissions.  This could allow the modification of plugins "
				 "which load before the privdrop.  See the 'Installation & Security' "
				 "and 'Configuration' sections of the README file for more "
				 "information about the security measures used by Kismet and proper "
				 "permissions for plugins.", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
		}

		// Load the meta plugin into our vector
		plugin_meta *meta = new plugin_meta;
		meta->filename = rootplugname;
		meta->objectname = root_plugin_names[x];
		meta->root = 1;
		plugin_vec.push_back(meta);

	}

	return 1;
}

int Plugintracker::ScanUserPlugins() {
	// Bail if plugins disabled
	if (plugins_active == 0)
		return 0;

	string plugin_path = string(LIB_LOC) + "/kismet/";
	DIR *plugdir;

	if ((plugdir = opendir(plugin_path.c_str())) == NULL) {
		_MSG("Failed to open primary plugin directory (" + plugin_path + "): " +
			 strerror(errno), MSGFLAG_ERROR);
	} else {
		if (ScanDirectory(plugdir, plugin_path) < 0)
			return -1;
		closedir(plugdir);
	}

	string config_path;
	if ((config_path = globalreg->kismet_config->FetchOpt("configdir")) == "") {
		_MSG("Failed to find a 'configdir' path in the Kismet config file, "
			 "ignoring local plugins.", MSGFLAG_ERROR);
		return 0;
	}

	plugin_path = 
		globalreg->kismet_config->ExpandLogPath(config_path + "/plugins/",
												"", "", 0, 1);
	if ((plugdir = opendir(plugin_path.c_str())) == NULL) {
		_MSG("Failed to open user plugin directory (" + plugin_path + "): " +
			 strerror(errno), MSGFLAG_ERROR);
	} else {
		if (ScanDirectory(plugdir, plugin_path) < 0)
			return -1;
		closedir(plugdir);
	}

	return 1;
}

int Plugintracker::ScanDirectory(DIR *in_dir, string in_path) {
	struct dirent *plugfile;
	int loaded;

	while ((plugfile = readdir(in_dir)) != NULL) {
		if (plugfile->d_name[0] == '.')
			continue;

		string fname = plugfile->d_name;

		// Found a .so
		loaded = 0;
		if (fname.find(".so") == fname.length() - 3) {
			// Look for the plugin in the vector.  This is slow to iterate every
			// time, but it's only happening once at boot so i don't care.
			for (unsigned int x = 0; x < plugin_vec.size(); x++) {
				if (plugin_vec[x]->filename == in_path + fname) {
					loaded = 1;
					break;
				}
			}

			if (loaded)
				continue;

			// Load the meta plugin into our vector
			plugin_meta *meta = new plugin_meta;
			meta->filename = in_path + fname;
			meta->objectname = fname;
			meta->root = 0;
			plugin_vec.push_back(meta);
		}
	}

	return 1;
}

// Catch plugin failures so we can alert the user
string global_plugin_load;
void PluginServerSignalHandler(int sig) {
	fprintf(stderr, "\n\n"
			"FATAL: Kismet (server) crashed while loading a plugin...\n"
			"Plugin loading: %s\n\n"
			"This is either a bug in the plugin, or the plugin needs to be recompiled\n"
			"to match the version of Kismet you are using (especially if you are using\n"
			"development versions of Kismet or have recently upgraded.)\n\n"
			"Remove the plugin from the plugins directory, or start Kismet with \n"
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

	// Try to activate all the plugins
	for (unsigned int x = 0; x < plugin_vec.size(); x++) {
		// Try to DLOPEN anything that isn't open
		if (plugin_vec[x]->dlfileptr == NULL) {
			global_plugin_load = plugin_vec[x]->filename;

			old_segv = signal(SIGSEGV, PluginServerSignalHandler);

			if ((plugin_vec[x]->dlfileptr = 
				 dlopen(plugin_vec[x]->filename.c_str(), RTLD_LAZY)) == NULL) {
				_MSG("Failed to open plugin '"+ plugin_vec[x]->filename + "': " +
					 dlerror(), MSGFLAG_FATAL);
				globalreg->fatal_condition = 1;
				signal(SIGSEGV, old_segv);
				return -1;
			}

			// Resolve the version function
			plugin_revisioncall vsym = NULL;	
			if ((vsym = (plugin_revisioncall) dlsym(plugin_vec[x]->dlfileptr, 
													"kis_revision_info")) == NULL) {
				_MSG("Failed to find a Kismet version record in plugin '" +
					 plugin_vec[x]->objectname + "'.  This plugin has not been "
					 "updated to use the new version API.  Please download the "
					 "latest version, or contact the plugin authors.  Kismet will "
					 "still load this plugin, but BE WARNED, there is no way "
					 "to know if it was compiled for this version of Kismet, and "
					 "crashes may occur.", MSGFLAG_ERROR);
			} else {
				// Make a struct of whatever PREV we use, it will tell us what
				// it supports in response.
				plugin_revision *prev = new plugin_revision;
				prev->version_api_revision = KIS_PLUGINTRACKER_VREVISION;

				(*vsym)(prev);

				if (prev->version_api_revision >= 1) {
					if (prev->major != string(VERSION_MAJOR) ||
						prev->minor != string(VERSION_MINOR) ||
						prev->tiny != string(VERSION_TINY)) {
						_MSG("Failed to load plugin '" + plugin_vec[x]->objectname + 
							 "': This plugin was compiled for a different version of "
							 "Kismet; Please recompile and reinstall it, or remove "
							 "it entirely.", MSGFLAG_FATAL);
						globalreg->fatal_condition = 1;
						signal(SIGSEGV, old_segv);
						return -1;
					}
				}

				delete(prev);
			}

			// resolve the info function
			if ((plugin_vec[x]->infosym = (plugin_infocall)
				 dlsym(plugin_vec[x]->dlfileptr, "kis_plugin_info")) == NULL) {
				_MSG("Failed to find 'kis_plugin_info' function in plugin '" +
					 plugin_vec[x]->objectname + "': " + strerror(errno),
					 MSGFLAG_FATAL);
				globalreg->fatal_condition = 1;
				signal(SIGSEGV, old_segv);
				return -1;
			}

			// Fetch the info
			int ret;
			ret = (*(plugin_vec[x]->infosym))(&(plugin_vec[x]->usrdata));

			if (ret < 0) {
				_MSG("Failed to fetch info from plugin '" + 
					 plugin_vec[x]->objectname + "'", MSGFLAG_FATAL);
				globalreg->fatal_condition = 1;
				signal(SIGSEGV, old_segv);
				return -1;
			}

			_MSG("Loaded info for plugin '" + plugin_vec[x]->objectname + "': " 
				 "Plugin name: '" + plugin_vec[x]->usrdata.pl_name + "' " 
				 "Plugin version: '" + plugin_vec[x]->usrdata.pl_version + "' "
				 "Plugin description: '" + 
				 plugin_vec[x]->usrdata.pl_description + "'",
				 MSGFLAG_INFO);
		}

		// Run the activate function
		int ret;
		if (plugin_vec[x]->usrdata.plugin_register == NULL || 
			plugin_vec[x]->activate == 1)
			continue;

		ret = (*(plugin_vec[x]->usrdata.plugin_register))(globalreg);

		if (ret < 0) {
			_MSG("Failed to activate plugin '" + plugin_vec[x]->filename + 
				 "'", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			signal(SIGSEGV, old_segv);
			return -1;
		} else if (ret > 0) {
			_MSG("Activated plugin '" + plugin_vec[x]->filename + "': " 
				 "'" + plugin_vec[x]->usrdata.pl_name + "' " 
				 "'" + plugin_vec[x]->usrdata.pl_version + "' ",
				 MSGFLAG_INFO);
			plugin_vec[x]->activate = 1;
		}

		signal(SIGSEGV, old_segv);
	}

	return 1;
}

int Plugintracker::LastChancePlugins() {
	if (ActivatePlugins() < 0 || globalreg->fatal_condition) {
		globalreg->fatal_condition = 1;
		return -1;
	}

	for (unsigned int x = 0; x < plugin_vec.size(); x++) {
		if (plugin_vec[x]->activate == 0) {
			_MSG("Plugin '" + plugin_vec[x]->filename + "' never activated even "
				 "though it responded to the request for plugin information.  This "
				 "plugin has problems and can not be loaded.", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
		}
	}

	return 1;
}

int Plugintracker::ShutdownPlugins() {
	_MSG("Shutting down plugins...", MSGFLAG_INFO);
	for (unsigned int x = 0; x < plugin_vec.size(); x++) {
		if (plugin_vec[x]->activate == 0 ||
			plugin_vec[x]->usrdata.plugin_unregister == NULL)
			continue;

		(*(plugin_vec[x]->usrdata.plugin_unregister))(globalreg);
		dlclose(plugin_vec[x]->dlfileptr);
	}

	// again inefficient, but it only happens once
	for (unsigned int x = 0; x < plugin_vec.size(); x++) {
		delete plugin_vec[x];
	}

	plugin_vec.clear();

	return 0;
}

int Plugintracker::BlitPlugins(int in_fd) {
	for (unsigned int x = 0; x < plugin_vec.size(); x++) {
		kis_protocol_cache cache;
		globalreg->kisnetserver->SendToClient(in_fd, plugins_protoref,
											  (void *) plugin_vec[x], &cache);
	}

	return 1;
}


