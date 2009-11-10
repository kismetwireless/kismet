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

#ifndef __PLUGINTRACKER_H__
#define __PLUGINTRACKER_H__

// Plugin handler core
//
// Handles scanning the config file, stocking the vector of plugins with root
// and nonroot plugins, getting the plugin info from the shared object, and
// calling the various plugin handler hooks.
//
// This is fairly platform specific -- posix systems should all be able to use
// the dlopen/dlsym/dlclose system, but it will have to be turned into 
// native code on win32 if we ever port there
//
// PLUGIN AUTHORS:  This is the Kismet internal tracking system that handles
// plugins.  All you need to worry about is filling in the plugin_usrdata struct
// and returning the proper info for register/unregister.
//
// PLUGIN VERSIONING:  Plugins should define a kis_plugin_info(...) function
// (as defined below) which fills in the supplied struct with the version_major,
// version_minor, and version_tiny of the *kismet* versions the plugin was compiled
// with.  These are used to make sure that the plugin is running in a sane environment.
//
// Plugins which operate as root WILL NOT be able to perform root actions after
// the privdrop has occured.  Currently there are no hooks to modularize the 
// server/rootpid system, this may change if needed in the future.  Open any
// files and sockets you need before the drop.

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <sys/types.h>
#include <dirent.h>

#include "globalregistry.h"

// Generic plugin function hook
typedef int (*plugin_hook)(GlobalRegistry *);

// This struct is passed to a plugin to be filled in with all their info
struct plugin_usrdata {
	// Basic info about the plugin
	string pl_name;
	string pl_description;
	string pl_version;
	
	// Can this plugin be unloaded?  Anything that touches capture sources 
	// should definitely say no, and anything else that sets up dynamic 
	// structures that can't be reasonably disassembled or recreated should
	// answer no.  Unloadable plugins should still handle the unload event in
	// a permanent fashion, this just means Kismet will not ask it to unload
	// during runtime.
	int pl_unloadable;

	// Call back to initialized.  A 0 return means "try again later in the build
	// chain", a negative means "failure" and a positive means success.
	plugin_hook plugin_register;

	// Callback to be removed
	plugin_hook plugin_unregister;
	
};

// Plugin information fetch function
typedef int (*plugin_infocall)(plugin_usrdata *);

// Plugin version information, v1
// This holds revision information for the KISMET THE PLUGIN WAS COMPILED WITH,
// NOT THE PLUGIN VERSION (plugin version is passed in the info struct!)
struct plugin_revision {
	// V1 data 

	// Versioned for possible updates to the version api
	int version_api_revision;

	string major;
	string minor;
	string tiny;

	// End V1 data
};

#define KIS_PLUGINTRACKER_VREVISION		1

// Plugin revision call.  If the kis_plugin_revision  symbol is available in the plugin,
// then it will be passed an allocated plugin_revision struct, with the version_api_rev
// set appropriately.  Plugins MUST ONLY use fields in the negotiated plugin version
// record.  This record is not expected to change significantly over time, BUT IT MAY,
// should it become necessary to add more complex data.
typedef void (*plugin_revisioncall)(plugin_revision *);

// Plugin management class
class Plugintracker {
public:
	struct plugin_meta {
		plugin_meta() {
			dlfileptr = NULL;
			activate = 0;
			root = 0;
			infosym = NULL;
		};

		// Path to plugin
		string filename; 
		// Object name of the plugin
		string objectname;

		// Pointer to dlopened file
		void *dlfileptr;
		// Plugin has successfully activated?
		int activate;
		// Plugin is activated as root?
		int root;

		// Data from the plugin
		plugin_usrdata usrdata;

		// Info symbol
		plugin_infocall infosym;
	};

	static void Usage(char *name);

	Plugintracker();
	Plugintracker(GlobalRegistry *in_globalreg);
	virtual ~Plugintracker();

	// Parse the config file and load root plugins into the vector
	int ScanRootPlugins();

	// Scan the plugins directories and load all the found plugins for userspace
	int ScanUserPlugins();

	// Activate the vector of plugins (called repeatedly during startup)
	int ActivatePlugins();

	// Last chance for plugins to activate or we error out
	int LastChancePlugins();

	// Shut down the plugins and close the shared files
	int ShutdownPlugins();

	// Network hook to send the plugins to a user on enable
	int BlitPlugins(int in_fd);

protected:
	GlobalRegistry *globalreg;
	int plugins_active;

	int ScanDirectory(DIR *in_dir, string in_path);

	vector<plugin_meta *> plugin_vec;

	int plugins_protoref;
};

#endif

