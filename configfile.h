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

#ifndef __CONFIGFILE_H__
#define __CONFIGFILE_H__

#include "config.h"

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <pwd.h>

#include <string>
#include <map>
#include <vector>

#include "globalregistry.h"
#include "macaddr.h"

class ConfigFile {
public:
	ConfigFile(GlobalRegistry *in_globalreg) { globalreg = in_globalreg; checksum = 0; }

    int ParseConfig(const char *in_fname);
	int SaveConfig(const char *in_fname);

    string FetchOpt(string in_key);
    vector<string> FetchOptVec(string in_key);

	// Fetch a true/false t/f value with a default (ie value returned if not
	// equal to true, or missing.)
	int FetchOptBoolean(string in_key, int dvalue);

	int FetchOptDirty(string in_key);
	void SetOptDirty(string in_key, int in_dirty);

	void SetOpt(string in_key, string in_val, int in_dirty);
	void SetOptVec(string in_key, vector<string> in_val, int in_dirty);

    string ExpandLogPath(string path, string logname, string type, 
						 int start, int overwrite = 0);

	// Fetches the load-time checksum of the config values.
	uint32_t FetchFileChecksum();

protected:
	GlobalRegistry *globalreg;
	void CalculateChecksum();

    map<string, vector<string> > config_map;
	map<string, int> config_map_dirty;
	uint32_t checksum;
	string ckstring;
};

// Config file with grouping.  Only used at the moment for runtime log file
// parsing.  Doesn't currently support the 'include = ' statement, either
class GroupConfigFile {
public:
	class GroupEntity {
	public:
		string name;
		map<string, vector<string> > value_map;
	};

	GroupConfigFile() { 
		checksum = 0; 
		root = NULL;
	}
	int ParseConfig(const char *in_fname);

	// Return the vector of entities in this group, or the top groups if NULL
	vector<GroupEntity *> FetchEntityGroup(GroupEntity *in_parent);

    string FetchOpt(string in_key, GroupEntity *in_parent);
    vector<string> FetchOptVec(string in_key, GroupEntity *in_parent);

	uint32_t FetchFileChecksum();

protected:
	void CalculateChecksum();

	map<GroupEntity *, vector<GroupEntity *> > parsed_group_map;

	uint32_t checksum;

	GroupEntity *root;
};

#endif

