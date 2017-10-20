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
	ConfigFile(GlobalRegistry *in_globalreg);
    ~ConfigFile();

    int ParseConfig(const char *in_fname);
	int SaveConfig(const char *in_fname);

    std::string FetchOpt(std::string in_key);
    std::string FetchOptDfl(std::string in_key, std::string in_dfl);
    std::string FetchOpt_nl(std::string in_key);
    std::vector<std::string> FetchOptVec(std::string in_key);

	// Fetch a true/false t/f value with a default (ie value returned if not
	// equal to true, or missing.)
	int FetchOptBoolean(std::string in_key, int dvalue);

    // Fetch an integer option
    int FetchOptInt(std::string in_key, int dvalue);
    unsigned int FetchOptUInt(std::string in_key, unsigned int dvalue);

	int FetchOptDirty(std::string in_key);
	void SetOptDirty(std::string in_key, int in_dirty);

	void SetOpt(std::string in_key, std::string in_val, int in_dirty);
	void SetOptVec(std::string in_key, std::vector<std::string> in_val, int in_dirty);

    std::string ExpandLogPath(std::string path, std::string logname, std::string type, 
            int start, int overwrite = 0);

	// Fetches the load-time checksum of the config values.
	uint32_t FetchFileChecksum();

protected:
	GlobalRegistry *globalreg;

    class config_entity {
    public:
        config_entity(std::string v, std::string sf) {
            value = v;
            sourcefile = sf;
        }

        std::string value;
        std::string sourcefile;
    };

	void CalculateChecksum();

    void ParseOptInclude(const std::string path);

    int ParseConfig(const char *in_fname, 
            std::map<std::string, std::vector<config_entity> > &target_map,
            std::map<std::string, int> &target_map_dirty);

    std::string filename;

    std::map<std::string, std::vector<config_entity> > config_map;
    std::map<std::string, int> config_map_dirty;
    uint32_t checksum;
    std::string ckstring;

    // List of config files which are *overriding*
    std::vector<std::string> config_override_file_lsit;

    std::recursive_timed_mutex config_locker;
};

#endif

