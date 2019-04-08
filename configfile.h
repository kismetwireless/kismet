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
#include "kis_mutex.h"

class HeaderValueConfig;

class ConfigFile {
public:
    ConfigFile();
	ConfigFile(GlobalRegistry *in_globalreg);
    ~ConfigFile();

    int ParseConfig(const char *in_fname);
    int ParseConfig(const std::string& in_fname) {
        return ParseConfig(in_fname.c_str());
    }

	int SaveConfig(const char *in_fname);
    int SaveConfig(const std::string& in_fname) {
        return SaveConfig(in_fname.c_str());
    }

    std::string FetchOpt(std::string in_key);
    std::string FetchOptDfl(std::string in_key, std::string in_dfl);
    std::string FetchOpt_nl(std::string in_key);
    std::vector<std::string> FetchOptVec(std::string in_key);

	// Fetch a true/false t/f value with a default (ie value returned if not
	// equal to true, or missing.)
	int FetchOptBoolean(std::string in_key, int dvalue);

    // Older API
    int FetchOptInt(const std::string& in_key, int dvalue);
    unsigned int FetchOptUInt(const std::string& in_key, unsigned int dvalue);
    unsigned long int FetchOptULong(const std::string& in_key, unsigned long dvalue);

    // New C++ api; fetch an opt as a dynamic type dervied via '>>' assignment; will thow
    // std::runtime_error if the type can not be converted.  If the key is not found, the
    // default value is used.
    template<typename T>
    T FetchOptAs(const std::string& in_key, const T& dvalue) {
        local_locker l(&config_locker);

        auto ki = config_map.find(StrLower(in_key));

        if (ki == config_map.end())
            return dvalue;

        std::stringstream ss(ki->second[0].value);
        T conv_value;
        ss >> conv_value;

        if (ss.fail())
            throw std::runtime_error(fmt::format("could not coerce content of key {}", in_key));

        return conv_value;
    }

	int FetchOptDirty(const std::string& in_key);
	void SetOptDirty(const std::string& in_key, int in_dirty);

    // Set a value, converting the arbitrary input into a string
    template<typename T>
    void SetOpt(const std::string& in_key, const T in_value, int in_dirty) {
        local_locker l(&config_locker); 
        std::vector<config_entity> v;
        config_entity e(fmt::format("{}", in_value), "::dynamic::");
        v.push_back(e);
        config_map[StrLower(in_key)] = v;
        SetOptDirty(in_key, in_dirty);
    }

	void SetOpt(const std::string& in_key, const std::string& in_val, int in_dirty);
	void SetOptVec(const std::string& in_key, const std::vector<std::string>& in_val, int in_dirty);

    // Expand complete log templates for logfile filenames
    std::string ExpandLogPath(const std::string& path, const std::string& logname, 
            const std::string& type, int start, int overwrite = 0);

    // Expand placeholders but not full log type/number/etc, for included config references, etc
    std::string ExpandLogPath(const std::string& path) {
        return ExpandLogPath(path, "", "", 0, 1);
    }

	// Fetches the load-time checksum of the config values.
	uint32_t FetchFileChecksum();

protected:
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

    // Optional included file, don't error if it's not found
    int ParseOptInclude(const std::string path,
            std::map<std::string, std::vector<config_entity> > &target_map,
            std::map<std::string, int> &target_map_dirty);

    // Option included override file, don't error if it's not found; parsed
    // at the END of the file parse cycle, for each 
    int ParseOptOverride(const std::string path);

    int ParseConfig(const char *in_fname, 
            std::map<std::string, std::vector<config_entity> > &target_map,
            std::map<std::string, int> &target_map_dirty);

    std::string filename;

    std::map<std::string, std::vector<config_entity> > config_map;
    std::map<std::string, int> config_map_dirty;
    uint32_t checksum;
    std::string ckstring;

    // List of config files which are *overriding*
    std::vector<std::string> config_override_file_list;

    kis_recursive_timed_mutex config_locker;
};

// Representation of 'complex' kismet config file values of the type:
// confvalue=header:key1=value1,key2=value2,key3=value3
//
// Values may also be quoted:
// confvalue=header:key1="value1,1a,1b",key2=value2,...
class HeaderValueConfig {
public:
    HeaderValueConfig(const HeaderValueConfig& hc) {
        header = hc.header;
        content_map = std::map<std::string, std::string> {hc.content_map};
    }

    HeaderValueConfig(const std::string& in_confline);
    HeaderValueConfig();

    void parseLine(const std::string& in_confline);

    std::string getHeader();
    void setHeader(const std::string& in_str);

    // Does a key exist?
    bool hasKey(const std::string& in_key);

    // Get a value by key, value MUST exist or std::runtime_exception is thrown
    std::string getValue(const std::string& in_key);

    // Get a value by key, if value is not present, return default value
    std::string getValue(const std::string& in_key, const std::string& in_default);

    // Get a value by key, coercing string content to another type; will throw 
    // std::runtime_error if the content cannot be coerced.  
    // If the key is not present, return the defautl value
    template<typename T>
    T getValueAs(const std::string& in_key, const T& dvalue) {
        local_locker l(&mutex);

        auto ki = content_map.find(StrLower(in_key));

        if (ki == content_map.end())
            return dvalue;

        std::stringstream ss(ki->second);
        T conv_value;
        ss >> conv_value;

        if (ss.fail())
            throw std::runtime_error(fmt::format("could not coerce content of key {}", in_key));

        return conv_value;
    }

    // Set a value, converting the arbitrary input into a string
    template<typename T>
    void setValue(const std::string& in_key, T in_value) {
        local_locker l(&mutex); 
        content_map[in_key] = fmt::format("{}", in_value);
    }

    // Erase a key; will not throw exception if key does not exist
    void eraseKey(const std::string& in_key);

    // Encode to string.  All values will be quoted for safety.
    std::string toString();
    friend std::ostream& operator<<(std::ostream& os, const HeaderValueConfig& c);
    friend std::istream& operator>>(std::istream& is, HeaderValueConfig& c);

protected:
    kis_recursive_timed_mutex mutex;

    std::string header;
    std::map<std::string, std::string> content_map;

};

std::ostream& operator<<(std::ostream& os, const HeaderValueConfig& h);
std::istream& operator>>(std::istream& is, HeaderValueConfig& h);

#endif

