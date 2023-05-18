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

class header_value_config;

class config_file {
public:
	config_file();
    ~config_file();

    int parse_config(const char *in_fname);
    int parse_config(const std::string& in_fname) {
        return parse_config(in_fname.c_str());
    }

    int parse_config_silent(const char *in_fname) {
        silent = true;
        return parse_config(in_fname);
    }

    int parse_config_silent(const std::string& in_fname) {
        return parse_config_silent(in_fname.c_str());
    }

	int save_config(const char *in_fname);
    int save_config(const std::string& in_fname) {
        return save_config(in_fname.c_str());
    }

    // Set a final override file that takes place after all other loading
    void set_final_override(const std::string& in_fname) {
        final_override = in_fname;
    }

    std::string fetch_opt(std::string in_key);
    std::string fetch_opt_dfl(std::string in_key, std::string in_dfl);
    std::string fetch_opt_nl(std::string in_key);
    std::vector<std::string> fetch_opt_vec(std::string in_key);

	// Fetch a true/false t/f value with a default (ie value returned if not
	// equal to true, or missing.)
	int fetch_opt_bool(std::string in_key, int dvalue);

    // Fetch an opt as a simple path
    std::string fetch_opt_path(const std::string& in_key, const std::string& in_dfl);

    // Fetch an option as a pre-parsed multivalue group
    header_value_config fetch_opt_complex(const std::string& in_key);

    // Older API
    int fetch_opt_int(const std::string& in_key, int dvalue);
    unsigned int fetch_opt_uint(const std::string& in_key, unsigned int dvalue);
    unsigned long int fetch_opt_ulong(const std::string& in_key, unsigned long dvalue);

    // New C++ api; fetch an opt as a dynamic type derived via '>>' assignment; will throw
    // std::runtime_error if the type can not be converted.  If the key is not found, the
    // default value is used.
    template<typename T>
    T fetch_opt_as(const std::string& in_key, const T& dvalue) {
        kis_lock_guard<kis_mutex> lk(config_locker);

        auto ki = config_map.find(str_lower(in_key));

        if (ki == config_map.end())
            return dvalue;

        std::stringstream ss(ki->second[0].value);
        T conv_value;
        ss >> conv_value;

        if (ss.fail())
            throw std::runtime_error(fmt::format("could not coerce content of key {}", in_key));

        return conv_value;
    }

	int fetch_opt_dirty(const std::string& in_key);
	void set_opt_dirty(const std::string& in_key, int in_dirty);

    // Set a value, converting the arbitrary input into a string
    template<typename T>
    void set_opt(const std::string& in_key, const T in_value, int in_dirty) {
        kis_lock_guard<kis_mutex> lg(config_locker);
        std::vector<config_entity> v;
        config_entity e(fmt::format("{}", in_value), "::dynamic::");
        v.push_back(e);
        config_map[str_lower(in_key)] = v;
        set_opt_dirty(in_key, in_dirty);
    }

	void set_opt(const std::string& in_key, const std::string& in_val, int in_dirty);
	void set_opt_vec(const std::string& in_key, const std::vector<std::string>& in_val, int in_dirty);

    // Expand complete log templates for logfile filenames
    std::string expand_log_path(const std::string& path, const std::string& logname, 
            const std::string& type, int start, int overwrite = 0);

    // Expand placeholders but not full log type/number/etc, for included config references, etc
    std::string expand_log_path(const std::string& path) {
        return expand_log_path(path, "", "", 0, 1);
    }

	// Fetches the load-time checksum of the config values.
	uint32_t fetch_file_checksum();

protected:
    bool silent;

    class config_entity {
    public:
        config_entity(std::string v, std::string sf) {
            value = v;
            sourcefile = sf;
            append = false;
        }

        config_entity(std::string v, std::string sf, bool ap) {
            value = v;
            sourcefile = sf;
            append = ap;
        }

        std::string value;
        std::string sourcefile;
        bool append;
    };

	void calculate_file_checksum();

    // Optional included file, don't error if it's not found
    int parse_opt_include(const std::string path,
            std::map<std::string, std::vector<config_entity> > &target_map,
            std::map<std::string, int> &target_map_dirty);

    // Option included override file, don't error if it's not found; parsed
    // at the END of the file parse cycle, for each 
    int parse_opt_override(const std::string path);

    int parse_config(const char *in_fname, 
            std::map<std::string, std::vector<config_entity> > &target_map,
            std::map<std::string, int> &target_map_dirty);

    std::string process_log_template(const std::string& path, const std::string& logname,
            const std::string& type, unsigned int iteration);

    std::string filename;

    std::map<std::string, std::vector<config_entity> > config_map;
    std::map<std::string, int> config_map_dirty;
    uint32_t checksum;
    std::string ckstring;

    // List of config files which are *overriding*
    std::vector<std::string> config_override_file_list;

    std::string final_override;

    kis_mutex config_locker;
};

// Representation of 'complex' kismet config file values of the type:
// confvalue=header:key1=value1,key2=value2,key3=value3
//
// Values may also be quoted:
// confvalue=header:key1="value1,1a,1b",key2=value2,...
class header_value_config {
public:
    header_value_config(const header_value_config& hc) {
        header = hc.header;
        content_map = std::map<std::string, std::string> {hc.content_map};
    }

    header_value_config(const std::string& in_confline);
    header_value_config();

    void parse_line(const std::string& in_confline);

    std::string get_header();
    void set_header(const std::string& in_str);

    std::string get_raw() {
        return raw;
    };

    // Does a key exist?
    bool has_key(const std::string& in_key);

    // Get a value by key, value MUST exist or std::runtime_exception is thrown
    std::string get_value(const std::string& in_key);

    // Get a value by key, if value is not present, return default value
    std::string get_value(const std::string& in_key, const std::string& in_default);

    // Get a value by key, coercing string content to another type; will throw 
    // std::runtime_error if the content cannot be coerced.  
    // If the key is not present, return the default value
    template<typename T>
    T get_value_as(const std::string& in_key, const T& dvalue) {
        kis_lock_guard<kis_mutex> lk(mutex);

        auto ki = content_map.find(str_lower(in_key));

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
    void set_value(const std::string& in_key, T in_value) {
        kis_lock_guard<kis_mutex> lk(mutex);
        content_map[in_key] = fmt::format("{}", in_value);
    }

    // Erase a key; will not throw exception if key does not exist
    void erase_key(const std::string& in_key);

    // Encode to string.  All values will be quoted for safety.
    std::string to_string();
    friend std::ostream& operator<<(std::ostream& os, const header_value_config& c);
    friend std::istream& operator>>(std::istream& is, header_value_config& c);

protected:
    kis_mutex mutex;

    std::string header;
    std::string raw;
    std::map<std::string, std::string> content_map;

};

std::ostream& operator<<(std::ostream& os, const header_value_config& h);
std::istream& operator>>(std::istream& is, header_value_config& h);

#endif

