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

#include <string>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <stdexcept>
#include <glob.h>
#include <sys/stat.h>

#include "util.h"

#include "configfile.h"
#include "messagebus.h"

#ifndef GLOB_TILDE_CHECK
#define GLOB_TILDE_CHECK GLOB_TILDE
#endif

// uclibc is missing GLOB_TILDE entirely so just disable it
#ifndef GLOB_TILDE
#define GLOB_TILDE 0
#endif

config_file::config_file() {
    config_locker.set_name("configfile_locker");
    checksum = 0;
    silent = false;
}

config_file::~config_file() {
}

int config_file::parse_config(const char *in_fname) {
    int r;

    r = parse_config(in_fname, config_map, config_map_dirty);

    if (r < 0)
        return r;

    for (auto f : config_override_file_list) {
        r = parse_opt_override(f);

        if (r < 0)
            break;

    }

    config_override_file_list.clear();

    if (final_override.length() > 0)
        parse_opt_override(final_override);

    return r;
}

int config_file::parse_config(const char *in_fname,
        std::map<std::string, std::vector<config_entity> > &target_map,
        std::map<std::string, int> &target_map_dirty) {
    kis_lock_guard<kis_mutex> lk(config_locker, "configfile parse_config");

    FILE *configf;
    char confline[8192];

    std::stringstream sstream;

    if ((configf = fopen(in_fname, "r")) == NULL) {

        if (!silent) {
            _MSG_ERROR("Error reading config file '{}': {}", in_fname, 
                    kis_strerror_r(errno));
        }

        return -1;
    }

    filename = in_fname;

    int lineno = 0;
    while (!feof(configf)) {
        if (fgets(confline, 8192, configf) == NULL || feof(configf)) 
            break;

        lineno++;

        // It's easier to parse this using C++ functions
        std::string parsestr = str_strip(confline);
        std::string directive, value;
        bool append = false;

        if (parsestr.length() == 0)
            continue;
        if (parsestr[0] == '#')
            continue;

        unsigned int eq;

        if ((eq = parsestr.find("=")) > parsestr.length() || eq == 0) {
            directive = parsestr;
            value = "";
        } else {
            if (parsestr[eq - 1] == '+') {
                append = true;
                directive = str_strip(parsestr.substr(0, eq - 1));
                value = str_strip(parsestr.substr(eq + 1, parsestr.length()));
            } else {
                directive = str_strip(parsestr.substr(0, eq));
                value = str_strip(parsestr.substr(eq+1, parsestr.length()));
            }

            if (value == "") {
                sstream << "Illegal config option in '" << in_fname << "' line " <<
                    lineno << ": " << parsestr;
                _MSG(sstream.str(), MSGFLAG_ERROR);
                sstream.str("");
                continue;
            }

            if (directive == "include") {
                value = expand_log_path(value, "", "", 0, 1);

                sstream << "Including sub-config file: " << value;
                _MSG(sstream.str(), MSGFLAG_INFO);
                sstream.str("");

                if (parse_config(value.c_str(), target_map, target_map_dirty) < 0) {
                    fclose(configf);
                    return -1;
                }
            } else if (directive == "opt_include") {
                if (parse_opt_include(expand_log_path(value, "", "", 0, 1), target_map, 
                            target_map_dirty) < 0)
                    return -1;
            } else if (directive == "opt_override") {
                // Store the override for parsing at the end
                config_override_file_list.push_back(expand_log_path(value, "", "", 0, 1));
            } else {
                config_entity e(value, in_fname, append);
                target_map[str_lower(directive)].push_back(e);
                target_map_dirty[str_lower(directive)] = 1;
            }
        }
    }

    fclose(configf);

    return 1;
}

int config_file::parse_opt_include(const std::string path,
        std::map<std::string, std::vector<config_entity> > &target_map,
        std::map<std::string, int> &target_map_dirty) {
    glob_t globbed;
    size_t i;
    struct stat st;

    std::stringstream sstream;

    if (glob(path.c_str(), GLOB_TILDE_CHECK, NULL, &globbed) == 0) {
        for(i=0; i<globbed.gl_pathc; i++) {
            if (stat(globbed.gl_pathv[i], &st) != 0) {
                continue;
            }

            if (!S_ISREG(st.st_mode)) {
                continue;
            }

            sstream << "Loading optional sub-config file: " << globbed.gl_pathv[i];
            _MSG(sstream.str(), MSGFLAG_INFO);
            sstream.str("");

            if (parse_config(globbed.gl_pathv[i], target_map, target_map_dirty) < 0) {
                sstream << "Parsing failed for optional sub-config file: " << 
                    globbed.gl_pathv[i];
                _MSG(sstream.str(), MSGFLAG_ERROR);
                sstream.str("");
                return -1;
            }
        }
    } else {
        sstream << "Optional sub-config file not present: " << path;
        _MSG(sstream.str(), MSGFLAG_INFO);
        sstream.str("");
        return 0;
    }

    globfree(&globbed);

    return 1;
}

int config_file::parse_opt_override(const std::string path) {
    std::map<std::string, std::vector<config_entity> > override_config_map;
    std::map<std::string, int> override_config_map_dirty;
    int r;

    _MSG("Loading config override file '" + path + "'", MSGFLAG_INFO);

    // Parse into our submaps
    r = parse_opt_include(path, override_config_map, override_config_map_dirty);

    // If we hit a legit error or a missing file, bail
    if (r <= 0)
        return r;

    // Clobber or append existing values
    for (auto v : override_config_map) {
        bool appendonly = true;

        for (const auto& uv : v.second) {
            if (!uv.append)
                appendonly = false;
        }

        // If we only use append +=, concat to an existing value, otherwise
        // override per usual since we have a '=' and a '+='
        if (appendonly) {
            for (const auto& uv : v.second) {
                config_map[v.first].push_back(uv);
            }
        } else {
            config_map[v.first] = v.second;
        }
    }

    for (auto d : override_config_map_dirty)
        config_map_dirty[d.first] = d.second;

    return 1;
}


int config_file::save_config(const char *in_fname) {
    kis_lock_guard<kis_mutex> lk(config_locker, "config_file save_config");

    FILE *wf = NULL;

    if ((wf = fopen(in_fname, "w")) == NULL) {
        _MSG_ERROR("Could not write config file {} - {}", in_fname, kis_strerror_r(errno));
        return -1;
    }

    for (auto x = config_map.begin(); x != config_map.end(); ++x) {
        for (unsigned int y = 0; y < x->second.size(); y++) {
            fprintf(wf, "%s=%s\n", x->first.c_str(), x->second[y].value.c_str());
        }
    }

    fclose(wf);
    return 1;
}

std::string config_file::fetch_opt(std::string in_key) {
    kis_lock_guard<kis_mutex> lk(config_locker, "config_file fetch_opt");

    auto cmitr = config_map.find(str_lower(in_key));
    // No such key
    if (cmitr == config_map.end())
        return "";

    // Get a single key if we can
    if (cmitr->second.size() == 0)
        return "";

    std::string val = cmitr->second[0].value;

    return val;
}

std::string config_file::fetch_opt_dfl(std::string in_key, std::string in_dfl) {
    std::string r = fetch_opt(in_key);

    if (r.length() == 0)
        return in_dfl;

    return r;
}

std::vector<std::string> config_file::fetch_opt_vec(std::string in_key) {
    kis_lock_guard<kis_mutex> lk(config_locker, "config_file fetch_opt_vec");

    // Empty vec to return
    std::vector<std::string> eretvec;

    auto cmitr = config_map.find(str_lower(in_key));
    // No such key
    if (cmitr == config_map.end())
        return eretvec;

    for (unsigned int i = 0; i < cmitr->second.size(); i++) {
        eretvec.push_back(cmitr->second[i].value);
    }

    return eretvec;
}

int config_file::fetch_opt_bool(std::string in_key, int dvalue) {
    // Don't lock, we're locked in fetchopt
    // local_locker lock(&config_locker);

    std::string v = str_lower(fetch_opt(in_key));
    int r;

    r = string_to_bool(v);

    if (r == -1)
        return dvalue;

    return r;
}

header_value_config config_file::fetch_opt_complex(const std::string& in_key) {
    return header_value_config(fetch_opt(in_key));
}

std::string config_file::fetch_opt_path(const std::string& in_key, const std::string& in_dfl) {
    auto p = fetch_opt_dfl(in_key, in_dfl);
    return expand_log_path(p, "", "", 0, 1);
}

int config_file::fetch_opt_int(const std::string& in_key, int dvalue) {
    return fetch_opt_as<int>(in_key, dvalue);
}

unsigned int config_file::fetch_opt_uint(const std::string& in_key, unsigned int dvalue) {
    return fetch_opt_as<unsigned int>(in_key, dvalue);
}

unsigned long config_file::fetch_opt_ulong(const std::string& in_key, unsigned long dvalue) {
    return fetch_opt_as<unsigned long>(in_key, dvalue);
}

int config_file::fetch_opt_dirty(const std::string& in_key) {
    kis_lock_guard<kis_mutex> lk(config_locker, "config_file fetch_opt_dirty");
    if (config_map_dirty.find(str_lower(in_key)) == config_map_dirty.end())
        return 0;

    return config_map_dirty[str_lower(in_key)];
}

void config_file::set_opt_dirty(const std::string& in_key, int in_dirty) {
    kis_lock_guard<kis_mutex> lk(config_locker, "config_file set_opt_dirty");
    config_map_dirty[str_lower(in_key)] = in_dirty;
}

void config_file::set_opt(const std::string& in_key, const std::string& in_val, int in_dirty) {
    kis_lock_guard<kis_mutex> lk(config_locker, "config_file set_opt");

    std::vector<config_entity> v;
    config_entity e(in_val, "::dynamic::");
    v.push_back(e);
    config_map[str_lower(in_key)] = v;
    set_opt_dirty(in_key, in_dirty);
}

void config_file::set_opt_vec(const std::string& in_key, const std::vector<std::string>& in_val, 
        int in_dirty) {
    kis_lock_guard<kis_mutex> lk(config_locker, "config_file set_opt_vec");

    std::vector<config_entity> cev;
    for (unsigned int x = 0; x < in_val.size(); x++) {
        config_entity ce(in_val[x], "::dynamic::");
        cev.push_back(ce);
    }

    config_map[str_lower(in_key)] = cev;
    set_opt_dirty(in_key, in_dirty);
}


std::string config_file::process_log_template(const std::string& path, const std::string& logname,
        const std::string& type, unsigned int iteration) {

    std::string logtemplate;

    logtemplate = path;

    for (unsigned int nl = logtemplate.find("%"); nl < logtemplate.length(); nl = logtemplate.find("%", nl)) {
        char op = logtemplate[nl+1];
        logtemplate.erase(nl, 2);

        if (op == 'n')
            logtemplate.insert(nl, logname);
        else if (op == 'd') {
            time_t tnow;
            struct tm now;

            tnow = Globalreg::globalreg->start_time;
            gmtime_r(&tnow, &now);

            char datestr[24];
            strftime(datestr, 24, "%b-%d-%Y", &now);

            logtemplate.insert(nl, datestr);
        }
        else if (op == 'D') {
            time_t tnow;
            struct tm now;

            tnow = Globalreg::globalreg->start_time;
            gmtime_r(&tnow, &now);

            char datestr[24];
            strftime(datestr, 24, "%Y%m%d", &now);

            logtemplate.insert(nl, datestr);
        } else if (op == 't') {
            time_t tnow;
            struct tm now;

            tnow = Globalreg::globalreg->start_time;
            gmtime_r(&tnow, &now);

            char timestr[12];
            strftime(timestr, 12, "%H-%M-%S", &now);

            logtemplate.insert(nl, timestr);
        } else if (op == 'T') {
            time_t tnow;
            struct tm now;

            // tnow = time(0);
            tnow = Globalreg::globalreg->start_time;
            gmtime_r(&tnow, &now);

            char timestr[12];
            strftime(timestr, 12, "%H%M%S", &now);

            logtemplate.insert(nl, timestr);
        } else if (op == 'l') {
            logtemplate.insert(nl, type.c_str());
        } else if (op == 'i') {
            logtemplate.insert(nl, fmt::format("{}", iteration));
        } else if (op == 'I') {
            logtemplate.insert(nl, fmt::format("{:06}", iteration));
        } else if (op == 'h') { 
            if (Globalreg::globalreg->homepath == "") {
                char *pwbuf;
                ssize_t pwbuf_sz;
                struct passwd pw, *pw_result = NULL;

                if ((pwbuf_sz = sysconf(_SC_GETPW_R_SIZE_MAX)) == -1) {
                    pwbuf_sz = 8192;
                }

                pwbuf = new char[pwbuf_sz];

                if (getpwuid_r(getuid(), &pw, pwbuf, pwbuf_sz, &pw_result) != 0 || 
                        pw_result == NULL) {
                    fprintf(stderr, "ERROR:  Could not explode home directory path, getpwuid() failed.\n");
                    exit(1);
                } else {
                    logtemplate.insert(nl, pw_result->pw_dir);
                }

                delete[] pwbuf;
            } else {
                logtemplate.insert(nl, Globalreg::globalreg->homepath);
            }
        } else if (op == 'p') {
            std::string pfx = Globalreg::globalreg->log_prefix;

            if (pfx == "") 
                pfx = fetch_opt_dfl("log_prefix", "./");

            if (pfx != "") 
                if (pfx[pfx.length() - 1] != '/')
                    pfx += "/";

            logtemplate.insert(nl, pfx);
        } else if (op == 'S') {
            logtemplate.insert(nl, Globalreg::globalreg->data_dir);
        } else if (op == 'E') {
            logtemplate.insert(nl, Globalreg::globalreg->etc_dir);
        } else if (op == 'B') {
            logtemplate.insert(nl, BIN_LOC);
        }
    }

    return logtemplate;
}

std::string config_file::expand_log_path(const std::string& path, const std::string& logname, 
        const std::string& type, int start, int overwrite) {
    kis_lock_guard<kis_mutex> lk(config_locker, "config_file expand_log_path");

    auto have_incremental = path.find("%i") != std::string::npos || path.find("%I") != std::string::npos;
    struct stat filstat;

    if (have_incremental) {
        // If we don't have a number we want to use, find the next free
        for (unsigned int i = start; i < 10000; i++) {
            auto logfile = process_log_template(path, logname, type, i);

            if (overwrite)
                return logfile;

            if (stat(logfile.c_str(), &filstat) == 0)
                continue;

            auto lfgz = logfile + ".gz";
            if (stat(lfgz.c_str(), &filstat) == 0)
                continue;

            auto lfbz = logfile + ".bz2";
            if (stat(lfgz.c_str(), &filstat) == 0)
                continue;

            return logfile;
        } 

        _MSG_ERROR("Could not allocate file for {} ({}) within a reasonable search, try moving "
                "similarly named log files out of the logging directory?", logname, type);
        return "";
    }

    auto logfile = process_log_template(path, logname, type, 0);

    if (overwrite)
        return logfile;

    if (stat(logfile.c_str(), &filstat) == 0)
        return "";

    auto lfgz = logfile + ".gz";
    if (stat(lfgz.c_str(), &filstat) == 0)
        return "";

    auto lfbz = logfile + ".bz2";
    if (stat(lfgz.c_str(), &filstat) == 0)
        return "";

    return logfile;
}

uint32_t config_file::fetch_file_checksum() {
    kis_lock_guard<kis_mutex> lk(config_locker, "config_file fetch_file_checksum");

    if (checksum == 0)
        calculate_file_checksum();

    return checksum;
}

void config_file::calculate_file_checksum() {
    kis_lock_guard<kis_mutex> lk(config_locker, "config_file calculate_file_checksum");

    std::string cks;

    for (auto x = config_map.begin(); x != config_map.end(); ++x) {
        cks += x->first;
        for (unsigned int y = 0; y < x->second.size(); y++) {
            cks += x->second[y].value;
        }
    }

    checksum = adler32_checksum(cks.c_str(), cks.length());
}

header_value_config::header_value_config(const std::string& in_confline) {
    parse_line(in_confline);
}

header_value_config::header_value_config() {
}

void header_value_config::parse_line(const std::string& in_confline) {
    kis_lock_guard<kis_mutex> lk(mutex, "header_value_config parse_line");

    auto cpos = in_confline.find(":");

    content_map.clear();

    if (cpos == std::string::npos) {
        header = in_confline;
    } else {
        header = in_confline.substr(0, cpos);
        raw = in_confline.substr(cpos + 1, in_confline.length() - (cpos + 1));
        std::vector<opt_pair> opt_vec;
        string_to_opts(in_confline.substr(cpos + 1, in_confline.size() - cpos), ",", &opt_vec);

        for (auto oi : opt_vec)
            content_map[oi.opt] = oi.val;
    }
}

std::string header_value_config::get_header() {
    kis_lock_guard<kis_mutex> lk(mutex, "header_value_config get_header");
    return header;
}

void header_value_config::set_header(const std::string& in_str) {
    kis_lock_guard<kis_mutex> lk(mutex, "header_value_config set_header");
    header = in_str;
}

bool header_value_config::has_key(const std::string& in_str) {
    kis_lock_guard<kis_mutex> lk(mutex, "header_value_config has_key");
    return (content_map.find(in_str) != content_map.end());
}

std::string header_value_config::get_value(const std::string& in_str) {
    kis_lock_guard<kis_mutex> lk(mutex, "header_value_config get_value");
    
    auto vi = content_map.find(in_str);

    if (vi == content_map.end()) {
        const auto e = fmt::format("no such key in content map: {}", in_str);
        throw std::runtime_error(e);
    }

    return vi->second;
}

std::string header_value_config::get_value(const std::string& in_str, const std::string& in_defl) {
    kis_lock_guard<kis_mutex> lk(mutex, "header_value_config get_value");

    auto vi = content_map.find(in_str);

    if (vi == content_map.end())
        return in_defl;

    return vi->second;
}

void header_value_config::erase_key(const std::string& in_key) {
    kis_lock_guard<kis_mutex> lk(mutex, "header_value_config erase_key");

    auto vi = content_map.find(in_key);

    if (vi == content_map.end())
        return;

    content_map.erase(vi);
}

std::string header_value_config::to_string() {
    std::stringstream ss;

    ss << header << ":";

    bool add_comma = false;
    for (auto kv : content_map) {
        if (add_comma)
            ss << ",";
        add_comma = true;

        ss << kv.first << "=\"" << kv.second << "\"";
    }

    return ss.str();
}

std::ostream& operator<<(std::ostream& os, const header_value_config& h) {
    os << h.header << ":";

    bool add_comma = false;
    for (auto kv : h.content_map) {
        if (add_comma)
            os << ",";
        add_comma = true;

        os << kv.first << "=\"" << kv.second << "\"";
    }

    return os;
}

std::istream& operator>>(std::istream& is, header_value_config& h) {
    std::string sline;
    std::getline(is, sline);
    h.parse_line(sline);
    return is;
}

