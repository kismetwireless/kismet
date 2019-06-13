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

ConfigFile::ConfigFile() {
    checksum = 0;
}

ConfigFile::ConfigFile(GlobalRegistry *in_globalreg) {
    checksum = 0;
}

ConfigFile::~ConfigFile() {
    local_locker lock(&config_locker);
}

int ConfigFile::ParseConfig(const char *in_fname) {
    int r;

    r = ParseConfig(in_fname, config_map, config_map_dirty);

    if (r < 0)
        return r;

    // Check the override vector, warn if there's more than one
    if (config_override_file_list.size() > 1) {
        _MSG("More than one override file included; Kismet will process them "
                "in the order they were defined.", MSGFLAG_INFO);
    }

    for (auto f : config_override_file_list) {
        r = ParseOptOverride(f);

        if (r < 0)
            break;

    }

    config_override_file_list.empty();

    return r;
}

int ConfigFile::ParseConfig(const char *in_fname,
        std::map<std::string, std::vector<config_entity> > &target_map,
        std::map<std::string, int> &target_map_dirty) {
    local_locker lock(&config_locker);

    FILE *configf;
    char confline[8192];

    std::stringstream sstream;

    if ((configf = fopen(in_fname, "r")) == NULL) {

        sstream << "Error reading config file '" << in_fname <<
            "': " << kis_strerror_r(errno);
        _MSG(sstream.str(), MSGFLAG_ERROR);
        return -1;
    }

    filename = in_fname;

    int lineno = 0;
    while (!feof(configf)) {
        if (fgets(confline, 8192, configf) == NULL || feof(configf)) 
            break;

        lineno++;

        // It's easier to parse this using C++ functions
        std::string parsestr = StrStrip(confline);
        std::string directive, value;

        if (parsestr.length() == 0)
            continue;
        if (parsestr[0] == '#')
            continue;

        unsigned int eq;

        if ((eq = parsestr.find("=")) > parsestr.length()) {
            directive = parsestr;
            value = "";
        } else {
            directive = StrStrip(parsestr.substr(0, eq));
            value = StrStrip(parsestr.substr(eq+1, parsestr.length()));

            if (value == "") {
                sstream << "Illegal config option in '" << in_fname << "' line " <<
                    lineno << ": " << parsestr;
                _MSG(sstream.str(), MSGFLAG_ERROR);
                sstream.str("");
                continue;
            }

            if (directive == "include") {
                value = ExpandLogPath(value, "", "", 0, 1);

                sstream << "Including sub-config file: " << value;
                _MSG(sstream.str(), MSGFLAG_INFO);
                sstream.str("");

                if (ParseConfig(value.c_str(), target_map, target_map_dirty) < 0) {
                    fclose(configf);
                    return -1;
                }
            } else if (directive == "opt_include") {
                if (ParseOptInclude(ExpandLogPath(value, "", "", 0, 1), target_map, 
                            target_map_dirty) < 0)
                    return -1;
            } else if (directive == "opt_override") {
                // Store the override for parsing at the end
                config_override_file_list.push_back(ExpandLogPath(value, "", "", 0, 1));
            } else {
                config_entity e(value, in_fname);
                target_map[StrLower(directive)].push_back(e);
                target_map_dirty[StrLower(directive)] = 1;
            }
        }
    }

    fclose(configf);

    return 1;
}

int ConfigFile::ParseOptInclude(const std::string path,
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

            if (ParseConfig(globbed.gl_pathv[i], target_map, target_map_dirty) < 0) {
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

int ConfigFile::ParseOptOverride(const std::string path) {
    std::map<std::string, std::vector<config_entity> > override_config_map;
    std::map<std::string, int> override_config_map_dirty;
    int r;

    _MSG("Loading config override file '" + path + "'", MSGFLAG_INFO);

    // Parse into our submaps
    r = ParseOptInclude(path, override_config_map, override_config_map_dirty);

    // If we hit a legit error or a missing file, bail
    if (r <= 0)
        return r;

    // Clobber any existing values
    for (auto v : override_config_map) 
        config_map[v.first] = v.second;

    for (auto d : override_config_map_dirty)
        config_map_dirty[d.first] = d.second;

    return 1;
}


int ConfigFile::SaveConfig(const char *in_fname) {
    local_locker lock(&config_locker);

    std::stringstream sstream;

    FILE *wf = NULL;

    if ((wf = fopen(in_fname, "w")) == NULL) {

        sstream << "Error writing config file '" << in_fname <<
            "': " << kis_strerror_r(errno);
        _MSG(sstream.str(), MSGFLAG_ERROR);
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

std::string ConfigFile::FetchOpt(std::string in_key) {
    local_locker lock(&config_locker);

    auto cmitr = config_map.find(StrLower(in_key));
    // No such key
    if (cmitr == config_map.end())
        return "";

    // Get a single key if we can
    if (cmitr->second.size() == 0)
        return "";

    std::string val = cmitr->second[0].value;

    return val;
}

std::string ConfigFile::FetchOptDfl(std::string in_key, std::string in_dfl) {
    std::string r = FetchOpt(in_key);

    if (r.length() == 0)
        return in_dfl;

    return r;
}

std::vector<std::string> ConfigFile::FetchOptVec(std::string in_key) {
    local_locker lock(&config_locker);

    // Empty vec to return
    std::vector<std::string> eretvec;

    auto cmitr = config_map.find(StrLower(in_key));
    // No such key
    if (cmitr == config_map.end())
        return eretvec;

    for (unsigned int i = 0; i < cmitr->second.size(); i++) {
        eretvec.push_back(cmitr->second[i].value);
    }

    return eretvec;
}

int ConfigFile::FetchOptBoolean(std::string in_key, int dvalue) {
    // Don't lock, we're locked in fetchopt
    // local_locker lock(&config_locker);

    std::string v = StrLower(FetchOpt(in_key));
    int r;

    r = StringToBool(v);

    if (r == -1)
        return dvalue;

    return r;
}

int ConfigFile::FetchOptInt(const std::string& in_key, int dvalue) {
    return FetchOptAs<int>(in_key, dvalue);
}

unsigned int ConfigFile::FetchOptUInt(const std::string& in_key, unsigned int dvalue) {
    return FetchOptAs<unsigned int>(in_key, dvalue);
}

unsigned long ConfigFile::FetchOptULong(const std::string& in_key, unsigned long dvalue) {
    return FetchOptAs<unsigned long>(in_key, dvalue);
}

int ConfigFile::FetchOptDirty(const std::string& in_key) {
    local_locker lock(&config_locker);
    if (config_map_dirty.find(StrLower(in_key)) == config_map_dirty.end())
        return 0;

    return config_map_dirty[StrLower(in_key)];
}

void ConfigFile::SetOptDirty(const std::string& in_key, int in_dirty) {
    local_locker lock(&config_locker);
    config_map_dirty[StrLower(in_key)] = in_dirty;
}

void ConfigFile::SetOpt(const std::string& in_key, const std::string& in_val, int in_dirty) {
    local_locker lock(&config_locker);

    std::vector<config_entity> v;
    config_entity e(in_val, "::dynamic::");
    v.push_back(e);
    config_map[StrLower(in_key)] = v;
    SetOptDirty(in_key, in_dirty);
}

void ConfigFile::SetOptVec(const std::string& in_key, const std::vector<std::string>& in_val, 
        int in_dirty) {
    local_locker lock(&config_locker);

    std::vector<config_entity> cev;
    for (unsigned int x = 0; x < in_val.size(); x++) {
        config_entity ce(in_val[x], "::dynamic::");
        cev.push_back(ce);
    }

    config_map[StrLower(in_key)] = cev;
    SetOptDirty(in_key, in_dirty);
}


// Expand a logfile into a full filename
// Path/template from config
// Logfile name to use
// Logfile type to use
// Starting number or desired number
std::string ConfigFile::ExpandLogPath(const std::string& path, const std::string& logname, 
        const std::string& type, int start, int overwrite) {
    local_locker lock(&config_locker);

    std::string logtemplate;
    int inc = 0;
    int incpad = 0;

    logtemplate = path;

    for (unsigned int nl = logtemplate.find("%"); nl < logtemplate.length();
            nl = logtemplate.find("%", nl)) {

        char op = logtemplate[nl+1];
        logtemplate.erase(nl, 2);

        if (op == 'n')
            logtemplate.insert(nl, logname);
        else if (op == 'd') {
            time_t tnow;
            struct tm *now;

            // tnow = time(0);
            tnow = Globalreg::globalreg->start_time;
            now = localtime(&tnow);

            char datestr[24];
            strftime(datestr, 24, "%b-%d-%Y", now);

            logtemplate.insert(nl, datestr);
        }
        else if (op == 'D') {
            time_t tnow;
            struct tm *now;

            // tnow = time(0);
            tnow = Globalreg::globalreg->start_time;
            now = localtime(&tnow);

            char datestr[24];
            strftime(datestr, 24, "%Y%m%d", now);

            logtemplate.insert(nl, datestr);
        } else if (op == 't') {
            time_t tnow;
            struct tm *now;

            // tnow = time(0);
            tnow = Globalreg::globalreg->start_time;
            now = localtime(&tnow);

            char timestr[12];
            strftime(timestr, 12, "%H-%M-%S", now);

            logtemplate.insert(nl, timestr);
        } else if (op == 'T') {
            time_t tnow;
            struct tm *now;

            // tnow = time(0);
            tnow = Globalreg::globalreg->start_time;
            now = localtime(&tnow);

            char timestr[12];
            strftime(timestr, 12, "%H%M%S", now);

            logtemplate.insert(nl, timestr);
        } else if (op == 'l') {
            logtemplate.insert(nl, type.c_str());
        } else if (op == 'i') {
            inc = nl;
        } else if (op == 'I') {
            inc = nl;
            incpad = 1;
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
                    fprintf(stderr, "ERROR:  Could not explode home directory path, "
                            "getpwuid() failed.\n");
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
                pfx = FetchOptDfl("log_prefix", "./");

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

    // If we've got an incremental, go back and find it and start testing
    if (inc) {
        int found = 0;

        if (start == 0) {
            // If we don't have a number we want to use, find the next free
            for (int num = 1; num < 10000; num++) {
                std::string copied;
                struct stat filstat;

                char numstr[6];
                if (incpad)
                    snprintf(numstr, 6, "%05d", num);
                else
                    snprintf(numstr, 6, "%d", num);

                copied = logtemplate;
                copied.insert(inc, numstr);
                copied += ".gz";

                if (stat(copied.c_str(), &filstat) == 0) {
                    continue;
                }

                copied = logtemplate;
                copied.insert(inc, numstr);
                copied += ".bz2";

                if (stat(copied.c_str(), &filstat) == 0) {
                    continue;
                }

                copied = logtemplate;
                copied.insert(inc, numstr);

                if (stat(copied.c_str(), &filstat) == 0) {
                    continue;
                }

                // If we haven't been found with any of our variants, we're
                // clean, mark us found

                found = 1;
                logtemplate = copied;
                break;
            }
        } else {
            // Otherwise find out if this incremental is taken
            std::string copied = logtemplate;
            struct stat filstat;
            char numstr[5];
            snprintf(numstr, 5, "%d", start);
            int localfound = 1;

            copied.insert(inc, numstr);

            copied = logtemplate;
            copied.insert(inc, numstr);
            copied += ".gz";

            if (stat(copied.c_str(), &filstat) == 0 && overwrite != 0) {
                localfound = 0;
            }

            copied = logtemplate;
            copied.insert(inc, numstr);
            copied += ".bz2";

            if (stat(copied.c_str(), &filstat) == 0 && overwrite != 0) {
                localfound = 0;
            }

            copied = logtemplate;
            copied.insert(inc, numstr);

            if (stat(copied.c_str(), &filstat) == 0 && overwrite != 0) {
                localfound = 0;
            }

            // If we haven't been found with any of our variants, we're
            // clean, mark us found

            found = localfound;
            if (localfound == 0)
                logtemplate = "";
            else
                logtemplate = copied;
        }


        if (!found) {
            fprintf(stderr, "ERROR:  Unable to find a logging file within 100 hits. "
                    "If you really are logging this many times in 1 day, change "
                    "log names or edit the source.\n");
            exit(1);
        }
    } else {
        struct stat filstat;

        if (stat(logtemplate.c_str(), &filstat) != -1 && overwrite == 0) {
            logtemplate = "";
        }
    }

    return logtemplate;
}

uint32_t ConfigFile::FetchFileChecksum() {
    local_locker lock(&config_locker);

    if (checksum == 0)
        CalculateChecksum();

    return checksum;
}

void ConfigFile::CalculateChecksum() {
    local_locker lock(&config_locker);

    std::string cks;

    for (auto x = config_map.begin(); x != config_map.end(); ++x) {
        cks += x->first;
        for (unsigned int y = 0; y < x->second.size(); y++) {
            cks += x->second[y].value;
        }
    }

    checksum = Adler32Checksum(cks.c_str(), cks.length());
}

HeaderValueConfig::HeaderValueConfig(const std::string& in_confline) {
    parseLine(in_confline);
}

HeaderValueConfig::HeaderValueConfig() {
}

void HeaderValueConfig::parseLine(const std::string& in_confline) {
    local_locker l(&mutex);

    auto cpos = in_confline.find(":");

    content_map.clear();

    if (cpos == std::string::npos) {
        header = in_confline;
    } else {
        header = in_confline.substr(0, cpos);
        std::vector<opt_pair> opt_vec;
        StringToOpts(in_confline.substr(cpos + 1, in_confline.size() - cpos), ",", &opt_vec);

        for (auto oi : opt_vec)
            content_map[oi.opt] = oi.val;
    }
}

std::string HeaderValueConfig::getHeader() {
    local_locker l(&mutex);
    return header;
}

void HeaderValueConfig::setHeader(const std::string& in_str) {
    local_locker l(&mutex);
    header = in_str;
}

bool HeaderValueConfig::hasKey(const std::string& in_str) {
    local_locker l(&mutex);
    return (content_map.find(in_str) != content_map.end());
}

std::string HeaderValueConfig::getValue(const std::string& in_str) {
    local_locker l(&mutex);
    
    auto vi = content_map.find(in_str);

    if (vi == content_map.end())
        throw std::runtime_error(fmt::format("no such key in content map: {}", in_str));

    return vi->second;
}

std::string HeaderValueConfig::getValue(const std::string& in_str, const std::string& in_defl) {
    local_locker l(&mutex);

    auto vi = content_map.find(in_str);

    if (vi == content_map.end())
        return in_defl;

    return vi->second;
}

void HeaderValueConfig::eraseKey(const std::string& in_key) {
    local_locker l(&mutex);

    auto vi = content_map.find(in_key);

    if (vi == content_map.end())
        return;

    content_map.erase(vi);
}

std::string HeaderValueConfig::toString() {
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

std::ostream& operator<<(std::ostream& os, const HeaderValueConfig& h) {
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

std::istream& operator>>(std::istream& is, HeaderValueConfig& h) {
    std::string sline;
    std::getline(is, sline);
    h.parseLine(sline);
    return is;
}

