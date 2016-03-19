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

#include "util.h"

#include "configfile.h"
#include "messagebus.h"

ConfigFile::ConfigFile(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;
    checksum = 0;

    pthread_mutex_init(&config_locker, NULL);
}

ConfigFile::~ConfigFile() {
    pthread_mutex_destroy(&config_locker);
}

int ConfigFile::ParseConfig(const char *in_fname) {
    local_locker lock(&config_locker);
    return ParseConfig_nl(in_fname);
}

int ConfigFile::ParseConfig_nl(const char *in_fname) {
    // We don't lock
    
    FILE *configf;
    char confline[8192];

    char errbuf[1024];
    char *errstr;
    stringstream sstream;

    if ((configf = fopen(in_fname, "r")) == NULL) {
        errstr = strerror_r(errno, errbuf, 1024);
        sstream << "Error reading config file '" << in_fname << "': " << errstr;
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
        string parsestr = StrStrip(confline);
        string directive, value;

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

            // Handling including files
            if (directive == "include") {
                value = ExpandLogPath_nl(value, "", "", 0, 1);

                sstream << "Including sub-config file: " << value;
                _MSG(sstream.str(), MSGFLAG_INFO);
                sstream.str("");

                if (ParseConfig_nl(value.c_str()) < 0) {
                    fclose(configf);
                    return -1;
                }
            } else {
                config_entity e(value, in_fname);
                config_map[StrLower(directive)].push_back(e);
                config_map_dirty[StrLower(directive)] = 1;
            }
        }
    }

    fclose(configf);

    return 1;
}

int ConfigFile::SaveConfig(const char *in_fname) {
    local_locker lock(&config_locker);

    char errbuf[1024];
    char *errstr;
    stringstream sstream;

	FILE *wf = NULL;

	if ((wf = fopen(in_fname, "w")) == NULL) {
        errstr = strerror_r(errno, errbuf, 1024);
        sstream << "Error writing config file '" << in_fname << "': " << errstr;
        _MSG(sstream.str(), MSGFLAG_ERROR);
		return -1;
	}

	for (map<string, vector<config_entity> >::iterator x = config_map.begin();
		 x != config_map.end(); ++x) {
		for (unsigned int y = 0; y < x->second.size(); y++) {
			fprintf(wf, "%s=%s\n", x->first.c_str(), x->second[y].value.c_str());
		}
	}

	fclose(wf);
	return 1;
}

string ConfigFile::FetchOpt(string in_key) {
    local_locker lock(&config_locker);

    map<string, vector<config_entity> >::iterator cmitr = 
        config_map.find(StrLower(in_key));
    // No such key
    if (cmitr == config_map.end())
        return "";

    // Get a single key if we can
    if (cmitr->second.size() == 0)
        return "";

    string val = cmitr->second[0].value;

    return val;
}

vector<string> ConfigFile::FetchOptVec(string in_key) {
    local_locker lock(&config_locker);

    // Empty vec to return
    vector<string> eretvec;

    map<string, vector<config_entity> >::iterator cmitr = 
        config_map.find(StrLower(in_key));
    // No such key
    if (cmitr == config_map.end())
        return eretvec;

    for (unsigned int i = 0; i < cmitr->second.size(); i++) {
        eretvec.push_back(cmitr->second[i].value);
    }

    return eretvec;
}

int ConfigFile::FetchOptBoolean(string in_key, int dvalue) {
    // Don't lock, we're locked in fetchopt
    // local_locker lock(&config_locker);

	string v = StrLower(FetchOpt(in_key));
	int r;

	r = StringToBool(v);

	if (r == -1)
		return dvalue;

	return r;
}

int ConfigFile::FetchOptInt(string in_key, int dvalue) {
    // Don't lock, we're locked in fetchopt
    // local_locker lock(&config_locker);

	string v = StrLower(FetchOpt(in_key));
	int r;

    try {
        r = StringToInt(v);
    } catch (const std::runtime_error e) {
        return dvalue;
    }

	return r;
}

unsigned int ConfigFile::FetchOptUInt(string in_key, unsigned int dvalue) {
    // Don't lock, we're locked in fetchopt
    // local_locker lock(&config_locker);

	string v = StrLower(FetchOpt(in_key));
	unsigned int r;

    try {
        r = StringToUInt(v);
    } catch (const std::runtime_error e) {
        return dvalue;
    }

	return r;
}

int ConfigFile::FetchOptDirty(string in_key) {
    local_locker lock(&config_locker);

	if (config_map_dirty.find(StrLower(in_key)) == config_map_dirty.end())
		return 0;

	return config_map_dirty[StrLower(in_key)];
}

void ConfigFile::SetOptDirty(string in_key, int in_dirty) {
    local_locker lock(&config_locker);

	config_map_dirty[StrLower(in_key)] = in_dirty;
}

void ConfigFile::SetOpt(string in_key, string in_val, int in_dirty) {
    local_locker lock(&config_locker);

    vector<config_entity> v;
    config_entity e(in_val, "::dynamic::");
	config_map[StrLower(in_key)] = v;
	SetOptDirty(in_key, in_dirty);
}

void ConfigFile::SetOptVec(string in_key, vector<string> in_val, int in_dirty) {
    local_locker lock(&config_locker);

    vector<config_entity> cev;
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
string ConfigFile::ExpandLogPath(string path, string logname, string type,
        int start, int overwrite) {
    local_locker lock(&config_locker);

    return ExpandLogPath_nl(path, logname, type, start, overwrite);
}

string ConfigFile::ExpandLogPath_nl(string path, string logname, string type,
        int start, int overwrite) {
    // We don't lock

    string logtemplate;
    int inc = 0;
	int incpad = 0;

    logtemplate = path;

    for (unsigned int nl = logtemplate.find("%"); nl < logtemplate.length();
         nl = logtemplate.find("%", nl))
    {
        char op = logtemplate[nl+1];
        logtemplate.erase(nl, 2);
        if (op == 'n')
            logtemplate.insert(nl, logname);
        else if (op == 'd') {
            time_t tnow;
            struct tm *now;

            // tnow = time(0);
			tnow = globalreg->start_time;
            now = localtime(&tnow);

            char datestr[24];
            strftime(datestr, 24, "%b-%d-%Y", now);

            logtemplate.insert(nl, datestr);
        }
        else if (op == 'D') {
            time_t tnow;
            struct tm *now;

            // tnow = time(0);
			tnow = globalreg->start_time;
            now = localtime(&tnow);

            char datestr[24];
            strftime(datestr, 24, "%Y%m%d", now);

            logtemplate.insert(nl, datestr);
        } else if (op == 't') {
            time_t tnow;
            struct tm *now;

            // tnow = time(0);
			tnow = globalreg->start_time;
            now = localtime(&tnow);

            char timestr[12];
            strftime(timestr, 12, "%H-%M-%S", now);

            logtemplate.insert(nl, timestr);
        } else if (op == 'T') {
            time_t tnow;
            struct tm *now;

            // tnow = time(0);
			tnow = globalreg->start_time;
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
			if (globalreg->homepath == "") {
				struct passwd *pw;

				pw = getpwuid(getuid());

				if (pw == NULL) {
					fprintf(stderr, "ERROR:  Could not explode home directory path, "
							"getpwuid() failed.\n");
					exit(1);
				}

				logtemplate.insert(nl, pw->pw_dir);
			} else {
				logtemplate.insert(nl, globalreg->homepath);
			}
        } else if (op == 'p') {
			string pfx = globalreg->log_prefix;

			if (pfx == "") 
				pfx = FetchOpt("logprefix");

			if (pfx != "")
				pfx += "/";

			logtemplate.insert(nl, pfx);
		} else if (op == 'S') {
            logtemplate.insert(nl, DATA_LOC);
        } else if (op == 'E') {
            logtemplate.insert(nl, SYSCONF_LOC);
        }
    }

    // If we've got an incremental, go back and find it and start testing
    if (inc) {
        int found = 0;

        if (start == 0) {
            // If we don't have a number we want to use, find the next free
            for (int num = 1; num < 10000; num++) {
				string copied;
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
            string copied;
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

    // Close the pwent
    endpwent();

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

	string cks;

	for (map<string, vector<config_entity> >::iterator x = config_map.begin();
		 x != config_map.end(); ++x) {
		cks += x->first;
		for (unsigned int y = 0; y < x->second.size(); y++) {
			cks += x->second[y].value;
		}
	}

	checksum = Adler32Checksum(cks.c_str(), cks.length());
}

