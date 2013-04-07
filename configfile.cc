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
#include "configfile.h"
#include "util.h"

int ConfigFile::ParseConfig(const char *in_fname) {
    FILE *configf;
    char confline[8192];

    if ((configf = fopen(in_fname, "r")) == NULL) {
        fprintf(stderr, "ERROR: Reading config file '%s': %d (%s)\n", in_fname,
                errno, strerror(errno));
        return -1;
    }

    while (!feof(configf)) {
        if (fgets(confline, 8192, configf) == NULL || feof(configf)) 
			break;

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
                fprintf(stderr, "ERROR: Illegal config option: %s\n", 
						parsestr.c_str());
                continue;
            }

            // Handling including files
            if (directive == "include") {
                printf("Including sub-config file: %s\n", value.c_str());

                if (ParseConfig(value.c_str()) < 0) {
                    fclose(configf);
                    return -1;
                }
            } else {
                config_map[StrLower(directive)].push_back(value);
                config_map_dirty[StrLower(directive)] = 1;
            }
        }
    }

    fclose(configf);

    return 1;
}

int ConfigFile::SaveConfig(const char *in_fname) {
	FILE *wf = NULL;

	if ((wf = fopen(in_fname, "w")) == NULL) {
		return -1;
	}

	for (map<string, vector<string> >::iterator x = config_map.begin();
		 x != config_map.end(); ++x) {
		for (unsigned int y = 0; y < x->second.size(); y++) {
			fprintf(wf, "%s=%s\n", x->first.c_str(), x->second[y].c_str());
		}
	}

	fclose(wf);
	return 1;
}

string ConfigFile::FetchOpt(string in_key) {
    map<string, vector<string> >::iterator cmitr = config_map.find(StrLower(in_key));
    // No such key
    if (cmitr == config_map.end())
        return "";

    // Get a single key if we can
    if (cmitr->second.size() == 0)
        return "";

    string val = cmitr->second[0];

    return val;
}

vector<string> ConfigFile::FetchOptVec(string in_key) {
    // Empty vec to return
    vector<string> eretvec;

    map<string, vector<string> >::iterator cmitr = config_map.find(StrLower(in_key));
    // No such key
    if (cmitr == config_map.end())
        return eretvec;

    return cmitr->second;
}

int ConfigFile::FetchOptBoolean(string in_key, int dvalue) {
	string v = StrLower(FetchOpt(in_key));
	int r;

	r = StringToBool(v);

	if (r == -1)
		return dvalue;

	return r;
}

int ConfigFile::FetchOptDirty(string in_key) {
	if (config_map_dirty.find(StrLower(in_key)) == config_map_dirty.end())
		return 0;

	return config_map_dirty[StrLower(in_key)];
}

void ConfigFile::SetOptDirty(string in_key, int in_dirty) {
	config_map_dirty[StrLower(in_key)] = in_dirty;
}

void ConfigFile::SetOpt(string in_key, string in_val, int in_dirty) {
	vector<string> v;
	v.push_back(in_val);
	config_map[StrLower(in_key)] = v;
	SetOptDirty(in_key, in_dirty);
}

void ConfigFile::SetOptVec(string in_key, vector<string> in_val, int in_dirty) {
	config_map[StrLower(in_key)] = in_val;
	SetOptDirty(in_key, in_dirty);
}


// Expand a logfile into a full filename
// Path/template from config
// Logfile name to use
// Logfile type to use
// Starting number or desired number
string ConfigFile::ExpandLogPath(string path, string logname, string type,
                                 int start, int overwrite) {
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
	if (checksum == 0)
		CalculateChecksum();

	return checksum;
}

void ConfigFile::CalculateChecksum() {
	string cks;

	for (map<string, vector<string> >::iterator x = config_map.begin();
		 x != config_map.end(); ++x) {
		cks += x->first;
		for (unsigned int y = 0; y < x->second.size(); y++) {
			cks += x->second[y];
		}
	}

	checksum = Adler32Checksum(cks.c_str(), cks.length());
}

int GroupConfigFile::ParseConfig(const char *in_fname) {
	FILE *configf;
	char confline[8192];

	if ((configf = fopen(in_fname, "r")) == NULL) {
		fprintf(stderr, "ERROR:  Reading grouped config file '%s': %s\n", in_fname,
				strerror(errno));
		return -1;
	}

	root = new GroupEntity;
	root->name = ":root:";

	vector<GroupEntity *> group_stack;
	group_stack.push_back(root);

	vector<GroupEntity *> primervec;

	parsed_group_map[root] = primervec;

	GroupEntity *sub = root;

	while (!feof(configf)) {
		if (fgets(confline, 8192, configf) == NULL)
			break;

		if (feof(configf)) break;

		string parsestr = StrStrip(confline);
		string directive, value;

		if (parsestr.length() == 0)
			continue;
		if (parsestr[0] == '#')
			continue;

		size_t eq;
		if ((eq = parsestr.find("=")) == string::npos) {
			// Look for a "foo {".  { must be the end
			if (parsestr[parsestr.length() - 1] == '{') {
				directive = StrStrip(parsestr.substr(0, parsestr.length() - 1));

				GroupEntity *newent = new GroupEntity;
				parsed_group_map[sub].push_back(newent);

				sub = newent;
				sub->name = directive;
				parsed_group_map[sub] = primervec;
				group_stack.push_back(sub);

				continue;
			}

			// Look for an ending }.  Must be the first character, everything after
			// it is ignored
			if (parsestr[0] == '}') {
				if (sub == root) {
					fprintf(stderr, "ERROR:  Unexpected closing '}'\n");
          fclose(configf);
					return -1;
				}

				group_stack.pop_back();
				sub = group_stack.back();

				continue;
			}
		} else {
			// Process a directive
			directive = StrStrip(parsestr.substr(0, eq));
			value = StrStrip(parsestr.substr(eq + 1, parsestr.length()));

			if (value == "") {
				fprintf(stderr, "ERROR:  Illegal config option: '%s'\n",
						parsestr.c_str());
				continue;
			}

			if (directive == "include") {
				fprintf(stderr, "ERROR:  Can't include sub-files right now\n");
        fclose(configf);
				return -1;
			}

			sub->value_map[StrLower(directive)].push_back(value);
		}
	}

  fclose(configf);

	return 1;
}

string GroupConfigFile::FetchOpt(string in_key, GroupEntity *in_parent) {
	if (in_parent == NULL)
		in_parent = root;

    map<string, vector<string> >::iterator cmitr = 
		in_parent->value_map.find(StrLower(in_key));
    // No such key
    if (cmitr == in_parent->value_map.end())
        return "";

    // Get a single key if we can
    if (cmitr->second.size() == 0)
        return "";

    string val = cmitr->second[0];

    return val;
}

vector<string> GroupConfigFile::FetchOptVec(string in_key, GroupEntity *in_parent) {
    // Empty vec to return
    vector<string> eretvec;

	if (in_parent == NULL)
		in_parent = root;

    map<string, vector<string> >::iterator cmitr = 
		in_parent->value_map.find(StrLower(in_key));
    // No such key
    if (cmitr == in_parent->value_map.end())
        return eretvec;

    return cmitr->second;
}

vector<GroupConfigFile::GroupEntity *> GroupConfigFile::FetchEntityGroup(GroupEntity *in_parent) {
	map<GroupEntity *, vector<GroupEntity *> >::iterator itr;
	if (in_parent == NULL)
		itr = parsed_group_map.find(root);
	else
		itr = parsed_group_map.find(in_parent);

	if (itr == parsed_group_map.end()) {
		vector<GroupEntity *> ret;
		return ret;
	}

	return itr->second;
}

uint32_t GroupConfigFile::FetchFileChecksum() {
	if (checksum == 0)
		CalculateChecksum();

	return checksum;
}

void GroupConfigFile::CalculateChecksum() {
	string cks;

	map<GroupEntity *, vector<GroupEntity *> >::iterator x;
	for (x = parsed_group_map.begin(); x != parsed_group_map.end(); ++x) {
		for (unsigned int y = 0; y < x->second.size(); y++) {
			cks += x->second[y]->name;
			for (map<string, vector<string> >::iterator z = 
				 x->second[y]->value_map.begin(); z != x->second[y]->value_map.end();
				 ++z) {
				cks += z->first;
				for (unsigned int zz = 0; zz < z->second.size(); zz++) {
					cks += z->second[zz];
				}
			}
		}
	}

	checksum = Adler32Checksum(cks.c_str(), cks.length());
}


