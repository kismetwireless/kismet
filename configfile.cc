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
        fgets(confline, 8192, configf);

        if (feof(configf)) break;

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
                fprintf(stderr, "ERROR: Illegal config option: %s\n", parsestr.c_str());
                continue;
            }

            // Handling including files
            if (directive == "include") {
                printf("Including sub-config file: %s\n", value.c_str());

                if (ParseConfig(value.c_str()) < 0)
                    return -1;
            } else {
                config_map[StrLower(directive)].push_back(value);
            }
        }
    }

    fclose(configf);

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

// Expand a logfile into a full filename
// Path/template from config
// Logfile name to use
// Logfile type to use
// Starting number or desired number
string ConfigFile::ExpandLogPath(string path, string logname, string type,
                                 int start, int overwrite) {
    string logtemplate;
    int inc = 0;

    logtemplate = path;

    for (unsigned int nl = logtemplate.find("%"); nl < logtemplate.length();
         nl = logtemplate.find("%", nl+1))
    {
        char op = logtemplate[nl+1];
        logtemplate.erase(nl, 2);
        if (op == 'n')
            logtemplate.insert(nl, logname);
        else if (op == 'd') {
            time_t tnow;
            struct tm *now;

            tnow = time(0);
            now = localtime(&tnow);

            char datestr[24];
            strftime(datestr, 24, "%b-%d-%Y", now);

            logtemplate.insert(nl, datestr);
        }
        else if (op == 't') {
            time_t tnow;
            struct tm *now;

            tnow = time(0);
            now = localtime(&tnow);

            char timestr[12];
            strftime(timestr, 12, "%H-%M-%S", now);

            logtemplate.insert(nl, timestr);
        }
        else if (op == 'l')
            logtemplate.insert(nl, type.c_str());
        else if (op == 'i')
            inc = nl;
        else if (op == 'h') {
            struct passwd *pw;

            pw = getpwuid(getuid());

            if (pw == NULL) {
                fprintf(stderr, "ERROR:  Could not explode home directory path, getpwuid() failed.\n");
                exit(1);
            }

            logtemplate.insert(nl, pw->pw_dir);
        }
    }

    // If we've got an incremental, go back and find it and start testing
    if (inc) {
        int found = 0;

        if (start == 0) {
            // If we don't have a number we want to use, find the next free

            // This is almost solely for the use of the packetlimit logger

            for (int num = 1; num < 100; num++) {
                string copied = logtemplate;
                struct stat filstat;

                // This is annoying
                char numstr[5];
                snprintf(numstr, 5, "%d", num);

                copied.insert(inc, numstr);

                if (stat(copied.c_str(), &filstat) == -1) {
                    found = 1;
                    logtemplate = copied;
                    break;
                }
            }
        } else {
            // Otherwise find out if this incremental is taken
            string copied = logtemplate;
            struct stat filstat;
            char numstr[5];
            snprintf(numstr, 5, "%d", start);

            copied.insert(inc, numstr);

            if (stat(copied.c_str(), &filstat) != -1 && overwrite == 0) {
                logtemplate = "";
            } else {
                logtemplate = copied;
            }

            found = 1;
        }


        if (!found) {
            fprintf(stderr, "ERROR:  Unable to find a logging file within 100 hits.  If you really are\n"
                    "        logging this many times in 1 day, change log names or edit the \n"
                    "        source.\n");
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

int ConfigFile::ParseFilterLine(string filter_str, map<mac_addr, int> *bssid_map,
                                map<mac_addr, int> *source_map,
                                map<mac_addr, int> *dest_map,
                                int *bssid_invert, int *source_invert, int *dest_invert) {
    // Break it into filter terms
    unsigned int parse_pos = 0;
    unsigned int parse_error = 0;

    while (parse_pos < filter_str.length()) {
        unsigned int addr_term_end;
        unsigned int address_target = 0; // 1=bssid 2=source 4=dest 7=any

        if (filter_str[parse_pos] == ',' || filter_str[parse_pos] == ' ') {
            parse_pos++;
            continue;
        }

        if ((addr_term_end = filter_str.find('(', parse_pos + 1)) == string::npos) {
            fprintf(stderr, "FATAL:  Couldn't parse filter line, no '(' found.\n");
            parse_error = 1;
            break;
        }

        string addr_term = StrLower(filter_str.substr(parse_pos, addr_term_end - parse_pos));

        parse_pos = addr_term_end + 1;

        if (addr_term.length() == 0) {
            fprintf(stderr, "FATAL: Couldn't parse filter line, no address type given.\n");
            parse_error = 1;
            break;
        }

        if (addr_term == "any") {
            address_target = 7;
        } else if (addr_term == "bssid") {
            address_target = 1;
        } else if (addr_term == "source") {
            address_target = 2;
        } else if (addr_term == "dest") {
            address_target = 4;
        } else {
            fprintf(stderr, "FATAL:  Couldn't parse filter line, unknown address type '%s'\n",
                    addr_term.c_str());
            parse_error = 1;
            break;
        }

        if ((addr_term_end = filter_str.find(')', parse_pos + 1)) == string::npos) {
            fprintf(stderr, "FATAL: Couldn't parse filter line, no ')' found.\n");
            parse_error = 1;
            break;
        }

        string term_contents = filter_str.substr(parse_pos, addr_term_end - parse_pos);

        parse_pos = addr_term_end + 1;

        if (term_contents.length() == 0) {
            fprintf(stderr, "FATAL: Couldn't parse filter line, no addresses listed.\n");
            parse_error = 1;
            break;
        }

        unsigned int term_parse_pos = 0;
        while (term_parse_pos < term_contents.length()) {
            unsigned int term_end;
            unsigned int invert = 0;

            if (term_contents[term_parse_pos] == ' ' || term_contents[term_parse_pos] == ',') {
                term_parse_pos++;
                continue;
            }

            if (term_contents[term_parse_pos] == '!') {
                invert = 1;
                term_parse_pos++;
            }

            if ((term_end = term_contents.find(',', term_parse_pos + 1)) == string::npos)
                term_end = term_contents.length();

            string single_addr = term_contents.substr(term_parse_pos, term_end - term_parse_pos);

            mac_addr mac = single_addr.c_str();
            if (mac.error != 0) {
                fprintf(stderr, "FATAL:  Couldn't parse filter MAC address '%s'\n",
                        single_addr.c_str());
                parse_error = 1;
                break;
            }

            // Catch non-inverted 'ANY'
            if (address_target == 7 && invert == 0) {
                fprintf(stderr, "FATAL:  Filtering type 'ANY' with a standard address will discard all packets.  'ANY' can only be used with inverted matches.\n");
                parse_error = 1;
                break;
            }

            // Insert it into the map, we'll look later to see if it's an inversion collision
            if (address_target & 0x01)
                (*bssid_map)[mac] = invert;
            if (address_target & 0x02)
                (*source_map)[mac] = invert;
            if (address_target & 0x04)
                (*dest_map)[mac] = invert;

            term_parse_pos = term_end + 1;

        }

    }

    if (parse_error == 1)
        return -1;

    int inversion_tracker;
    map<mac_addr, int>::iterator x;

    for (inversion_tracker = -1, x = bssid_map->begin(); x != bssid_map->end(); ++x) {

        if (inversion_tracker == -1) {
            inversion_tracker = x->second;
            continue;
        }

        if (x->second != inversion_tracker) {
            fprintf(stderr, "FATAL:  BSSID filter has an illegal mix of normal and inverted addresses.  All addresses must be inverted or standard.\n");
            return -1;
        }
    }
    *bssid_invert = inversion_tracker;

    for (inversion_tracker = -1, x = source_map->begin(); x != source_map->end(); ++x) {

        if (inversion_tracker == -1) {
            inversion_tracker = x->second;
            continue;
        }

        if (x->second != inversion_tracker) {
            fprintf(stderr, "FATAL:  Source filter has an illegal mix of normal and inverted addresses.  All addresses must be inverted or standard.\n");
            return -1;
        }
    }
    *source_invert = inversion_tracker;

    for (inversion_tracker = -1, x = dest_map->begin(); x != dest_map->end(); ++x) {

        if (inversion_tracker == -1) {
            inversion_tracker = x->second;
            continue;
        }

        if (x->second != inversion_tracker) {
            fprintf(stderr, "FATAL:  Destination filter has an illegal mix of normal and inverted addresses.  All addresses must be inverted or standard.\n");
            return -1;
        }
    }
    *dest_invert = inversion_tracker;

    return 1;
}

