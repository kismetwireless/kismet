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

// Munge input to shell-safe
void MungeToShell(char *in_data, int max) {
    int i, j;

    for (i = 0, j = 0; i < max, j < max; i++) {
        if (in_data[i] == '\0')
            break;

        if (isalnum(in_data[i]) || isspace(in_data[i]) ||
            in_data[i] == '=' || in_data[i] == '-' || in_data[i] == '_' ||
            in_data[i] == '.' || in_data[i] == ',') {

            if (j == i) {
                j++;
            } else {
                in_data[j++] = in_data[i];
            }
        }
    }

    in_data[j] = '\0';

}

// Quick wrapper to save us time in other code
string MungeToShell(string in_data) {
    char *data = new char[in_data.length() + 1];
    string ret;

    snprintf(data, in_data.length() + 1, "%s", in_data.c_str());

    MungeToShell(data, in_data.length() + 1);

    ret = data;
    delete[] data;
    return ret;
}

string StrLower(string in_str) {
    string thestr = in_str;
    for (unsigned int i = 0; i < thestr.length(); i++)
        thestr[i] = tolower(thestr[i]);

    return thestr;

}

string StrStrip(string in_str) {
    string temp;
    unsigned int start, end;

    start = 0;
    end = in_str.length();

    if (in_str[0] == '\n')
        return "";

    for (unsigned int x = 0; x < in_str.length(); x++) {
        if (in_str[x] != ' ' && in_str[x] != '\t') {
            start = x;
            break;
        }
    }
    for (unsigned int x = in_str.length() - 1; x > 0; x--) {
        if (in_str[x] != ' ' && in_str[x] != '\t' && in_str[x] != '\n') {
            end = x;
            break;
        }
    }

    return in_str.substr(start, end-start+1);

}

int XtoI(char x) {
    if (isxdigit(x)) {
        if (x <= '9')
            return x - '0';
        return toupper(x) - 'A' + 10;
    }

    return -1;
}

int Hex2UChar13(unsigned char *in_hex, unsigned char *in_chr) {
    memset(in_chr, 0, sizeof(unsigned char) * WEPKEY_MAX);
    int chrpos = 0;

    for (unsigned int strpos = 0; strpos < WEPKEYSTR_MAX && chrpos < WEPKEY_MAX; strpos++) {
        if (in_hex[strpos] == 0)
            break;

        if (in_hex[strpos] == ':')
            strpos++;

        // Assume we're going to eat the pair here
        if (isxdigit(in_hex[strpos])) {
            if (strpos > (WEPKEYSTR_MAX - 2))
                return 0;

            int d1, d2;
            if ((d1 = XtoI(in_hex[strpos++])) == -1)
                return 0;
            if ((d2 = XtoI(in_hex[strpos])) == -1)
                return 0;

            in_chr[chrpos++] = (d1 * 16) + d2;
        }

    }

    return(chrpos);
}


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

            config_map[StrLower(directive)].push_back(value);
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

