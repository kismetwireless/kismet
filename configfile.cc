#include "config.h"

#include <string>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "configfile.h"

// Munge input to shell-safe
void MungeToShell(char *in_data, int max) {
    for (int i = 0; i < max; i++) {
        // space
        if (in_data[i] == 32)
            continue;

        // " to :
        if (in_data[i] >= 34 && in_data[i] <= 58)
            continue;

        // =
        if (in_data[i] == 61)
            continue;

        if (in_data[i] >= 63 && in_data[i] <= 90)
            continue;

        if (in_data[i] == 95)
            continue;

        if (in_data[i] >= 97 && in_data[i] <= 122)
            continue;

        if (in_data[i] == 126)
            continue;

        in_data[i] = '\0';
        break;
    }
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

            config_map[StrLower(directive)] = value;
        }
    }

    return 1;
}

string ConfigFile::FetchOpt(string in_key) {
    // No such key
    if (config_map.find(StrLower(in_key)) == config_map.end())
        return "";

    // Get key
    string val = config_map[StrLower(in_key)];
    // Catch single-element stuff "DisableWEP" or whatever
    if (val == "")
        val = "true";

    return val;
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
                struct stat fstat;

                // This is annoying
                char numstr[5];
                snprintf(numstr, 5, "%d", num);

                copied.insert(inc, numstr);

                if (stat(copied.c_str(), &fstat) == -1) {
                    found = 1;
                    logtemplate = copied;
                    break;
                }
            }
        } else {
            // Otherwise find out if this incremental is taken
            string copied = logtemplate;
            struct stat fstat;
            char numstr[5];
            snprintf(numstr, 5, "%d", start);

            copied.insert(inc, numstr);

            if (stat(copied.c_str(), &fstat) != -1 && overwrite == 0) {
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
        struct stat fstat;

        if (stat(logtemplate.c_str(), &fstat) != -1 && overwrite == 0) {
            logtemplate = "";
        }
    }

    return logtemplate;
}

