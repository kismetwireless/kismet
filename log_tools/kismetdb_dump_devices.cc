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

#include <map>
#include <iomanip>
#include <ctime>
#include <iostream>

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sqlite3.h>

#include "getopt.h"

#include "fmt.h"
#include "nlohmann/json.hpp"
#include "sqlite3_cpp11.h"

void print_help(char *argv) {
    printf("Kismetdb to JSON\n");
    printf("A simple tool for converting the device data from a KismetDB log file to\n"
           "a JSON log.\n");
    printf("usage: %s [OPTION]\n", argv);
    printf(" -i, --in [filename]          Input kismetdb file\n"
           " -o, --out [filename]         Output device data into JSON file\n"
           " -f, --force                  Force writing to the target file, even if it exists.\n"
           " -j, --json-path              Rewrite fields to use '_' instead of '.'\n"
           " -e, --ekjson                 Write as ekjson records, one device per line, instead of as\n"
           "                              a complete JSON array.\n"
           " -v, --verbose                Verbose output\n"
           " -s, --skip-clean             Don't clean (sql vacuum) input database\n");
}

std::string multi_replace_all(const std::string& in, const std::string& match, const std::string& repl) {
    std::string work = in;

    for (size_t pos = 0; (pos = in.find(match, pos)) != std::string::npos;
            pos += repl.length()) {
        work.replace(pos, match.length(), repl);
    }

    return work;
}

nlohmann::json transform_json(const nlohmann::json &json) {
    nlohmann::json ret;

    try {
        if (json.is_object()) {
            for (auto k : json.items()) {
                auto repl = multi_replace_all(k.key(), ".", "_");

                ret[repl] = transform_json(k.value());
            }

            return ret;
        } 

        if (json.is_array()) {
            for (auto v : json)
                ret.push_back(transform_json(v));
            return ret;
        }

        return json;
    } catch (...) {
        return json;
    }
}

int main(int argc, char *argv[]) {
    static struct option longopt[] = {
        { "in", required_argument, 0, 'i' },
        { "out", required_argument, 0, 'o' },
        { "verbose", no_argument, 0, 'v' },
        { "force", no_argument, 0, 'f' },
        { "help", no_argument, 0, 'h' },
        { "skip-clean", no_argument, 0, 's' },
        { "ekjson", no_argument, 0, 'e' },
        { "json-path", no_argument, 0, 'j' },
        { 0, 0, 0, 0 }
    };

    int option_idx = 0;
    optind = 0;
    opterr = 0;

    std::string in_fname, out_fname;
    bool verbose = false;
    bool force = false;
    bool skipclean = false;
    bool ekjson = false;
    bool reformat = false;

    int sql_r = 0;
    char *sql_errmsg = NULL;
    sqlite3 *db = NULL;

    FILE *ofile = NULL;

    struct stat statbuf;

    while (1) {
        int r = getopt_long(argc, argv, 
                            "-hi:o:vfsej", 
                            longopt, &option_idx);
        if (r < 0) break;

        if (r == 'h') {
            print_help(argv[0]);
            exit(1);
        } else if (r == 'i') {
            in_fname = std::string(optarg);
        } else if (r == 'o') {
            out_fname = strdup(optarg);
        } else if (r == 'v') { 
            verbose = true;
        } else if (r == 'f') {
            force = true;
        } else if (r == 's') {
            skipclean = true;
        } else if (r == 'e') {
            ekjson = true;
            reformat = true;
        } else if (r == 'j') {
            reformat = true;
        }
    }

    if (out_fname == "" || in_fname == "") {
        fprintf(stderr, "ERROR: Expected --in [kismetdb file] and "
                "--out [JSON file]\n");
        exit(1);
    }

    if (stat(in_fname.c_str(), &statbuf) < 0) {
        if (errno == ENOENT) 
            fprintf(stderr, "ERROR:  Input file '%s' does not exist.\n", in_fname.c_str());
        else
            fprintf(stderr, "ERROR:  Unexpected problem checking input "
                    "file '%s': %s\n", in_fname.c_str(), strerror(errno));

        exit(1);
    }

    if (out_fname != "-") {
        if (stat(out_fname.c_str(), &statbuf) < 0) {
            if (errno != ENOENT) {
                fprintf(stderr, "ERROR:  Unexpected problem checking output "
                        "file '%s': %s\n", out_fname.c_str(), strerror(errno));
                exit(1);
            }
        } else if (force == false) {
            fprintf(stderr, "ERROR:  Output file '%s' exists already; use --force to "
                    "clobber the file.\n", out_fname.c_str());
            exit(1);
        }
    }

    /* Open the database and run the vacuum command to clean up any stray journals */
    if (!skipclean)
        sql_r = sqlite3_open(in_fname.c_str(), &db);
    else
        sql_r = sqlite3_open_v2(in_fname.c_str(), &db, SQLITE_OPEN_READONLY, nullptr);

    if (sql_r) {
        fprintf(stderr, "ERROR:  Unable to open '%s': %s\n",
                in_fname.c_str(), sqlite3_errmsg(db));
        exit(1);
    }

    if (!skipclean) {
        if (verbose)
            fprintf(stderr, "* Preparing input database '%s'...\n", in_fname.c_str());


        sql_r = sqlite3_exec(db, "VACUUM;", NULL, NULL, &sql_errmsg);

        if (sql_r != SQLITE_OK) {
            fprintf(stderr, "ERROR:  Unable to clean up (vacuum) database before copying: %s\n",
                    sql_errmsg);
            sqlite3_close(db);
            exit(1);
        }
    }

    // Use our sql adapters

    using namespace kissqlite3;

    int db_version = 0;
    unsigned long n_devices_db = 0L;

    try {
        // Get the version
        auto version_query = _SELECT(db, "KISMET", {"db_version"});
        auto version_ret = version_query.begin();
        if (version_ret == version_query.end()) {
            fprintf(stderr, "ERROR:  Unable to fetch database version.\n");
            sqlite3_close(db);
            exit(1);
        }
        db_version = sqlite3_column_as<int>(*version_ret, 0);

        auto ndevices_q = _SELECT(db, "devices", {"count(*)"});
        auto ndevices_ret = ndevices_q.begin();
        if (ndevices_ret == ndevices_q.end()) {
            fprintf(stderr, "ERROR:  Unable to fetch device count.\n");
            sqlite3_close(db);
            exit(1);
        }
        n_devices_db = sqlite3_column_as<unsigned long>(*ndevices_ret, 0);

        if (verbose)
            fprintf(stderr, "* Found KismetDB version %d %lu devices\n", db_version, n_devices_db);

    } catch (const std::exception& e) {
        fprintf(stderr, "ERROR:  Could not get database information from '%s': %s\n",
                in_fname.c_str(), e.what());
        exit(0);
    }

    if (out_fname == "-") {
        ofile = stdout;
    } else {
        ofile = fopen(out_fname.c_str(), "w");
        if (ofile == NULL) {
            fprintf(stderr, "ERROR:  Unable to open output file for writing: %s\n",
                    strerror(errno));
            exit(1);
        }
    }

    // JSON array
    if (!ekjson)
        fprintf(ofile, "[\n");

    auto query = _SELECT(db, "devices", {"device"});

    unsigned long n_logs = 0;
    unsigned long n_division = (n_devices_db / 20);

    if (n_division <= 0)
        n_division = 1;

    bool newline = false;

    for (auto d : query) {
        n_logs++;

        if (n_logs % n_division == 0 && verbose) {
            fprintf(stderr, "* %d%% Processed %lu devices of %lu\n",
                    (int) (((float) n_logs / (float) n_devices_db) * 100) + 1, 
                    n_logs, n_devices_db);

        }

        auto json = sqlite3_column_as<std::string>(d, 0);

        try {
            std::stringstream ss(json);

            nlohmann::json parsed_json;

            ss >> parsed_json;

            if (reformat)
                parsed_json = transform_json(parsed_json);

            if (newline) {
                if (!ekjson) {
                    fprintf(ofile, ",\n");
                } else {
                    fprintf(ofile, "\n");
                }
            }
            newline = true;

            ss.str("");
            ss << parsed_json;

            fmt::print(ofile, "{}", ss.str());
        } catch (const std::exception& e) {
            fmt::print(stderr, "ERROR:  Could not process device JSON: {}", e.what());
            continue;
        }
    }

    if (!ekjson)
        fprintf(ofile, "]\n");

    if (ofile != stdout)
        fclose(ofile);
    sqlite3_close(db);

    if (verbose)  {
        fprintf(stderr, "* Processed %lu devices\n", n_logs);
        fprintf(stderr, "* Done!\n");
    }

    return 0;
}

