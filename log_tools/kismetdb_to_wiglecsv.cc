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

/* 
 * Simple tool to clean up a kismetdb log file, duplicate it, and strip the packet
 * content, in preparation to uploading to a site like wigle.
 */

#include "config.h"

#include <map>

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

#include "json/json.h"
#include "sqlite3_cpp11.h"

void print_help(char *argv) {
    printf("Kismetdb to WigleCSV\n");
    printf("A simple tool for converting the packet data from a KismetDB log file to\n"
           "the CSV format used by Wigle\n");
    printf("Usage: %s [OPTION]\n", argv);
    printf(" -i, --in [filename]          Input kismetdb file\n"
           " -o, --out [filename]         Output Wigle CSV file\n"
           " -v, --verbose                Verbose output\n"
           " -f, --force                  Force writing to the target file, even if it exists.\n"
           " -s, --skip-clean             Don't clean (sql vacuum) input database\n");
}

int main(int argc, char *argv[]) {
    static struct option longopt[] = {
        { "in", required_argument, 0, 'i' },
        { "out", required_argument, 0, 'o' },
        { "verbose", no_argument, 0, 'b' },
        { "force", no_argument, 0, 'f' },
        { "help", no_argument, 0, 'h' },
        { "skip-clean", no_argument, 0, 's' },
        { "secret", no_argument, 0, 'k' }, // secret argument required to make it work
        { 0, 0, 0, 0 }
    };

    int option_idx = 0;
    optind = 0;
    opterr = 0;

    char *in_fname = NULL, *out_fname = NULL;
    bool verbose = false;
    bool force = false;
    bool skipclean = false;

    bool beta_ok_secret = false;

    int sql_r = 0;
    char *sql_errmsg = NULL;
    sqlite3 *db = NULL;

    FILE *ofile = NULL;

    struct stat statbuf;

    while (1) {
        int r = getopt_long(argc, argv, 
                            "-hi:o:vfsk", 
                            longopt, &option_idx);
        if (r < 0) break;

        if (r == 'h') {
            print_help(argv[0]);
            exit(1);
        } else if (r == 'i') {
            in_fname = strdup(optarg);
        } else if (r == 'o') {
            out_fname = strdup(optarg);
        } else if (r == 'v') { 
            verbose = true;
        } else if (r == 'f') {
            force = true;
        } else if (r == 's') {
            skipclean = true;
        } else if (r == 'k') {
            beta_ok_secret = true;
        }
    }

    if (!beta_ok_secret) {
        fprintf(stderr, "ERROR: This code doesn't work yet!  It will soon though.  Sorry!\n");
        exit(1);
    }

    if (out_fname == NULL || in_fname == NULL) {
        fprintf(stderr, "ERROR: Expected --in [kismetdb file] and "
                "--out [wigle CSV file]\n");
        exit(1);
    }

    /* Open the database and run the vacuum command to clean up any stray journals */

    if (stat(out_fname, &statbuf) < 0) {
        if (errno != ENOENT) {
            fprintf(stderr, "ERROR:  Unexpected problem checking output "
                    "file '%s': %s\n", out_fname, strerror(errno));
            exit(1);
        }
    } else if (force == false) {
        fprintf(stderr, "ERROR:  Output file '%s' exists already; use --force to "
                "clobber the file.\n", out_fname);
        exit(1);
    }

    sql_r = sqlite3_open(in_fname, &db);

    if (sql_r) {
        fprintf(stderr, "ERROR:  Unable to open '%s': %s\n",
                in_fname, sqlite3_errmsg(db));
        exit(1);
    }

    if (!skipclean) {
        if (verbose)
            printf("* Preparing input database '%s'...\n", in_fname);


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

    auto version_query = _SELECT(db, "KISMET", {"db_version"});
    auto version_ret = version_query.begin();

    if (version_ret == version_query.end()) {
        fprintf(stderr, "ERROR:  Unable to fetch database version.\n");
        sqlite3_close(db);
        exit(1);
    }

    // Get the version
    int db_version = sqlite3_column_as<int>(*version_ret, 0);

    if (verbose)
        printf("* Found KismetDB version %d\n", db_version);

    ofile = fopen(out_fname, "w");
    if (ofile == NULL) {
        fprintf(stderr, "ERROR:  Unable to open output file for writing: %s\n",
                strerror(errno));
        exit(1);
    }

    // Define a simple cache; we don't need to use a proper kismet macaddr here, just operate
    // on it as a string
    class cache_obj {
    public:
        cache_obj(uint64_t t, std::string s, std::string c) :
            first_time{t},
            ssid{s},
            crypto{c} { }

        uint64_t first_time;
        std::string ssid;
        std::string crypto;
    };

    std::map<std::string, cache_obj *> device_cache_map;

    std::list<std::string> packet_fields;

    if (db_version < 5) {
        packet_fields = std::list<std::string>{"sourcemac", "phyname", "lat", "lon", "signal", "frequency"};
    } else {
        packet_fields = std::list<std::string>{"sourcemac", "phyname", "lat", "lon", "signal", "frequency", "alt", "speed"};
    }

    auto query = _SELECT(db, "packets", packet_fields,
            _WHERE("sourcemac", NEQ, "00:00:00:00:00:00", 
                AND, 
                "lat", NEQ, 0,
                AND,
                "lon", NEQ, 0));


    for (auto p : query) {
        auto sourcemac = sqlite3_column_as<std::string>(p, 0);
        auto phy = sqlite3_column_as<std::string>(p, 1);

        auto lat = 0.0f, lon = 0.0f, alt = 0.0f, spd = 0.0f;

        if (db_version < 5) {
            lat = sqlite3_column_as<double>(p, 2) / 100000;
            lon = sqlite3_column_as<double>(p, 3) / 100000;
        } else {
            lat = sqlite3_column_as<double>(p, 2);
            lon = sqlite3_column_as<double>(p, 3);
            alt = sqlite3_column_as<double>(p, 6);
            spd = sqlite3_column_as<double>(p, 7);
        }

        auto ci = device_cache_map.find(sourcemac);
        cache_obj *cached = nullptr;

        if (ci != device_cache_map.end()) {
            cached = ci->second;
        } else {
            auto dev_query = _SELECT(db, "devices", {"device"},
                    _WHERE("devmac", EQ, sourcemac,
                        AND,
                        "phyname", EQ, phy));

            auto dev = dev_query.begin();

            if (dev == dev_query.end()) {
                printf("Could not find device record for %s\n", sqlite3_column_as<std::string>(p, 0).c_str());
                continue;
            }

            Json::Value json;
            std::stringstream ss(sqlite3_column_as<std::string>(*dev, 0));

            try {
                ss >> json;

                uint64_t timestamp = json["kismet.device.base.first_time"].asInt64();
                std::string ssid = json["dot11.device"]["dot11.device.last_beaconed_ssid"].asString();

                cached = new cache_obj{timestamp, ssid, "[tbd]"};

                device_cache_map[sourcemac] = cached;

            } catch (const std::exception& e) {
                fprintf(stderr, "WARNING:  Could not process device info for %s/%s, skipping\n",
                        sourcemac.c_str(), phy.c_str());
            }
        }

        if (cached == nullptr)
            continue;

        printf("%s %s %lu \"%s\" %lf %lf %f %f %d %f\n", 
                sourcemac.c_str(), phy.c_str(),
                cached->first_time, cached->ssid.c_str(),
                lat, lon, alt, spd,
                sqlite3_column_as<int>(p, 4),
                sqlite3_column_as<double>(p, 5));


    }

    sqlite3_close(db);

    if (verbose) 
        printf("* Done!\n");

    return 0;
}

