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
#include <iomanip>
#include <ctime>
#include <iostream>
#include <tuple>

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
#include "fmt.h"
#include "packet_ieee80211.h"


// we can't do this is as a sqlite function, as cool as that would be, because sqlite functions
// can't be part of a `where`, only a `having`, which introduces tons of problems.
double distance_meters(double lat0, double lon0, double lat1, double lon1) {
    lat0 = (M_PI / 180) * lat0;
    lon0 = (M_PI / 180) * lon0;
    lat1 = (M_PI / 180) * lat1;
    lon1 = (M_PI / 180) * lon1;

    double diff_lon = lon1 - lon0;
    double diff_lat = lat1 - lat0;

    double ret = 
        (2 * asin(sqrt(pow(sin(diff_lat / 2), 2) +
                       cos(lat0) * cos(lat1) * pow(sin(diff_lon / 2), 2)))) * 6731000.0f;

    return ret;
}

void print_help(char *argv) {
    printf("Kismetdb to WigleCSV\n");
    printf("A simple tool for converting the packet data from a KismetDB log file to\n"
           "the CSV format used by Wigle\n");
    printf("Usage: %s [OPTION]\n", argv);
    printf(" -i, --in [filename]          Input kismetdb file\n"
           " -s, --skip-clean             Don't clean (sql vacuum) input database\n");
}

int main(int argc, char *argv[]) {
    static struct option longopt[] = {
        { "in", required_argument, 0, 'i' },
        { "skip-clean", no_argument, 0, 's' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0 }
    };

    int option_idx = 0;
    optind = 0;
    opterr = 0;

    std::string in_fname;
    bool skipclean = false;

    int sql_r = 0;
    char *sql_errmsg = NULL;
    sqlite3 *db = NULL;

    struct stat statbuf;

    while (1) {
        int r = getopt_long(argc, argv, 
                            "-hi:s", longopt, &option_idx);
        if (r < 0) break;

        if (r == 'h') {
            print_help(argv[0]);
            exit(1);
        } else if (r == 'i') {
            in_fname = std::string(optarg);
        } else if (r == 's') {
            skipclean = true;
        }
    }

    if (in_fname == "") {
        fmt::print(stderr, "ERROR: Expected --in [kismetdb file]\n");
        exit(1);
    }

    if (stat(in_fname.c_str(), &statbuf) < 0) {
        if (errno == ENOENT) 
            fmt::print(stderr, "ERROR:  Input file '{}' does not exist.\n", in_fname);
        else
            fmt::print(stderr, "ERROR:  Unexpected problem checking input "
                    "file '{}': {}\n", in_fname, strerror(errno));

        exit(1);
    }

    /* Open the database and run the vacuum command to clean up any stray journals */
    sql_r = sqlite3_open(in_fname.c_str(), &db);

    if (sql_r) {
        fmt::print(stderr, "ERROR:  Unable to open '{}': {}\n", in_fname, sqlite3_errmsg(db));
        exit(1);
    }

    if (!skipclean) {
        fmt::print("* Preparing input database '{}'...\n", in_fname);

        sql_r = sqlite3_exec(db, "VACUUM;", NULL, NULL, &sql_errmsg);

        if (sql_r != SQLITE_OK) {
            fmt::print(stderr, "ERROR:  Unable to clean up (vacuum) database before copying: {}\n", sql_errmsg);
            sqlite3_close(db);
            exit(1);
        }
    }

    // Use our sql adapters

    using namespace kissqlite3;

    try {
        // Get the version
        int db_version = 0;
        auto version_query = _SELECT(db, "KISMET", {"db_version"});
        auto version_ret = version_query.begin();
        if (version_ret == version_query.end()) {
            fmt::print(stderr, "ERROR:  Unable to fetch database version.\n");
            sqlite3_close(db);
            exit(1);
        }
        db_version = sqlite3_column_as<int>(*version_ret, 0);

        fmt::print("* KismetDB version: {}\n", in_fname, db_version);
        fmt::print("\n");

        // Get the total counts
        unsigned long n_total_packets_db = 0L;
        unsigned long n_packets_with_loc = 0L;
        auto npackets_q = _SELECT(db, "packets", 
                {"count(*), sum(case when (lat != 0 and lon != 0) then 1 else 0 end)"});
        auto npackets_ret = npackets_q.begin();
        if (npackets_ret == npackets_q.end()) {
            fmt::print(stderr, "ERROR:  Unable to fetch packet count.\n");
            sqlite3_close(db);
            exit(1);
        }
        n_total_packets_db = sqlite3_column_as<unsigned long>(*npackets_ret, 0);
        n_packets_with_loc = sqlite3_column_as<unsigned long>(*npackets_ret, 1);

        unsigned long n_total_data_db = 0L;
        unsigned long n_data_with_loc = 0L;
        auto ndata_q = _SELECT(db, "data",
                {"count(*), sum(case when(lat != 0 and lon != 0) then 1 else 0 end)"});
        auto ndata_ret = ndata_q.begin();
        if (ndata_ret == ndata_q.end()) {
            fmt::print(stderr, "ERROR: Unable to fetch data count.\n");
            sqlite3_close(db);
            exit(1);
        }
        n_total_data_db = sqlite3_column_as<unsigned long>(*ndata_ret, 0);
        n_data_with_loc = sqlite3_column_as<unsigned long>(*ndata_ret, 1);

        fmt::print("  Packets: {}\n", n_total_packets_db);
        fmt::print("  Non-packet data: {}\n", n_total_data_db);
        fmt::print("  Packets with location: {}\n", n_packets_with_loc);
        fmt::print("  Data with location: {}\n", n_data_with_loc);
        fmt::print("\n");
       
        unsigned long n_total_devices;
        auto ndevices_q = _SELECT(db, "devices", {"count(*)"});
        auto ndevices_ret = ndevices_q.begin();
        if (ndevices_ret == ndevices_q.end()) {
            fmt::print(stderr, "ERROR:  Unable to fetch device count.\n");
            sqlite3_close(db);
            exit(1);
        }
        n_total_devices = sqlite3_column_as<unsigned long>(*ndevices_ret, 0);

        fmt::print("  Devices: {}\n", n_total_devices);

    } catch (const std::exception& e) {
        fmt::print(stderr, "ERROR:  Could not get database information from '{}': {}\n", in_fname, e.what());
        exit(0);
    }

    return 0;
}

