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
        fmt::print("* Cleaning database '{}'...\n", in_fname);

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
        auto version_query = _SELECT(db, "KISMET", {"db_version"});
        auto version_ret = version_query.run();
        auto db_version = sqlite3_column_as<int>(*version_ret, 0);

        fmt::print("  KismetDB version: {}\n", db_version);
        fmt::print("\n");

        // Get the total counts
        auto npackets_q = _SELECT(db, "packets", 
                {"count(*), sum(case when (lat != 0 and lon != 0) then 1 else 0 end)"});
        auto npackets_ret = npackets_q.run();
        auto n_total_packets_db = sqlite3_column_as<unsigned long>(*npackets_ret, 0);
        auto n_packets_with_loc = sqlite3_column_as<unsigned long>(*npackets_ret, 1);

        auto ndata_q = _SELECT(db, "data",
                {"count(*), sum(case when(lat != 0 and lon != 0) then 1 else 0 end)"});
        auto ndata_ret = ndata_q.run();
        auto n_total_data_db = sqlite3_column_as<unsigned long>(*ndata_ret, 0);
        auto n_data_with_loc = sqlite3_column_as<unsigned long>(*ndata_ret, 1);

        fmt::print("  Packets: {}\n", n_total_packets_db);
        fmt::print("  Non-packet data: {}\n", n_total_data_db);
        fmt::print("\n");
       
        auto ndevices_q = _SELECT(db, "devices", {"count(*)", "min(first_time)", "max(last_time)"});
        auto ndevices_ret = ndevices_q.run();
        auto n_total_devices = sqlite3_column_as<unsigned long>(*ndevices_ret, 0);
        auto min_time = sqlite3_column_as<time_t>(*ndevices_ret, 1);
        auto max_time = sqlite3_column_as<time_t>(*ndevices_ret, 2);

        auto min_tm = *std::localtime(&min_time);
        auto max_tm = *std::localtime(&max_time);

        fmt::print("  Devices: {}\n", n_total_devices);
        fmt::print("  Devices seen between: {} ({}) to {} ({})\n",
                std::put_time(&min_tm, "%Y-%m-%d %H:%M:%S"), min_time,
                std::put_time(&max_tm, "%Y-%m-%d %H:%M:%S"), max_time);

        auto n_sources_q = _SELECT(db, "datasources",
                {"count(*)"});
        auto n_sources_q_ret = n_sources_q.run();
        fmt::print("  {} datasources\n", sqlite3_column_as<unsigned int>(*n_sources_q_ret, 0));
        
        auto sources_q = _SELECT(db, "datasources", 
                {"uuid", "typestring", "definition", "name", "interface", "json"});
        auto sources_q_ret = sources_q.begin();
        if (sources_q_ret == sources_q.end()) {
            fmt::print(stderr, "ERROR:  Unable to fetch datasource count.\n");
            sqlite3_close(db);
            exit(1);
        }

        for (auto i = sources_q.begin(); i != sources_q.end(); ++i) {
        // for (auto i : sources_q) {
            fmt::print("    {:<16} {:<16} {} {}\n",
                    sqlite3_column_as<std::string>(*i, 3),
                    sqlite3_column_as<std::string>(*i, 4),
                    sqlite3_column_as<std::string>(*i, 0),
                    sqlite3_column_as<std::string>(*i, 1));

            Json::Value json;
            std::stringstream ss(sqlite3_column_as<std::string>(*i, 5));

            ss >> json;

            // Pull some data out of the JSON records
            fmt::print("      Hardware: {}\n", json["kismet.datasource.hardware"].asString());
            fmt::print("      Packets: {}\n", json["kismet.datasource.num_packets"].asDouble());

            if (json["kismet.datasource.hopping"].asInt()) {
                auto rate = json["kismet.datasource.hop_rate"].asDouble();

                if (rate >= 1) {
                    fmt::print("      Hop rate: {:f}/second\n", rate);
                } else if (rate / 60.0f < 60) {
                    fmt::print("      Hop rate: {:f}/minute\n", rate / 60.0f);
                } else {
                    fmt::print("      Hop rate: {:f} seconds\n", rate / 60.0f);
                }

                std::stringstream chan_ss;
                bool comma = false;
                for (auto c : json["kismet.datasource.hop_channels"]) {
                    if (comma)
                        chan_ss << ", ";

                    comma = true;

                    chan_ss << c.asString();
                }

                if (chan_ss.str().length()) {
                    fmt::print("      Hop channels: {}\n", chan_ss.str());
                }
            } else {
                auto chan = json["kismet.datasource.channel"].asString();
                if (chan.length()) {
                    fmt::print("      Channel: {}", chan);
                }
            }
        }
        fmt::print("\n");

        auto range_q = _SELECT(db, "devices",
                {"min(min_lat)", "min(min_lon)", "max(max_lat)", "max(max_lon)"},
                _WHERE("min_lat", NEQ, 0, 
                    AND, 
                    "min_lon", NEQ, 0, 
                    AND,
                    "max_lat", NEQ, 0,
                    AND,
                    "max_lon", NEQ, 0));

        double min_lat, min_lon, max_lat, max_lon;

        try {
            auto range_q_ret = range_q.run();

            min_lat = sqlite3_column_as<double>(*range_q_ret, 0);
            min_lon = sqlite3_column_as<double>(*range_q_ret, 1);
            max_lat = sqlite3_column_as<double>(*range_q_ret, 2);
            max_lon = sqlite3_column_as<double>(*range_q_ret, 3);

        } catch (const std::exception& e) {
            min_lat = 0;
            max_lat = 0;
            min_lon = 0;
            max_lon = 0;
        }

        if (min_lat == 0 || min_lon == 0 || max_lat == 0 || max_lon == 0) {
            fmt::print("  Location data: None\n");
        } else {
            auto diag_distance = distance_meters(min_lat, min_lon, max_lat, max_lon) / 1000.0f;
            fmt::print("  Bounding location: {:f},{:f} {:f},{:f} (~{:f} Km)\n",
                    min_lat, min_lon, max_lat, max_lon, diag_distance);
        }

        fmt::print("  Packets with location: {}\n", n_packets_with_loc);
        fmt::print("  Data with location: {}\n", n_data_with_loc);
        fmt::print("\n");


    } catch (const std::exception& e) {
        fmt::print(stderr, "ERROR:  Could not get database information from '{}': {}\n", in_fname, e.what());
        exit(0);
    }

    return 0;
}

