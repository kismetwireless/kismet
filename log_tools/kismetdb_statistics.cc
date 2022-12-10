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
#include "nlohmann/json.hpp"
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
    printf("Kismetdb statistics\n");
    printf("usage: %s [OPTION]\n", argv);
    printf(" -i, --in [filename]          Input kismetdb file\n"
           " -s, --skip-clean             Don't clean (sql vacuum) input database\n"
           " -j, --json                   Dump stats as a JSON dictionary\n");
}

int main(int argc, char *argv[]) {
    static struct option longopt[] = {
        { "in", required_argument, 0, 'i' },
        { "skip-clean", no_argument, 0, 's' },
        { "json", no_argument, 0, 'j' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0 }
    };

    int option_idx = 0;
    optind = 0;
    opterr = 0;

    std::string in_fname;
    bool skipclean = false;
    bool outputjson = false;
    nlohmann::json root;

    int sql_r = 0;
    char *sql_errmsg = NULL;
    sqlite3 *db = NULL;

    struct stat statbuf;

    while (1) {
        int r = getopt_long(argc, argv, 
                            "-hi:sj", longopt, &option_idx);
        if (r < 0) break;

        if (r == 'h') {
            print_help(argv[0]);
            exit(1);
        } else if (r == 'i') {
            in_fname = std::string(optarg);
        } else if (r == 's') {
            skipclean = true;
        } else if (r == 'j') {
            outputjson = true;
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
    if (!skipclean)
        sql_r = sqlite3_open(in_fname.c_str(), &db);
    else
        sql_r = sqlite3_open_v2(in_fname.c_str(), &db, SQLITE_OPEN_READONLY, nullptr);

    if (sql_r) {
        fmt::print(stderr, "ERROR:  Unable to open '{}': {}\n", in_fname, sqlite3_errmsg(db));
        exit(1);
    }

    if (!skipclean) {
        fmt::print(stderr, "* Cleaning database '{}'...\n", in_fname);

        sql_r = sqlite3_exec(db, "VACUUM;", NULL, NULL, &sql_errmsg);

        if (sql_r != SQLITE_OK) {
            fmt::print(stderr, "ERROR:  Unable to clean up (vacuum) database before copying: {}\n", sql_errmsg);
            sqlite3_close(db);
            exit(1);
        }
    }

    // Use our sql adapters

    using namespace kissqlite3;

    if (outputjson)
        root["file"] = in_fname;

    try {
        // Get the version
        auto version_query = _SELECT(db, "KISMET", {"db_version"});
        auto version_ret = version_query.run();
        auto db_version = sqlite3_column_as<int>(*version_ret, 0);

        if (outputjson) {
            root["kismetdb_version"] = db_version;
        } else {
            fmt::print("  KismetDB version: {}\n", db_version);
            fmt::print("\n");
        }

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

        if (outputjson) {
            root["packets"] = (uint64_t) n_total_packets_db;
            root["data_packets"] = (uint64_t) n_total_data_db;
        } else {
            fmt::print("  Packets: {}\n", n_total_packets_db);
            fmt::print("  Non-packet data: {}\n", n_total_data_db);
            fmt::print("\n");
        }
       
        auto ndevices_q = _SELECT(db, "devices", {"count(*)", "min(first_time)", "max(last_time)"});
        auto ndevices_ret = ndevices_q.run();
        auto n_total_devices = sqlite3_column_as<unsigned long>(*ndevices_ret, 0);
        auto min_time = sqlite3_column_as<time_t>(*ndevices_ret, 1);
        auto max_time = sqlite3_column_as<time_t>(*ndevices_ret, 2);
        struct tm min_tm, max_tm;

        gmtime_r(&min_time, &min_tm);
        gmtime_r(&max_time, &max_tm);

        if (outputjson) {
            root["devices"] = (uint64_t) n_total_devices;
            root["device_min_time"] = (uint64_t) min_time;
            root["device_max_time"] = (uint64_t) max_time;
        } else {
            fmt::print("  Devices: {}\n", n_total_devices);
            char min_tmstr[256];
            char max_tmstr[256];
            strftime(min_tmstr, 255, "%Y-%m-%d %H:%M:%S", &min_tm);
            strftime(max_tmstr, 255, "%Y-%m-%d %H:%M:%S", &max_tm);
            fmt::print("  Devices seen between: {} ({}) to {} ({})\n",
                    min_tmstr, min_time, max_tmstr, max_time);
        }

        auto n_sources_q = _SELECT(db, "datasources", {"count(*)"});
        auto n_sources_q_ret = n_sources_q.run();

        if (!outputjson)
            fmt::print("  {} datasources\n", sqlite3_column_as<unsigned int>(*n_sources_q_ret, 0));
        
        auto sources_q = _SELECT(db, "datasources", 
                {"uuid", "typestring", "definition", "name", "interface", "json"});
        auto sources_q_ret = sources_q.begin();
        if (sources_q_ret == sources_q.end()) {
            fmt::print(stderr, "ERROR:  Unable to fetch datasource count.\n");
            sqlite3_close(db);
            exit(1);
        }

        nlohmann::json ds_vec;

        for (auto i = sources_q.begin(); i != sources_q.end(); ++i) {
            nlohmann::json ds_root;

            if (outputjson) {
                ds_root["uuid"] = sqlite3_column_as<std::string>(*i, 0);
                ds_root["type"] = sqlite3_column_as<std::string>(*i, 1);
                ds_root["definition"] = sqlite3_column_as<std::string>(*i, 2);
                ds_root["name"] = sqlite3_column_as<std::string>(*i, 3);
                ds_root["interface"] = sqlite3_column_as<std::string>(*i, 4);
            } else {
                fmt::print("    {:<16} {:<16} {} {}\n",
                        sqlite3_column_as<std::string>(*i, 3),
                        sqlite3_column_as<std::string>(*i, 4),
                        sqlite3_column_as<std::string>(*i, 0),
                        sqlite3_column_as<std::string>(*i, 1));
            }

            nlohmann::json json;
            std::stringstream ss(sqlite3_column_as<std::string>(*i, 5));

            ss >> json;

            // Pull some data out of the JSON records
            if (outputjson) {
                ds_root["hardware"] = json["kismet.datasource.hardware"];
                ds_root["packets"] = json["kismet.datasource.num_packets"];
            } else {
                fmt::print("      Hardware: {}\n", json["kismet.datasource.hardware"].get<std::string>());
                fmt::print("      Packets: {}\n", json["kismet.datasource.num_packets"].get<double>());
            }

            if (json["kismet.datasource.hopping"].get<int>()) {
                if (outputjson) {
                    ds_root["hop_rate"] = json["kismet.datasource.hop_rate"];
                } else {
                    auto rate = json["kismet.datasource.hop_rate"].get<double>();
                    if (rate >= 1) {
                        fmt::print("      Hop rate: {:f}/second\n", rate);
                    } else if (rate / 60.0f < 60) {
                        fmt::print("      Hop rate: {:f}/minute\n", rate / 60.0f);
                    } else {
                        fmt::print("      Hop rate: {:f} seconds\n", rate / 60.0f);
                    }
                }

                if (outputjson) {
                    ds_root["hop_channels"] = json["kismet.datasource.hop_channels"];
                } else {
                    std::stringstream chan_ss;
                    bool comma = false;
                    for (auto c : json["kismet.datasource.hop_channels"]) {
                        if (comma)
                            chan_ss << ", ";

                        comma = true;

                        chan_ss << c.get<std::string>();
                    }

                    if (chan_ss.str().length()) {
                        fmt::print("      Hop channels: {}\n", chan_ss.str());
                    }
                }
            } else {
                auto chan = json["kismet.datasource.channel"].get<std::string>();
                if (chan.length()) {
                    if (outputjson) {
                        ds_root["channel"] = chan;
                    } else {
                        fmt::print("      Channel: {}\n", chan);
                    }
                }
            }

            ds_vec.push_back(ds_root);
        }

        if (outputjson) {
            root["datasources"] = ds_vec;
        } else {
            fmt::print("\n");
        }

        // Extract tags
        std::map<std::string, bool> tag_map;

        auto tags_q = _SELECT(db, "packets", 
                              {"DISTINCT tags"},
                              _WHERE("tags", NEQ, ""));

        for (auto ti : tags_q) {
            auto t = sqlite3_column_as<std::string>(ti, 0);

            while (t.size()) {
                auto index = t.find(" ");
                if (index != std::string::npos) {
                    tag_map[t.substr(0, index)] = true;
                    t = t.substr(index + 1);

                    if (t.size() == 0)
                        tag_map[t] = true;
                } else {
                    tag_map[t] = true;
                    t = "";
                }
            }
        }

        nlohmann::json tag_vec;

        if (outputjson) {
            for (auto ti : tag_map) {
                auto tag = ti.first;
                tag_vec.push_back(tag);
            }

            root["packettags"] = tag_vec;
        } else {
            fmt::print("  Packet tags found in log:\n    ");
            bool first = true;

            for (auto ti : tag_map) {
                if (!first)
                    fmt::print(" ");
                first = false;
                fmt::print("{}", ti.first);
            }

            fmt::print("\n\n");
        }

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
            if (!outputjson)
                fmt::print("  Location data: None\n");
        } else {
            auto diag_distance = distance_meters(min_lat, min_lon, max_lat, max_lon) / 1000.0f;
            if (outputjson) {
                root["min_lat"] = min_lat;
                root["min_lon"] = min_lon;
                root["max_lat"] = max_lat;
                root["max_lon"] = max_lon;
                root["diag_distance_km"] = diag_distance;
            } else {
                fmt::print("  Bounding location: {:3.10f},{:3.10f} {:3.10f},{:3.10f} (~{:f} Km)\n",
                        min_lat, min_lon, max_lat, max_lon, diag_distance);
            }
        }

        auto breadcrumb_q = _SELECT(db, "snapshots",
                {"lat", "lon"},
                _WHERE("lat", NEQ, 0, 
                    AND,
                    "lon", NEQ, 0,
                    AND,
                    "snaptype", EQ, "GPS"));
        double bc_cur_lat = 0, bc_cur_lon = 0, bc_last_lat = 0, bc_last_lon = 0;
        double breadcrumb_len = 0;

        for (auto bc : breadcrumb_q) {
            if (bc_last_lat == 0 || bc_last_lon == 0) {
                bc_last_lat = sqlite3_column_as<double>(bc, 0);
                bc_last_lon = sqlite3_column_as<double>(bc, 1);
                continue;
            }

            bc_cur_lat = sqlite3_column_as<double>(bc, 0);
            bc_cur_lon = sqlite3_column_as<double>(bc, 1);

            if (bc_cur_lat == bc_last_lat && bc_cur_lon == bc_last_lon)
                continue;

            breadcrumb_len += distance_meters(bc_cur_lat, bc_cur_lon, bc_last_lat, bc_last_lon);

            bc_last_lat = bc_cur_lat;
            bc_last_lon = bc_cur_lon;
        }

        if (outputjson) {
            root["breadcrumb_dist_meters"] = breadcrumb_len;
        } else {
            fmt::print("  Breadcrumb travel distance: {} Km\n", breadcrumb_len / 1000);
        }

        if (!outputjson) {
            fmt::print("  Packets with location: {}\n", n_packets_with_loc);
            fmt::print("  Data with location: {}\n", n_data_with_loc);
            fmt::print("\n");
        }


    } catch (const std::exception& e) {
        fmt::print(stderr, "ERROR:  Could not get database information from '{}': {}\n", in_fname, e.what());
        exit(0);
    }

    if (outputjson) {
        std::stringstream os;

        os << root;

        fmt::print("{}\n", os.str());
    }

    return 0;
}

