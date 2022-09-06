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
 * Convert a kismetdb log to GPX
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

// Aggressive additional mangle of text to handle converting to hexcode for XML
std::string MungeForXML(const std::string& in_data) {
	std::string ret;

	for (size_t i = 0; i < in_data.length(); i++) {
        if (in_data[i] == '<') {
            ret += "&lt;";
        } else if (in_data[i] == '>') {
            ret += "&gt;";
        } else if (in_data[i] == '&') {
            ret += "&amp;";
        } else if (in_data[i] == '"') { 
            ret += "&quot;";
        } else if (in_data[i] == '\'') {
            ret += "&apos;";
        } else if ((unsigned char) in_data[i] >= 32 && (unsigned char) in_data[i] <= 126) {
			ret += in_data[i];
		} else {
			ret += '\\';
			ret += ((in_data[i] >> 6) & 0x03) + '0';
			ret += ((in_data[i] >> 3) & 0x07) + '0';
			ret += ((in_data[i] >> 0) & 0x07) + '0';
		}
	}

	return ret;
}

// Some conversion functions from Kismet for Wi-Fi channels
int FrequencyToWifiChannel(double in_freq) {
    if (in_freq == 0)
        return 0;

    in_freq = in_freq / 1000;

    if (in_freq == 2484)
        return 14;
    else if (in_freq < 2484)
        return (in_freq - 2407) / 5;
    else if (in_freq >= 4910 && in_freq <= 4980)
        return (in_freq - 4000) / 5;
    else if (in_freq <= 45000)
        return (in_freq - 5000) / 5;
    else if (in_freq >= 58320 && in_freq <= 64800)
        return (in_freq - 56160) / 2160;
    else
        return in_freq;
}

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

std::string WifiCryptToString(unsigned long cryptset) {
    std::stringstream ss;

    if (cryptset & crypt_wps)
        ss << "[WPS] ";

    if ((cryptset & crypt_protectmask) == crypt_wep) 
        ss << "[WEP] ";

    if (cryptset & crypt_wpa) {

        std::string cryptver = "";

        if (cryptset & crypt_tkip) {
            if (cryptset & crypt_aes_ccm) {
                cryptver = "CCMP+TKIP";
            } else {
                cryptver = "TKIP";
            }
        } else if (cryptset & crypt_aes_ccm) {
            cryptver = "CCMP";
        }

        std::string authver = "";

        if (cryptset & crypt_psk) {
            authver = "PSK";
        } else if (cryptset & crypt_eap) {
            authver = "EAP";
        }

        if ((cryptset & crypt_version_wpa) && (cryptset & crypt_version_wpa2)) {
            ss << "[WPA-" << authver << "-" << cryptver << "] ";
            ss << "[WPA2-" << authver << "-" << cryptver << "] ";
        } else if (cryptset & crypt_version_wpa2) {
            ss << "[WPA2-" << authver << "-" << cryptver << "] ";
        } else {
            ss << "[WPA-" << authver << "-" << cryptver << "] ";
        }
    }

    auto retstr = ss.str();

    if (retstr.length() > 0)
        return retstr.substr(0, retstr.length() - 1);

    return "";
}

// Specific points
class gpx_point {
public:
    double lat, lon, alt;
};

// Placemark cache
class gpx_waypoint {
public:
    // Running lat, lon, and alt, if we're computing it
    double avg_lat, avg_lon, avg_alt;
    double avg_2d_num, avg_alt_num;

    double lat, lon, alt;

    // Name (last known name, user name, or mac address)
    std::string name;
};

void print_help(char *argv) {
    printf("Kismetdb to GPX\n");
    printf("A simple tool for converting the packet data from a KismetDB log file to\n"
           "a GPX file for plotting in OSM and other tools.\n");
    printf("usage: %s [OPTION]\n", argv);
    printf(" -i, --in [filename]          Input kismetdb file\n"
           " -o, --out [filename]         Output GPX file\n"
           " -f, --force                  Force writing to the target file, even if it exists.\n"
           " -v, --verbose                Verbose output\n"
           " -s, --skip-clean             Don't clean (sql vacuum) input database\n"
           " -e, --exclude lat,lon,dist   Exclude records within 'dist' *meters* of the lat,lon\n"
           "                              provided.  This can be used to exclude packets close to\n"
           "                              your home, or other sensitive locations.\n"
           " --basic-location             Use basic average location information instead of computing a\n"
           "                              high-precision location; faster, but less accurate\n"
          );
}

int main(int argc, char *argv[]) {
    static struct option longopt[] = {
        { "in", required_argument, 0, 'i' },
        { "out", required_argument, 0, 'o' },
        { "verbose", no_argument, 0, 'v' },
        { "force", no_argument, 0, 'f' },
        { "help", no_argument, 0, 'h' },
        { "skip-clean", no_argument, 0, 's' },
        { "exclude", required_argument, 0, 'e'},
        { "basic-location", no_argument, 0, 'B'},
        { 0, 0, 0, 0 }
    };

    int option_idx = 0;
    optind = 0;
    opterr = 0;

    std::string in_fname, out_fname;
    bool verbose = false;
    bool force = false;
    bool skipclean = false;
    bool basiclocation = false;

    std::vector<std::tuple<double, double, double>> exclusion_zones;

    int sql_r = 0;
    char *sql_errmsg = NULL;
    sqlite3 *db = NULL;

    FILE *ofile = NULL;

    struct stat statbuf;

    while (1) {
        int r = getopt_long(argc, argv, 
                            "-hi:o:r:c:e:vfs", 
                            longopt, &option_idx);
        if (r < 0) break;

        if (r == 'h') {
            print_help(argv[0]);
            exit(1);
        } else if (r == 'i') {
            in_fname = std::string(optarg);
        } else if (r == 'o') {
            out_fname = std::string(optarg);
        } else if (r == 'v') { 
            verbose = true;
        } else if (r == 'f') {
            force = true;
        } else if (r == 's') {
            skipclean = true;
        } else if (r == 'e') {
            double lat, lon, distance;

            if (sscanf(optarg, "%lf,%lf,%lf", &lat, &lon, &distance) != 3) {
                fmt::print(stderr, "ERROR:  Expected an exclusion zone of lat,lon,distance_in_meters.\n");
                exit(1);
            }

            exclusion_zones.push_back(std::make_tuple(lat, lon, distance));
        } else if (r == 'B') {
            basiclocation = true;
        }
    }

    if (out_fname == "" || in_fname == "") {
        fmt::print(stderr, "ERROR: Expected --in [kismetdb file] and --out [GPX file]\n");
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

    if (out_fname != "-") {
        if (stat(out_fname.c_str(), &statbuf) < 0) {
            if (errno != ENOENT) {
                fmt::print(stderr, "ERROR:  Unexpected problem checking output "
                        "file '{}': {}\n", out_fname, strerror(errno));
                exit(1);
            }
        } else if (force == false) {
            fmt::print(stderr, "ERROR:  Output file '{}' exists already; use --force to "
                    "clobber the file.\n", out_fname);
            exit(1);
        }
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
        if (verbose)
            fmt::print(stderr, "* Preparing input database '{}'...\n", in_fname);


        sql_r = sqlite3_exec(db, "VACUUM;", NULL, NULL, &sql_errmsg);

        if (sql_r != SQLITE_OK) {
            fmt::print(stderr, "ERROR:  Unable to clean up (vacuum) database before copying: {}\n", sql_errmsg);
            sqlite3_close(db);
            exit(1);
        }
    }

    // Use our sql adapters

    using namespace kissqlite3;

    int db_version = 0;
    long int n_total_packets_db = 0L;
    long int n_packets_db = 0L;
    long int n_devices_db = 0L;
    long int n_devices_gps_db = 0L;
    long int n_data_gps_db = 0L;

    try {
        // Get the version
        auto version_query = _SELECT(db, "KISMET", {"db_version"});
        auto version_ret = version_query.begin();
        if (version_ret == version_query.end()) {
            fmt::print(stderr, "ERROR:  Unable to fetch database version.\n");
            sqlite3_close(db);
            exit(1);
        }
        db_version = sqlite3_column_as<int>(*version_ret, 0);

        if (verbose)
            fmt::print(stderr, "* Found KismetDB version {}\n", db_version);

        // Get the total counts
        auto npackets_q = _SELECT(db, "packets", 
                {"count(*), sum(case when (sourcemac != '00:00:00:00:00:00' "
                "and lat != 0 and lon != 0) then 1 else 0 end)"});
        auto npackets_ret = npackets_q.begin();
        if (npackets_ret == npackets_q.end()) {
            fmt::print(stderr, "ERROR:  Unable to fetch packet count.\n");
            sqlite3_close(db);
            exit(1);
        }
        n_total_packets_db = sqlite3_column_as<unsigned long>(*npackets_ret, 0);
        n_packets_db = sqlite3_column_as<unsigned long>(*npackets_ret, 1);

        auto ndata_q = _SELECT(db, "data", {"count(*)"}, _WHERE("lat", NEQ, 0, AND, "lon", NEQ, 0));
        auto ndata_ret = ndata_q.begin();
        if (npackets_ret == npackets_q.end()) {
            fmt::print(stderr, "ERROR:  Unable to fetch data count.\n");
            sqlite3_close(db);
            exit(1);
        }
        n_data_gps_db = sqlite3_column_as<unsigned long>(*ndata_ret, 0);

        auto ndevices_q = _SELECT(db, "devices", {"count(*)"});
        auto ndevices_ret = ndevices_q.begin();
        if (ndevices_ret == ndevices_q.end()) {
            fmt::print(stderr, "ERROR:  Unable to fetch device count.\n");
            sqlite3_close(db);
            exit(1);
        }
        n_devices_db = sqlite3_column_as<unsigned long>(*ndevices_ret, 0);

        auto ndevices_gps_q = _SELECT(db, "devices", {"count(*)"}, 
                _WHERE("avglat", NEQ, 0,
                    AND,
                    "avglon", NEQ, 0));
        auto ndevices_gps_ret = ndevices_q.begin();
        if (ndevices_gps_ret == ndevices_gps_q.end()) {
            fmt::print(stderr, "ERROR: Unable to fetch device-with-gps count.\n");
            sqlite3_close(db);
            exit(1);
        }
        n_devices_gps_db = sqlite3_column_as<unsigned long>(*ndevices_gps_ret, 0);

        if (verbose) 
            fmt::print(stderr, "* Found {} devices, {} devices with gps, {} usable packets, {} total packets\n", 
                    n_devices_db, n_devices_gps_db, n_packets_db, n_total_packets_db);

        if (n_devices_gps_db && basiclocation) {
            fmt::print(stderr, "ERROR:  No usable devices in the log file; devices must have GPS information\n"
                               "        to be usable with GPX.  You can try without --basic-location to use the\n"
                               "        packets to derive a more precise location, but you may have no GPS data\n"
                               "        in this log.\n");
            sqlite3_close(db);
            exit(1);
        }

        if (n_packets_db == 0 && n_data_gps_db == 0 && !basiclocation) {
            fmt::print(stderr, "ERROR:  No usable packets in the log file; packets must have GPS information\n"
                               "        to be usable with GPX.  You can try with --basic-location to use the\n"
                               "        device averages.\n");
            sqlite3_close(db);
            exit(1);
        }
    } catch (const std::exception& e) {
        fmt::print(stderr, "ERROR:  Could not get database information from '{}': {}\n", in_fname, e.what());
        exit(0);
    }

    if (out_fname == "-") {
        ofile = stdout;
    } else {
        ofile = fopen(out_fname.c_str(), "w");
        if (ofile == NULL) {
            fmt::print(stderr, "ERROR:  Unable to open output file for writing: {}\n", strerror(errno));
            exit(1);
        }
    }

    std::vector<gpx_waypoint> waypoint_vec;

    if (basiclocation) {
        auto basic_q = 
            _SELECT(db, "devices", 
                    {"min_lat", "min_lon", "max_lat", "max_lon", "avg_lat", "avg_lon", "device"}, 
                    _WHERE("avglat", NEQ, 0, AND, "avglon", NEQ, 0));

        for (auto d : basic_q) {
            double avg_lat, avg_lon;

            // Handle the different versions
            if (db_version < 5) {
                avg_lat = sqlite3_column_as<double>(d, 4) / 100000;
                avg_lon = sqlite3_column_as<double>(d, 5) / 100000;
            } else {
                avg_lat = sqlite3_column_as<double>(d, 4);
                avg_lon = sqlite3_column_as<double>(d, 5);
            }

            // Check to see if we lie in any exclusion zones
            bool violates_exclusion = false;
            for (auto ez : exclusion_zones) {
                if (distance_meters(avg_lat, avg_lon, std::get<0>(ez), std::get<1>(ez)) <= std::get<2>(ez)) {
                    violates_exclusion = true;
                    break;
                }
            }

            if (violates_exclusion) {
                continue;
            }

            nlohmann::json json;
            std::stringstream ss(sqlite3_column_as<std::string>(d, 6));

            try {
                ss >> json;

                if (avg_lat == 0 || avg_lon == 0)
                    continue;

                gpx_waypoint pl;
                pl.name = json["kismet.device.base.commonname"].get<std::string>();
                pl.lat = avg_lat;
                pl.lon = avg_lon;
                pl.alt = 0;


                waypoint_vec.push_back(pl);
            } catch (const std::exception& e) {
                std::cerr << 
                    fmt::format("WARNING:  Could not process device info for '{}', skipping", json.dump()) << std::endl;
            }

        }
    } else {
        auto basic_q = 
            _SELECT(db, "devices", {"phyname", "devmac", "device"});

        for (auto d : basic_q) {
            // Prep the packet list for different kismetdb versions
            std::list<std::string> packet_fields;

            if (db_version < 5) {
                packet_fields = std::list<std::string>{"lat", "lon" };
            } else {
                packet_fields = std::list<std::string>{"lat", "lon", "alt"};
            }

            auto phyname = sqlite3_column_as<std::string>(d, 0);
            auto devmac = sqlite3_column_as<std::string>(d, 1);
            nlohmann::json json;

            std::stringstream ss(sqlite3_column_as<std::string>(d, 2));

            gpx_waypoint pl;

            try {
                ss >> json;
                pl.name = json["kismet.device.base.commonname"].get<std::string>();
            } catch (const std::exception& e) {
                fmt::print(stderr, "WARNING:  Could not process device info for '{}', skipping\n", json.dump());
                continue;
            }

            pl.avg_alt = 0;
            pl.avg_lat = 0;
            pl.avg_lon = 0;
            pl.avg_2d_num = 0;
            pl.avg_alt = 0;

            auto packet_q = _SELECT(db, "packets", packet_fields,
                    _WHERE("sourcemac", EQ, devmac, AND, "phyname", EQ, phyname, AND, "lat", NEQ, 0, AND, "lon", NEQ, 0));

            for (auto p : packet_q) {
                double lat, lon, alt;

                // Handle the different versions
                if (db_version < 5) {
                    lat = sqlite3_column_as<double>(p, 0) / 100000;
                    lon = sqlite3_column_as<double>(p, 1) / 100000;
                    alt = 0;
                } else {
                    lat = sqlite3_column_as<double>(p, 0);
                    lon = sqlite3_column_as<double>(p, 1);
                    alt = sqlite3_column_as<double>(p, 2);
                }

                if (lat == 0 || lon == 0)
                    continue;

                // Check to see if we lie in any exclusion zones
                bool violates_exclusion = false;
                for (auto ez : exclusion_zones) {
                    if (distance_meters(lat, lon, std::get<0>(ez), std::get<1>(ez)) <= std::get<2>(ez)) {
                        violates_exclusion = true;
                        break;
                    }
                }

                if (violates_exclusion) {
                    continue;
                }

                pl.avg_lat += lat;
                pl.avg_lon += lon;
                pl.avg_2d_num++;

                if (alt != 0) {
                    pl.avg_alt += alt;
                    pl.avg_alt_num++;
                }
            }

            auto data_q = _SELECT(db, "data", packet_fields,
                    _WHERE("devmac", EQ, devmac, AND, "phyname", EQ, phyname, AND, "lat", NEQ, 0, AND, "lon", NEQ, 0));

            for (auto p : data_q) {
                double lat, lon, alt;

                // Handle the different versions
                if (db_version < 5) {
                    lat = sqlite3_column_as<double>(p, 0) / 100000;
                    lon = sqlite3_column_as<double>(p, 1) / 100000;
                    alt = 0;
                } else {
                    lat = sqlite3_column_as<double>(p, 0);
                    lon = sqlite3_column_as<double>(p, 1);
                    alt = sqlite3_column_as<double>(p, 2);
                }

                if (lat == 0 || lon == 0)
                    continue;

                // Check to see if we lie in any exclusion zones
                bool violates_exclusion = false;
                for (auto ez : exclusion_zones) {
                    if (distance_meters(lat, lon, std::get<0>(ez), std::get<1>(ez)) <= std::get<2>(ez)) {
                        violates_exclusion = true;
                        break;
                    }
                }

                if (violates_exclusion) {
                    continue;
                }

                pl.avg_lat += lat;
                pl.avg_lon += lon;
                pl.avg_2d_num++;

                if (alt != 0) {
                    pl.avg_alt += alt;
                    pl.avg_alt_num++;
                }
            }

            if (pl.avg_2d_num == 0) {
                fmt::print(stderr, "WARNING:  No packets with GPS info for '{}', skipping\n", pl.name);
                continue;
            }

            pl.lat = pl.avg_lat / pl.avg_2d_num;
            pl.lon = pl.avg_lon / pl.avg_2d_num;

            if (pl.avg_alt_num)
                pl.alt = pl.avg_alt / pl.avg_alt_num;

            waypoint_vec.push_back(pl);
        }

        fmt::print(ofile, 
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                "<gpx version=\"1.0\">\n"
                "<name>Kismet {}</name>\n", MungeForXML(in_fname));

        for (auto pl : waypoint_vec) {
            fmt::print(ofile, "<wpt lat=\"{}\" lon=\"{}\">\n", pl.lat, pl.lon);
            fmt::print(ofile, "<ele>{}</ele>\n", pl.alt);
            fmt::print(ofile, "<name>{}</name>", MungeForXML(pl.name));
            fmt::print(ofile, "</wpt>");
        }

        fmt::print(ofile, "<trk><trkseg>\n");

        auto status_q = _SELECT(db, "snapshots", {"lat", "lon"},
                _WHERE("snaptype", EQ, "GPS"));

        for (auto l : status_q) {
            double lat = 0, lon = 0;

            // Handle the different versions
            if (db_version < 5) {
                lat = sqlite3_column_as<double>(l, 0) / 100000;
                lon = sqlite3_column_as<double>(l, 1) / 100000;
            } else {
                lat = sqlite3_column_as<double>(l, 0);
                lon = sqlite3_column_as<double>(l, 1);
            }

            if (lat == 0 || lon == 0)
                continue;

            fmt::print(ofile, "<trkpt lat=\"{}\" lon=\"{}\"></trkpt>\n", lat, lon);
        }
        fmt::print(ofile, "</trkseg>\n</trk>\n");

        fmt::print(ofile, "</gpx>\n");

    }

    if (ofile != stdout) {
        fclose(ofile);
    }

    sqlite3_close(db);

    return 0;
}

