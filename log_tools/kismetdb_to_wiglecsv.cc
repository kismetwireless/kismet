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
#include "nlohmann/json.hpp"
#include "sqlite3_cpp11.h"
#include "fmt.h"
#include "packet_ieee80211.h"
#include "version.h"

#ifdef HAVE_LIBPCRE1
#include <pcre.h>
#endif

#ifdef HAVE_LIBPCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

// Aggressive additional mangle of text to handle converting ',' and '"' to
// hexcode for CSV
std::string MungeForCSV(const std::string& in_data) {
	std::string ret;

	for (size_t i = 0; i < in_data.length(); i++) {
		if ((unsigned char) in_data[i] >= 32 && (unsigned char) in_data[i] <= 126 &&
				in_data[i] != ',' && in_data[i] != '\"' ) {
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

    if (cryptset & dot11_crypt_akm_wps)
        ss << "[WPS] ";

    if (cryptset & dot11_crypt_general_wep)
        ss << "[WEP] ";

    if (cryptset & dot11_crypt_general_wpa) {

        std::string cryptver = "";

        if ((cryptset & dot11_crypt_pairwise_tkip) || (cryptset & dot11_crypt_group_tkip)) {
            if ((cryptset & dot11_crypt_pairwise_ccmp128) || (cryptset & dot11_crypt_group_ccmp128)) {
                cryptver = "CCMP+TKIP";
            } else {
                cryptver = "TKIP";
            }
        } else if (cryptset & dot11_crypt_pairwise_ccmp128) {
            cryptver = "CCMP";
        }

        std::string authver = "";

        if (cryptset & dot11_crypt_akm_psk) {
            authver = "PSK";
        } else if (cryptset & dot11_crypt_akm_1x) {
            authver = "EAP";
        } else if (cryptset & dot11_crypt_akm_owe) {
            authver = "OWE";
        } else {
            authver = "UNKNOWN";
        }

        if ((cryptset & dot11_crypt_general_wpa2) && (cryptset & dot11_crypt_general_wpa1)) {
            ss << "[WPA-" << authver << "-" << cryptver << "] ";
            ss << "[WPA2-" << authver << "-" << cryptver << "] ";
        } else if (cryptset & dot11_crypt_general_wpa2) {
            ss << "[WPA2-" << authver << "-" << cryptver << "] ";
        } else if ((cryptset & dot11_crypt_general_wpa3) || (cryptset & dot11_crypt_akm_owe)) {
            ss << "[WPA3-" << authver << "-" << cryptver << "] ";
        } else {
            ss << "[WPA-" << authver << "-" << cryptver << "] ";
        }
    }

    auto retstr = ss.str();

    if (retstr.length() > 0)
        return retstr.substr(0, retstr.length() - 1);

    return "";
}

void print_help(char *argv) {
    printf("Kismetdb to WigleCSV\n");
    printf("A simple tool for converting the packet data from a KismetDB log file to\n"
           "the CSV format used by Wigle\n");
    printf("usage: %s [OPTION]\n", argv);
    printf(" -i, --in [filename]          Input kismetdb file\n"
           " -o, --out [filename]         Output Wigle CSV file\n"
           " -f, --force                  Force writing to the target file, even if it exists.\n"
           " -r, --rate-limit [rate]      Limit updated records to one update per [rate] seconds\n"
           "                              per device\n"
           " -c, --cache-limit [limit]    Maximum number of device to cache, defaults to 1000.\n"
           " -v, --verbose                Verbose output\n"
           " -s, --skip-clean             Don't clean (sql vacuum) input database\n"
           " -e, --exclude lat,lon,dist   Exclude records within 'dist' *meters* of the lat,lon\n"
           "                              provided.  This can be used to exclude packets close to\n"
           "                              your home, or other sensitive locations.\n");
}

int main(int argc, char *argv[]) {
    static struct option longopt[] = {
        { "in", required_argument, 0, 'i' },
        { "out", required_argument, 0, 'o' },
        { "verbose", no_argument, 0, 'v' },
        { "force", no_argument, 0, 'f' },
        { "help", no_argument, 0, 'h' },
        { "skip-clean", no_argument, 0, 's' },
        { "rate-limit", required_argument, 0, 'r'},
        { "cache-limit", required_argument, 0, 'c'},
        { "exclude", required_argument, 0, 'e'},
        { "filter", required_argument, 0, 'F' },
        { 0, 0, 0, 0 }
    };

    struct pcre_filter {
#if defined HAVE_LIBPCRE1
        pcre_filter(const std::string& in_regex) {
            const char *compile_error, *study_error;
            int err_offt;

            re = pcre_compile(in_regex.c_str(), 0, &compile_error, &err_offt, NULL);

            if (re == nullptr)
                throw std::runtime_error(fmt::format("Could not parse PCRE Regex: {} at {}",
                            compile_error, err_offt));

            study = pcre_study(re, 0, &study_error);
            if (study_error != nullptr) {
                pcre_free(re);
                throw std::runtime_error(fmt::format("Could not parse PCRE Regex, optimization "
                            "failed: {}", study_error));
            }
        }

        ~pcre_filter() {
            if (re != NULL)
                pcre_free(re);
            if (study != NULL)
                pcre_free(study);
        }

        bool match(const std::string& target) {
            int rc;
            int ovector[128];

            rc = pcre_exec(re, study, target.c_str(), target.length(), 0, 0, ovector, 128);

            if (rc >= 0)
                return true;

            return false;
        }

        pcre *re;
        pcre_extra *study;
#elif defined HAVE_LIBPCRE2
        pcre_filter(const std::string& in_regex) {
            PCRE2_SIZE erroroffset;
            int errornumber;

            re = NULL;
            match_data = NULL;

            re = pcre2_compile((PCRE2_SPTR8) in_regex.c_str(),
                    PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);

            if (re == nullptr) {
                PCRE2_UCHAR buffer[256];
                pcre2_get_error_message(errornumber, buffer, sizeof(buffer));
                throw std::runtime_error(fmt::format("Could not parse PCRE regex: {} at {}",
                            (int) erroroffset, (char *) buffer));
            }

			match_data = pcre2_match_data_create_from_pattern(re, NULL);
        }

        ~pcre_filter() {
            if (match_data != nullptr)
                pcre2_match_data_free(match_data);
            if (re != nullptr)
                pcre2_code_free(re);
        }

        bool match(const std::string& target) {
            int rc;

            rc = pcre2_match(re, (PCRE2_SPTR8) target.c_str(), target.length(),
                    0, 0, match_data, NULL);

            if (rc >= 0)
                return true;

            return false;
        }

        pcre2_code *re;
        pcre2_match_data *match_data;

#else
        pcre_filter(const std::string& in_regex) {}
        bool match(const std::string& target) {return false;}
#endif
    };

    std::list<std::shared_ptr<pcre_filter>> pcre_list;

    int option_idx = 0;
    optind = 0;
    opterr = 0;

    std::string in_fname, out_fname;
    bool verbose = false;
    bool force = false;
    bool skipclean = false;

    std::vector<std::tuple<double, double, double>> exclusion_zones;

    int sql_r = 0;
    char *sql_errmsg = NULL;
    sqlite3 *db = NULL;

    FILE *ofile = NULL;

    struct stat statbuf;

    unsigned int rate_limit = 1;
    unsigned int cache_limit = 1000;

    while (1) {
        int r = getopt_long(argc, argv,
                            "-hi:o:r:c:e:vfsF:",
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
        } else if (r == 'r') {
            if (sscanf(optarg, "%u", &rate_limit) != 1) {
                fmt::print(stderr, "ERROR:  Expected a rate limit of # seconds between packets of the same device.\n");
                exit(1);
            }
        } else if (r == 'c') {
            if (sscanf(optarg, "%u", &cache_limit) != 1) {
                fmt::print(stderr, "ERROR:  Expected a cache limit number.\n");
                exit(1);
            }
        } else if (r == 'e') {
            double lat, lon, distance;

            if (sscanf(optarg, "%lf,%lf,%lf", &lat, &lon, &distance) != 3) {
                fmt::print(stderr, "ERROR:  Expected an exclusion zone of lat,lon,distance_in_meters.\n");
                exit(1);
            }

            exclusion_zones.push_back(std::make_tuple(lat, lon, distance));
        } else if (r == 'F') {
#if defined(HAVE_LIBPCRE1) == 0 && defined(HAVE_LIBPCRE2) == 0
            fmt::print(stderr, "ERROR:  We were not compiled with libpcre support, so we "
                    "can't use regex filters.");
            exit(1);
#endif

            try {
                auto regex = std::make_shared<pcre_filter>(std::string(optarg));
                pcre_list.push_back(regex);
            } catch (const std::runtime_error& e) {
                fmt::print(stderr, "ERROR:  Could not process regex: {}", e.what());
                exit(1);
            }
        }
    }

    if (out_fname == "" || in_fname == "") {
        fmt::print(stderr, "ERROR: Expected --in [kismetdb file] and --out [wigle CSV file]\n");
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

        auto ndevices_q = _SELECT(db, "devices", {"count(*)"});
        auto ndevices_ret = ndevices_q.begin();
        if (ndevices_ret == ndevices_q.end()) {
            fmt::print(stderr, "ERROR:  Unable to fetch device count.\n");
            sqlite3_close(db);
            exit(1);
        }
        n_devices_db = sqlite3_column_as<unsigned long>(*ndevices_ret, 0);

        if (verbose)
            fmt::print(stderr, "* Found {} devices, {} packets with GPS, {} total packets\n",
                    n_devices_db, n_packets_db, n_total_packets_db);

        if (n_packets_db == 0) {
            fmt::print(stderr, "ERROR:  No usable data in the provided log; Wigle export currently works\n"
                            "        with WiFi devices which were captured with GPS data.  Make sure\n"
                            "        you have a GPS connected with a signal lock.\n");
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
            fmt::print(stderr, "ERROR:  Unable to open output file {}: {}\n", out_fname, strerror(errno));
            exit(1);
        }
    }

    // Define a simple cache; we don't need to use a proper kismet macaddr here, just operate
    // on it as a string
    class cache_obj {
    public:
        cache_obj(std::string t, std::string s, std::string c) :
            first_time{t},
            name{s},
            crypto{c},
            last_time_sec{0},
            type{""},
            filtered{false} { }

        cache_obj(std::string t, std::string s, std::string c, std::string type) :
            first_time{t},
            name{s},
            crypto{c},
            last_time_sec{0},
            type{type},
            filtered{false} { }

        void filter(bool f) {
            filtered = f;
        }

        std::string first_time;
        std::string name;
        std::string crypto;
        uint64_t last_time_sec;
        std::string type;
        bool filtered;
    };

    std::map<std::string, std::shared_ptr<cache_obj>> device_cache_map;

    if (verbose)
        fmt::print(stderr, "* Starting to process file, max device cache {}\n", cache_limit);

    // CSV headers
    fmt::print(ofile, "WigleWifi-1.4,appRelease=Kismet{0}{1}{2},model=Kismet,release={0}.{1}.{2}.{3},"
            "device=kismet,display=kismet,board=kismet,brand=kismet\n",
            VERSION_MAJOR, VERSION_MINOR, VERSION_TINY, db_version);
    fmt::print(ofile, "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,"
            "AltitudeMeters,AccuracyMeters,Type\n");

    // Prep the packet list for different kismetdb versions
    std::list<std::string> packet_fields;

    if (db_version < 5) {
        packet_fields = std::list<std::string>{"ts_sec", "sourcemac", "phyname", "lat", "lon",
            "signal", "frequency"};
    } else {
        packet_fields = std::list<std::string>{"ts_sec", "sourcemac", "phyname", "lat", "lon",
            "signal", "frequency", "alt", "speed"};
    }

    std::list<std::string> bt_fields;
    switch (db_version) {
        case 1:
        case 2:
        case 3:
        case 4:
            bt_fields = std::list<std::string>{"ts_sec", "devmac", "phyname", "lat", "lon"};
            break;
        default:
            bt_fields = std::list<std::string>{"ts_sec", "devmac", "phyname", "lat", "lon", "alt"};
            break;
    }

    auto query = _SELECT(db, "packets", packet_fields,
            _WHERE("sourcemac", NEQ, "00:00:00:00:00:00",
                AND,
                "lat", NEQ, 0,
                AND,
                "lon", NEQ, 0));

    auto bt_query = _SELECT(db, "data", bt_fields,
            _WHERE("lat", NEQ, 0, AND, "lon", NEQ, 0));
    bt_query.append_where(AND, _WHERE("phyname", EQ, "Bluetooth", OR, "phyname", EQ, "BTLE"));

    unsigned long n_logs = 0;
    unsigned long n_saved = 0;
    unsigned long n_discarded_logs_rate = 0;
    unsigned long n_discarded_logs_zones = 0;
    unsigned long n_division = (n_packets_db / 20);

    if (n_division <= 0)
        n_division = 1;

    for (auto p : query) {
        // Brute-force cache maintenance; if we're full at the start of the
        // processing loop, nuke the ENTIRE cache and rebuild it; this is
        // cleaner than constantly re-sorting it.
        if (device_cache_map.size() >= cache_limit) {
            if (verbose)
                fmt::print(stderr, "* Cleaning cache...\n");

            device_cache_map.clear();
        }

        n_logs++;
        if (n_logs % n_division == 0 && verbose)
            std::cerr <<
                fmt::format("* {}%% processed {} records, {} discarded from rate limiting, {} discarded from exclusion zones, {} cached",
                    (int) (((float) n_logs / (float) n_packets_db) * 100) + 1,
                    n_logs, n_discarded_logs_rate, n_discarded_logs_zones, device_cache_map.size()) << std::endl;

        auto ts = sqlite3_column_as<std::uint64_t>(p, 0);
        auto sourcemac = sqlite3_column_as<std::string>(p, 1);
        auto phy = sqlite3_column_as<std::string>(p, 2);

        auto lat = 0.0f, lon = 0.0f, alt = 0.0f;

        auto signal = sqlite3_column_as<int>(p, 5);
        auto channel = sqlite3_column_as<double>(p, 6);

        auto crypt = std::string{""};

        // Handle the different versions
        if (db_version < 5) {
            lat = sqlite3_column_as<double>(p, 3) / 100000;
            lon = sqlite3_column_as<double>(p, 4) / 100000;
        } else {
            lat = sqlite3_column_as<double>(p, 3);
            lon = sqlite3_column_as<double>(p, 4);
            alt = sqlite3_column_as<double>(p, 7);
        }

        auto ci = device_cache_map.find(sourcemac);
        std::shared_ptr<cache_obj> cached;

        if (ci != device_cache_map.end()) {
            cached = ci->second;
        } else {
            auto dev_query = _SELECT(db, "devices", {"device"},
                    _WHERE("devmac", EQ, sourcemac,
                        AND,
                        "phyname", EQ, phy));

            auto dev = dev_query.begin();

            if (dev == dev_query.end()) {
                // printf("Could not find device record for %s\n", sqlite3_column_as<std::string>(p, 0).c_str());
                continue;
            }

            // Check to see if we lie in any exclusion zones
            bool violates_exclusion = false;
            for (auto ez : exclusion_zones) {
                if (distance_meters(lat, lon, std::get<0>(ez), std::get<1>(ez)) <= std::get<2>(ez)) {
                    violates_exclusion = true;
                    break;
                }
            }

            if (violates_exclusion) {
                n_discarded_logs_zones++;
                continue;
            }

            nlohmann::json json;
            std::stringstream ss(sqlite3_column_as<std::string>(*dev, 0));

            try {
                ss >> json;

                if (json["kismet.device.base.first_time"].is_null())
                    throw std::runtime_error("No first_time in record");

                auto timestamp = json["kismet.device.base.first_time"].get<uint64_t>();
                auto name = std::string{""};
                auto crypt = std::string{""};
                auto type = json["kismet.device.base.type"].get<std::string>();

                if (phy == "IEEE802.11") {
                    if (type != "Wi-Fi AP")
                        continue;

                    if (json["dot11.device"]["dot11.device.last_beaconed_ssid"].is_string()) {
                        name = MungeForCSV(json["dot11.device"]["dot11.device.last_beaconed_ssid"]);
                    } else if (!json["dot11.device"]["dot11.device.last_beaconed_ssid_record"].is_null()) {
                        name = MungeForCSV(json["dot11.device"]["dot11.device.last_beaconed_ssid_record"]["dot11.advertisedssid.ssid"]);
                    } else {
                        name = "";
                    }

                    if (json["dot11.device"]["dot11.device.last_beaconed_ssid"].is_string()) {
                        name = MungeForCSV(json["dot11.device"]["dot11.device.last_beaconed_ssid"]);
                    } else if (json["dot11.device"]["dot11.device.last_beaconed_ssid_record"]["dot11.advertisedssid.ssid"].is_string()) {
                        name = MungeForCSV(json["dot11.device"]["dot11.device.last_beaconed_ssid_record"]["dot11.advertisedssid.ssid"]);
                    } else {
                        name = "";
                    }

                    // Handle the aliased ssid_record for modern info
                    if (!json["dot11.device"]["dot11.device.last_beaconed_ssid_record"].is_null()) {
                        crypt = WifiCryptToString(json["dot11.device"]["dot11.device.last_beaconed_ssid_record"].value("dot11.advertisedssid.crypt_bitfield", 0));
                    } else {
                        if (json["dot11.device"]["dot11.device.last_beaconed_ssid_checksum"].is_null())
                            throw std::runtime_error("No last beaconed checksum");

                        auto last_ssid_key =
                            json["dot11.device"]["dot11.device.last_beaconed_ssid_checksum"].get<uint64_t>();
                        std::stringstream ss;

                        ss << last_ssid_key;

                        crypt = WifiCryptToString(json["dot11.device"]["dot11.device.advertised_ssid_map"][ss.str()].value("dot11.advertisedssid.crypt_bitfield", 0));
                    }

                    crypt += "[ESS]";

                }

                std::time_t timet(timestamp);
                std::tm tm;
                std::stringstream ts;

                gmtime_r(&timet, &tm);

                char tmstr[256];
                strftime(tmstr, 255, "%Y-%m-%d %H:%M:%S", &tm);
                ts << tmstr;

                // because apparently gcc4 is still a thing?
                // ts << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");

                cached = std::make_shared<cache_obj>(ts.str(), name, crypt);

                device_cache_map[sourcemac] = cached;

#if defined(HAVE_LIBPCRE1) || defined(HAVE_LIBPCRE2)
                for (const auto& i : pcre_list) {
                    if (i->match(name))
                        cached->filter(true);
                }
#endif

            } catch (const std::exception& e) {
                std::cerr <<
                    fmt::format("WARNING:  Could not process device info for {}/{}, skipping: {}", sourcemac, phy, e.what()) << std::endl;
            }
        }

        if (cached == nullptr)
            continue;

        if (cached->filtered)
            continue;

        // Rate throttle
        if (rate_limit != 0 && cached->last_time_sec != 0) {
            if (cached->last_time_sec + rate_limit < ts) {
                n_discarded_logs_rate++;
                continue;
            }
        }
        cached->last_time_sec = ts;

        if (phy == "IEEE802.11")
            channel = FrequencyToWifiChannel(channel);

        // printf("MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n");

        fmt::print(ofile, "{},{},{},{},{},{},{:3.10f},{:3.10f},{:f},0,{}\n",
                sourcemac,
                cached->name,
                cached->crypto,
                cached->first_time,
                (int) channel,
                signal,
                lat, lon, alt,
                "WIFI");

        n_saved++;
    }

    // Clear the cache before bluetooth processing
    device_cache_map.clear();

    for (auto p : bt_query) {
        // Brute-force cache maintenance; if we're full at the start of the
        // processing loop, nuke the ENTIRE cache and rebuild it; this is
        // cleaner than constantly re-sorting it.
        if (device_cache_map.size() >= cache_limit) {
            if (verbose)
                fmt::print(stderr, "* Cleaning cache...\n");

            device_cache_map.clear();
        }

        n_logs++;
        if (n_logs % n_division == 0 && verbose)
            std::cerr <<
                fmt::format("* {}%% processed {} records, {} discarded from rate limiting, {} discarded from exclusion zones, {} cached",
                    (int) (((float) n_logs / (float) n_packets_db) * 100) + 1,
                    n_logs, n_discarded_logs_rate, n_discarded_logs_zones, device_cache_map.size()) << std::endl;

        auto ts = sqlite3_column_as<std::uint64_t>(p, 0);
        auto sourcemac = sqlite3_column_as<std::string>(p, 1);
        auto phy = sqlite3_column_as<std::string>(p, 2);

        auto lat = 0.0f, lon = 0.0f, alt = 0.0f;

        if (db_version < 5) {
            lat = sqlite3_column_as<double>(p, 3) / 100000;
            lon = sqlite3_column_as<double>(p, 4) / 100000;
        } else {
            lat = sqlite3_column_as<double>(p, 3);
            lon = sqlite3_column_as<double>(p, 4);
            alt = sqlite3_column_as<double>(p, 7);
        }

        auto ci = device_cache_map.find(sourcemac);
        std::shared_ptr<cache_obj> cached;

        if (ci != device_cache_map.end()) {
            cached = ci->second;
        } else {
            auto dev_query = _SELECT(db, "devices", {"device"},
                    _WHERE("devmac", EQ, sourcemac,
                        AND,
                        "phyname", EQ, phy));

            auto dev = dev_query.begin();

            if (dev == dev_query.end()) {
                // printf("Could not find device record for %s\n", sqlite3_column_as<std::string>(p, 0).c_str());
                continue;
            }

            // Check to see if we lie in any exclusion zones
            bool violates_exclusion = false;
            for (auto ez : exclusion_zones) {
                if (distance_meters(lat, lon, std::get<0>(ez), std::get<1>(ez)) <= std::get<2>(ez)) {
                    violates_exclusion = true;
                    break;
                }
            }

            if (violates_exclusion) {
                n_discarded_logs_zones++;
                continue;
            }

            nlohmann::json json;
            std::stringstream ss(sqlite3_column_as<std::string>(*dev, 0));

            try {
                ss >> json;

                auto timestamp = json["kismet.device.base.first_time"].get<uint64_t>();
                auto type = json["kismet.device.base.type"].get<std::string>();
                auto name = MungeForCSV(json["kismet.device.base.commonname"]);

                if (name == sourcemac)
                    name = "";

                std::time_t timet(timestamp);
                std::tm tm;
                std::stringstream ts;
                auto crypt = std::string{""};
                auto mod_type = std::string("");

                gmtime_r(&timet, &tm);

                char tmstr[256];
                strftime(tmstr, 255, "%Y-%m-%d %H:%M:%S", &tm);
                ts << tmstr;

                if (type == "BTLE") {
                    crypt = "Misc [LE]";
                    mod_type = "BLE";
                } else {
                    crypt = "Misc [BT]";
                    mod_type = "BT";
                }

                cached = std::make_shared<cache_obj>(ts.str(), name, crypt, mod_type);

                device_cache_map[sourcemac] = cached;

            } catch (const std::exception& e) {
                std::cerr <<
                    fmt::format("WARNING:  Could not process device info for {}/{}, skipping", sourcemac, phy) << std::endl;
            }
        }

        if (cached == nullptr)
            continue;

        // Rate throttle
        if (rate_limit != 0 && cached->last_time_sec != 0) {
            if (cached->last_time_sec + rate_limit < ts) {
                n_discarded_logs_rate++;
                continue;
            }
        }

        cached->last_time_sec = ts;

        fmt::print(ofile, "{},{},{},{},{},{},{:3.10f},{:3.10f},{:f},0,{}\n",
                sourcemac,
                cached->name,
                cached->crypto,
                cached->first_time,
                0, // channel always 0
                0, // currently no bt signal in kismet
                lat, lon, alt,
                cached->type);

        n_saved++;
    }


    if (ofile != stdout) {
        fclose(ofile);

    }

    sqlite3_close(db);

    if (n_saved == 0) {
        fmt::print(stderr, "ERROR: No records saved, not saving empty output file.  Your log file may have no\n"
                "packets with GPS information, no packets with recognized devices, or your exclusion\n"
                "options have blocked all possible packets ({} blocked by {} exclusion(s))\n",
                n_discarded_logs_zones, exclusion_zones.size());

        if (ofile != stdout)
            unlink(out_fname.c_str());

        exit(1);
    }

    if (verbose)  {
        fmt::print(stderr, "* Processed {} records, {} discarded from rate limiting, {} discarded from exclusion zones\n",
                n_logs, n_discarded_logs_rate, n_discarded_logs_zones);
        fmt::print(stderr, "* Done!\n");
    }

    return 0;
}

