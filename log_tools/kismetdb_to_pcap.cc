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
 * Convert a kismetdb log file to a pcap or pcapng file, for use with
 * wireshark/tshark/tcpdump/etc
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

#include "fmt.h"
#include "getopt.h"
#include "json/json.h"
#include "packet_ieee80211.h"
#include "pcapng.h"
#include "sqlite3_cpp11.h"
#include "version.h"

extern "C" {
#ifndef HAVE_PCAPPCAP_H
#include <pcap.h>
#else
#include <pcap/pcap.h>
#endif
}

size_t PAD_TO_32BIT(size_t in) {
    while (in % 4) in++;
    return in;
}

void print_help(char *argv) {
    printf("Kismetdb to pcap\n");
    printf("Convert packet data from KismetDB logs to standard pcap or pcapng logs for use in\n"
           "tools like Wireshark and tcpdump\n");
    printf("usage: %s [OPTION]\n", argv);
    printf(" -i, --in [filename]            Input kismetdb file\n"
           " -o, --out [filename]           Output file name\n"
           " -v, --verbose                  Verbose output\n"
           " -s, --skip-clean               Don't clean (sql vacuum) input database\n"
           "     --old-pcap                 Create a traditional pcap file\n"
           "                                Traditional PCAP files cannot have multiple link types.\n"
           "     --dlt [linktype #]         Limit pcap to a single DLT (link type); necessary when\n"
           "                                generating older traditional pcap instead of pcapng.\n"
           "     --list-datasources         List datasources in kismetdb; do not create a pcap file\n"
           "     --datasource [uuid]        Include packets from this datasource.  Multiple datasource\n"
           "                                arguments can be given to include multiple datasources.\n"
           "     --split-datasource         Split output into multiple files, with each file containing\n"
           "                                packets from a single datasource.\n"
           "     --split-packets [num]      Split output into multiple files, with each file containing\n"
           "                                at most [num] packets\n"
           "     --split-size [size-in-kb]  Split output into multiple files, with each file containing\n"
           "                                at most [kb] bytes\n"
           "\n"
           "When splitting output by datasource, the file will be named [outname]-[datasource-uuid].\n"
           "\n"
           "When splitting output into multiple files, file will be named [outname]-0001, \n"
           "[outname]-0002, and so forth.\n"
           "\n"
           "Output can be split by datasource, packet count, or file size.  These options can be\n"
           "combined as datasource and packet count, or datasource and file size.\n"
           "\n"
           "When splitting by both datasource and count or size, the files will be named \n"
           "[outname]-[datasource-uuid]-0001, and so on.\n"
          );
}

bool string_case_cmp(const std::string& a, const std::string& b) {
    if (a.size() != b.size())
        return false;

    for (size_t i = 0; i < a.size(); i++) {
        if (tolower(a[i]) != tolower(b[i]))
            return false;
    }

    return true;
}

class log_interface {
public:
    std::string uuid;
    unsigned int dlt;
    std::string cap_interface;
    unsigned int idb_id;
};

class log_file {
public:
    FILE *file;
    size_t sz;

    unsigned int count;
    unsigned int number;

    // map of uuid-dlt to record
    std::map<std::string, std::shared_ptr<log_interface>> ng_interface_map;
};

class db_interface {
public:
    std::string uuid;
    std::string typestring;
    std::string definition;
    std::string name;
    std::string interface;
    unsigned long num_packets;
    std::vector<int> dlts;
};

std::vector<int> get_dlts_per_datasouce(sqlite3 *db, const std::string& uuid) {
    using namespace kissqlite3;

    std::vector<int> ret;

    auto npackets_q = _SELECT(db, "packets", 
            {"distinct dlt"}, _WHERE("datasource", EQ, uuid));

    for (auto i : npackets_q) 
        ret.push_back(sqlite3_column_as<int>(i, 0));

    return ret;
}

void open_pcap_file(const std::string& path, FILE **pcap_file, bool force, unsigned int dlt) {
    struct stat statbuf;

    if (path != "-") {
        if (stat(path.c_str(), &statbuf) < 0) {
            if (errno != ENOENT) {
                throw std::runtime_error(fmt::format("Unexpected problem opening output "
                            "file '{}': {} (errno {})", path, strerror(errno), errno));
            }
        } else if (force == false) {
            throw std::runtime_error(fmt::format("Output file '{}' already exists, use --force "
                        "to overwrite existing files.", path));
        }
    }

    if (path == "-") {
        *pcap_file = stdout;
    } else {
        if ((*pcap_file = fopen(path.c_str(), "w")) == nullptr) 
            throw std::runtime_error(fmt::format("Error opening output file '{}': {} (errno {})",
                        path, strerror(errno), errno));
    }

    pcap_hdr_t pcap_hdr {
        .magic_number = PCAP_MAGIC,
        .version_major = PCAP_VERSION_MAJOR,
        .version_minor = PCAP_VERSION_MINOR,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = PCAP_MAX_SNAPLEN,
        .dlt = dlt
    };

    fwrite(&pcap_hdr, sizeof(pcap_hdr_t), 1, *pcap_file);
}

void open_pcapng_file(const std::string& path, FILE **pcapng_file, bool force) {
    struct stat statbuf;

    if (path != "-") {
        if (stat(path.c_str(), &statbuf) < 0) {
            if (errno != ENOENT) {
                throw std::runtime_error(fmt::format("Unexpected problem opening output "
                            "file '{}': {} (errno {})", path, strerror(errno), errno));
            }
        } else if (force == false) {
            throw std::runtime_error(fmt::format("Output file '{}' already exists, use --force "
                        "to overwrite existing files.", path));
        }
    }

    if (path != "-") {
        if (stat(path.c_str(), &statbuf) < 0) {
            if (errno != ENOENT) {
                throw std::runtime_error(fmt::format("Unexpected problem opening output "
                            "file '{}': {} (errno {})", path, strerror(errno), errno));
            }
        } else if (force == false) {
            throw std::runtime_error(fmt::format("Output file '{}' already exists, use --force "
                        "to overwrite existing files.", path));
        }
    }

    if (path == "-") {
        *pcapng_file = stdout;
    } else {
        if ((*pcapng_file = fopen(path.c_str(), "w")) == nullptr) 
            throw std::runtime_error(fmt::format("Error opening output file '{}': {} (errno {})",
                        path, strerror(errno), errno));
    }

    std::string app = fmt::format("Kismet kismetdb_to_pcapng {}-{}-{} {}",
            VERSION_MAJOR, VERSION_MINOR, VERSION_TINY, VERSION_GIT_COMMIT);

    size_t shb_sz = sizeof(pcapng_shb_t);
    shb_sz += sizeof(pcapng_option_t);
    shb_sz += sizeof(pcapng_option_t) + PAD_TO_32BIT(app.size());

    auto buf = new char[shb_sz];

    auto shb = reinterpret_cast<pcapng_shb_t *>(buf);

    shb->block_type = PCAPNG_SHB_TYPE_MAGIC;
    shb->block_length = shb_sz + 4;
    shb->block_endian_magic = PCAPNG_SHB_ENDIAN_MAGIC;
    shb->version_major = PCAPNG_SHB_VERSION_MAJOR;
    shb->version_minor = PCAPNG_SHB_VERSION_MINOR;
    shb->section_length = -1;

    auto opt = reinterpret_cast<pcapng_option_t *>(shb->options);
    opt->option_code = PCAPNG_OPT_SHB_USERAPPL;
    opt->option_length = app.size();
    memcpy(opt->option_data, app.data(), app.size());

    opt = reinterpret_cast<pcapng_option_t *>(shb->options + sizeof(pcapng_option_t) + 
            PAD_TO_32BIT(app.size()));
    opt->option_code = PCAPNG_OPT_ENDOFOPT;
    opt->option_length = 0;

    uint32_t end_sz = shb_sz + 4;

    // Write the SHB, options, and the second copy of the length
    fwrite(buf, shb_sz, 1, *pcapng_file);
    fwrite(&end_sz, sizeof(uint32_t), 1, *pcapng_file);
}

int main(int argc, char *argv[]) {
#define OPT_LIST                1
#define OPT_INTERFACE           2
#define OPT_SPLIT_PKTS          3
#define OPT_SPLIT_SIZE          4
#define OPT_SPLIT_INTERFACE     5
#define OPT_OLD_PCAP            6
#define OPT_DLT                 7
    static struct option longopt[] = {
        { "in", required_argument, 0, 'i' },
        { "out", required_argument, 0, 'o' },
        { "verbose", no_argument, 0, 'v' },
        { "help", no_argument, 0, 'h' },
        { "skip-clean", no_argument, 0, 's' },
        { "old-pcap", no_argument, 0, OPT_OLD_PCAP },
        { "list-datasources", no_argument, 0, OPT_LIST },
        { "datasource", required_argument, 0, OPT_INTERFACE },
        { "split-datasource", no_argument, 0, OPT_SPLIT_INTERFACE },
        { "split-packets", required_argument, 0, OPT_SPLIT_PKTS },
        { "split-size", required_argument, 0, OPT_SPLIT_SIZE },
        { "dlt", required_argument, 0, OPT_DLT },
        { 0, 0, 0, 0 }
    };

    int option_idx = 0;
    optind = 0;
    opterr = 0;

    std::string in_fname, out_fname;
    bool verbose = false;
    bool force = false;
    bool skipclean = false;
    bool pcapng = true;
    bool list_only = false;
    unsigned int split_packets = 0;
    unsigned int split_size = 0;
    bool split_interface = false;
    std::vector<std::string> raw_interface_vec;
    int dlt = -1;

    int sql_r = 0;
    char *sql_errmsg = NULL;
    sqlite3 *db = NULL;

    // Derived interfaces
    std::vector<std::shared_ptr<db_interface>> interface_vec;
    std::vector<std::shared_ptr<db_interface>> logging_interface_vec;

    // Single logs
    std::map<std::string, std::shared_ptr<log_interface>> ng_interface_map;
    FILE *ofile = NULL;
    size_t log_sz = 0;
    unsigned int log_packets = 0;

    // Per-interface logs
    std::map<std::string, std::shared_ptr<log_file>> per_interface_logs;

    struct stat statbuf;

    while (1) {
        int r = getopt_long(argc, argv, 
                            "-hi:o:vhsn", 
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
        } else if (r == 's') {
            skipclean = true;
        } else if (r == OPT_SPLIT_PKTS) {
            if (sscanf(optarg, "%u", &split_packets) != 1) {
                fmt::print(stderr, "ERROR:  Expected --split-packets [number]\n");
                exit(1);
            }
        } else if (r == OPT_SPLIT_SIZE) {
            if (sscanf(optarg, "%u", &split_size) != 1) {
                fmt::print(stderr, "ERROR:  Expected --split-size [size-in-kb]\n");
                exit(1);
            }
        } else if (r == OPT_SPLIT_INTERFACE) {
            split_interface = true;
        } else if (r == OPT_LIST) {
            list_only = true;
        } else if (r == OPT_INTERFACE) {
            raw_interface_vec.push_back(std::string(optarg));
        } else if (r == OPT_OLD_PCAP) {
            pcapng = false;
        } else if (r == OPT_DLT) {
            unsigned int u;
            if (sscanf(optarg, "%u", &u) != 1) {
                fmt::print(stderr, "ERROR: Expected --dlt [dlt number]\n");
                exit(1);
            }
            dlt = static_cast<int>(u);
        }
    }

    if (split_packets && split_size) {
        fmt::print(stderr, "ERROR: You can split by number of packets, or by file size, but not both\n"
                           "       at the same time.\n");
        exit(1);
    }

    if ((out_fname == "" || in_fname == "") && !list_only) {
        fmt::print(stderr, "ERROR: Expected --in [kismetdb file] and --out [pcap file]\n");
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
        if (verbose)
            fmt::print(stderr, "* Preparing input database '{}'...\n", in_fname);

        sql_r = sqlite3_exec(db, "VACUUM;", NULL, NULL, &sql_errmsg);

        if (sql_r != SQLITE_OK) {
            fmt::print(stderr, "ERROR:  Unable to clean up (vacuum) database before copying: {}\n", 
                    sql_errmsg);
            sqlite3_close(db);
            exit(1);
        }
    }

    using namespace kissqlite3;

    int db_version = 0;

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

    } catch (const std::exception& e) {
        fmt::print(stderr, "ERROR:  Could not get database information from '{}': {}\n", in_fname, e.what());
        exit(0);
    }

    try {
        if (verbose)
            fmt::print(stderr, "* Collecting info about datasources...\n");

        auto interface_query = _SELECT(db, "datasources", 
                {"uuid", "typestring", "definition", "name", "interface"});
     
        for (auto q : interface_query) {
            auto dbsource = std::make_shared<db_interface>();
            dbsource->uuid = sqlite3_column_as<std::string>(q, 0);
            dbsource->typestring = sqlite3_column_as<std::string>(q, 1);
            dbsource->definition = sqlite3_column_as<std::string>(q, 2);
            dbsource->name = sqlite3_column_as<std::string>(q, 3);
            dbsource->interface = sqlite3_column_as<std::string>(q, 4);

            // Get the total counts
            auto npackets_q = _SELECT(db, "packets", 
                    {"count(*)"}, 
                    _WHERE("datasource", EQ, dbsource->uuid));
            auto npackets_ret = npackets_q.begin();
            if (npackets_ret == npackets_q.end()) {
                fmt::print(stderr, "ERROR:  Unable to fetch packet count for datasource {} {} ({}).\n",
                        dbsource->uuid, dbsource->name, dbsource->interface);
                sqlite3_close(db);
                exit(1);
            }
            dbsource->num_packets = sqlite3_column_as<unsigned long>(*npackets_ret, 0);

            dbsource->dlts = get_dlts_per_datasouce(db, dbsource->uuid);

            interface_vec.push_back(dbsource);
        }

    } catch (const std::exception& e) {
        fmt::print(stderr, "ERROR:  Could not get datasources from '{}': {}\n", in_fname, e.what());
        exit(0);
    }

    if (list_only) {
        int ifnum = 0;

        for (auto i : interface_vec) {
            fmt::print("Datasource #{} ({} {} {}) {} packets\n", 
                    ifnum++, i->uuid, i->name, i->interface, i->num_packets);
            for (auto d : i->dlts) {
                fmt::print("   DLT {}: {} {}\n",
                        d, pcap_datalink_val_to_name(d), pcap_datalink_val_to_description(d));
            }

            if (i->dlts.size() == 0) 
                fmt::print("    No packets seen by this datasource\n");
        }

        exit(0);
    }

    if (raw_interface_vec.size() != 0) {
        for (auto i : raw_interface_vec) {
            bool ok = false;

            for (auto dbi : interface_vec) {
                if (string_case_cmp(dbi->uuid, i)) {
                    logging_interface_vec.push_back(dbi);
                    ok = true;
                    break;
                }
            }

            if (!ok) {
                fmt::print(stderr, "ERROR:  Could not find a datasource with UUID '{}' in {}\n",
                        i, in_fname);
                exit(0);
            }
        }
    } else {
        logging_interface_vec = interface_vec;
    }

    // Confirm interfaces are OK for this type of output; we can't mix DLT on pcap, even if
    // we split interfaces.
    if (!pcapng && raw_interface_vec.size() != 0) {
        int common_dlt = -1;

        for (auto i : logging_interface_vec) {
            if (i->dlts.size() == 0)
                continue;

            if (i->dlts.size() > 1 && dlt == -1) {
                fmt::print(stderr, "ERROR:  Datasource {} {} ({}) has multiple link types; when "
                        "logging to a legacy pcap file, only one link type can be used; specify "
                        "a link type with the --dlt argument.\n",
                        i->uuid, i->name, i->interface);
                exit(0);
            }

            if (common_dlt == -1) {
                common_dlt = i->dlts[0];
                continue;
            }

            if (common_dlt != i->dlts[0] && dlt == -1 && !split_interface) {
                fmt::print(stderr, "ERROR:  Datasource {} {} ({}) has a DLT of {} {} ({}), while "
                        "another datasource has a DLT of {} {} ({}).  Only one DLT is supported "
                        "per file in legacy pcap mode; use pcapng, split by datasource, or "
                        "specify a single DLT to support.\n",
                        i->uuid, i->name, i->interface,
                        i->dlts[0], pcap_datalink_val_to_name(i->dlts[0]),
                        pcap_datalink_val_to_description(i->dlts[0]),
                        common_dlt, pcap_datalink_val_to_name(common_dlt),
                        pcap_datalink_val_to_description(common_dlt));
                exit(0);
            }
        }
    }


    // Assemble the where clause for how we grab packets
    auto packet_filter_q = _WHERE();

    // If we've specified an exact DLT
    if (dlt >= 0) 
        packet_filter_q = _WHERE(packet_filter_q, AND, "dlt", EQ, dlt);

    // If we're filtering by specific UUID...
    if (raw_interface_vec.size() != 0) {
        auto uuid_clause = _WHERE();

        for (auto i : logging_interface_vec)
            uuid_clause = _WHERE(uuid_clause, OR, "uuid", LIKE, i->uuid);

        packet_filter_q = _WHERE(packet_filter_q, AND, uuid_clause);
    }

    sqlite3_close(db);

    return 0;
}

