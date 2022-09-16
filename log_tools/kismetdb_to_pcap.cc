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

#include <algorithm>
#include <map>
#include <iomanip>
#include <ctime>
#include <iostream>
#include <tuple>
#include <string>

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sqlite3.h>

#include "endian_magic.h"
#include "fmt.h"
#include "getopt.h"
#include "nlohmann/json.hpp"
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

/* pcapng and ppi conversions */

/*
 * input: a signed floating point value between -180.0000000 and + 180.0000000, inclusive)
 * output: a unsigned 32-bit (native endian) value between 0 and 3600000000 (inclusive)
 */
u_int32_t double_to_fixed3_7(double in) 
{
    if (in < -180 || in >= 180) 
        return 0;
    //This may be positive or negative.
    int32_t scaled_in =  (int32_t) ((in) * (double) 10000000); 
    //If the input conditions are met, this will now always be positive.
    u_int32_t  ret = (u_int32_t) (scaled_in +  ((int32_t) 180 * 10000000)); 
    return ret;
}
/*
 * input: a signed floating point value between -180000.0000 and + 180000.0000, inclusive)
 * output: a unsigned 32-bit (native endian) value between 0 and 3600000000 (inclusive)
 */
u_int32_t double_to_fixed6_4(double in) 
{
    if (in < -180000.0001 || in >= 180000.0001) 
        return 0;
    //This may be positive or negative.
    int32_t scaled_in =  (int32_t) ((in) * (double) 10000); 
    //If the input conditions are met, this will now always be positive.
    u_int32_t  ret = (u_int32_t) (scaled_in +  ((int32_t) 180000 * 10000)); 
    return ret;
}
/*
 * input: a positive floating point value between 000.0000000 and 999.9999999
 * output: a native 32 bit unsigned value between 0 and 999999999
 */
u_int32_t double_to_fixed3_6(double in) {
    u_int32_t ret = (u_int32_t) (in  * (double) 1000000.0);
    return ret;
}

/*
 * input: a signed floating point second counter
 * output: a native 32 bit nano-second counter
 */
u_int32_t double_to_ns(double in) {
    u_int32_t ret;
    ret =  in * (double) 1000000000;
    return ret;
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

/* Log file we're processing */

class log_file {
public:
    log_file() {
        file = nullptr;
        sz = 0;
        count = 0;
        number = 0;
    }

    std::string name;

    FILE *file;
    size_t sz;

    unsigned int count;
    unsigned int number;

    // map of uuid-dlt to record
    std::map<std::string, unsigned int> ng_interface_map;
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

FILE *open_pcap_file(const std::string& path, bool force, unsigned int dlt) {
    struct stat statbuf;
    FILE *pcap_file;

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
        pcap_file = stdout;
    } else {
        if ((pcap_file = fopen(path.c_str(), "w")) == nullptr) 
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

    if (fwrite(&pcap_hdr, sizeof(pcap_hdr_t), 1, pcap_file) != 1)
        throw std::runtime_error(fmt::format("Error writing pcap header: {} (errno {})",
                    strerror(errno), errno));

    return pcap_file;
}

void write_pcap_packet(FILE *pcap_file, const std::string& packet,
        unsigned long ts_sec, unsigned long ts_usec) {
    pcap_packet_hdr_t hdr;
    hdr.ts_sec = ts_sec;
    hdr.ts_usec = ts_usec;
    hdr.incl_len = packet.size();
    hdr.orig_len = packet.size();

    if (fwrite(&hdr, sizeof(pcap_packet_hdr_t), 1, pcap_file) != 1)
        throw std::runtime_error(fmt::format("error writing pcap packet: {} (errno {})",
                    strerror(errno), errno));

    if (fwrite(packet.data(), packet.size(), 1, pcap_file) != 1)
        throw std::runtime_error(fmt::format("error writing pcap packet: {} (errno {})",
                    strerror(errno), errno));
}


FILE *open_pcapng_file(const std::string& path, bool force) {
    struct stat statbuf;
    FILE *pcapng_file;

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
        pcapng_file = stdout;
    } else {
        if ((pcapng_file = fopen(path.c_str(), "w")) == nullptr) 
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

    // Write the SHB, options, and the second copy of the length
    if (fwrite(buf, shb_sz, 1, pcapng_file) != 1)
        throw std::runtime_error(fmt::format("error writing pcapng header: {} (errno {})",
                    strerror(errno), errno));

    shb_sz += 4;
    
    if (fwrite(&shb_sz, 4, 1, pcapng_file) != 1)
        throw std::runtime_error(fmt::format("error writing pcapng header: {} (errno {})",
                    strerror(errno), errno));

    return pcapng_file;
}

void write_pcapng_interface(FILE *pcapng_file, unsigned int ngindex, const std::string& interface, 
        unsigned int dlt, const std::string& description) {

    size_t idb_sz = sizeof(pcapng_idb_t) + sizeof(pcapng_option_t);
    idb_sz += sizeof(pcapng_option_t) + PAD_TO_32BIT(interface.length());
    idb_sz += sizeof(pcapng_option_t) + PAD_TO_32BIT(description.length());

    auto buf = new char[idb_sz];
    auto idb = reinterpret_cast<pcapng_idb *>(buf);

    size_t opt_offt = 0;

    idb->block_type = PCAPNG_IDB_BLOCK_TYPE;
    idb->block_length = idb_sz + 4;
    idb->dlt = dlt;
    idb->reserved = 0;
    idb->snaplen = 65535;

    pcapng_option_t *opt = reinterpret_cast<pcapng_option_t *>(idb->options + opt_offt);
    opt->option_code = PCAPNG_OPT_IDB_IFNAME;
    opt->option_length = interface.length();
    memcpy(opt->option_data, interface.c_str(), interface.length());
    opt_offt += sizeof(pcapng_option_t) + PAD_TO_32BIT(interface.length());

    opt = reinterpret_cast<pcapng_option_t *>(idb->options + opt_offt);
    opt->option_code = PCAPNG_OPT_IDB_IFDESC;
    opt->option_length = description.length();
    memcpy(opt->option_data, description.c_str(), description.length());
    opt_offt += sizeof(pcapng_option_t) + PAD_TO_32BIT(description.length());

    opt = reinterpret_cast<pcapng_option_t *>(idb->options + opt_offt);
    opt->option_code = PCAPNG_OPT_ENDOFOPT;
    opt->option_length = 0;

    if (fwrite(buf, idb_sz, 1, pcapng_file) != 1)
        throw std::runtime_error(fmt::format("error writing pcapng interface block: {} (errno {})",
                strerror(errno), errno));

    idb_sz += 4;

    if (fwrite(&idb_sz, 4, 1, pcapng_file) != 1)
        throw std::runtime_error(fmt::format("error writing pcapng interface block: {} (errno {}))",
                    strerror(errno), errno));
}

void write_pcapng_gps(FILE *pcapng_file, unsigned long ts_sec, unsigned long ts_usec, 
        double lat, double lon, double alt) {

    if (lat == 0 || lon == 0)
        return;

    pcapng_custom_block cb;

    auto gps_sz = sizeof(kismet_pcapng_gps_chunk_t);

    // lat, lon, and timesttamps
    gps_sz += 16;

    if (alt != 0)
        gps_sz += 4;

    auto data_sz = sizeof(pcapng_custom_block) + PAD_TO_32BIT(gps_sz) + sizeof(pcapng_option_t);

    cb.block_type = PCAPNG_CB_BLOCK_TYPE;
    cb.block_length = data_sz + 4;
    cb.custom_pen = KISMET_IANA_PEN;

    if (fwrite(&cb, sizeof(pcapng_custom_block_t), 1, pcapng_file) != 1)
        throw std::runtime_error(fmt::format("error writing pcapng gps packet header: {} (errno {})",
                strerror(errno), errno));

    kismet_pcapng_gps_chunk_t gps;

    gps.gps_magic = PCAPNG_GPS_MAGIC;
    gps.gps_verison = PCAPNG_GPS_VERSION;
    gps.gps_len = 16; // lat, lon, tsh, tsl
    gps.gps_fields_present = PCAPNG_GPS_FLAG_LON | PCAPNG_GPS_FLAG_LAT |
        PCAPNG_GPS_TS_HIGH | PCAPNG_GPS_TS_LOW;

    if (alt != 0) {
        gps.gps_len += 4;
        gps.gps_fields_present |= PCAPNG_GPS_FLAG_ALT;
    }

    // GPS header
    if (fwrite(&gps, sizeof(kismet_pcapng_gps_chunk_t), 1, pcapng_file) != 1)
        throw std::runtime_error(fmt::format("error writing packet gps options: {} (errno {})",
                    strerror(errno), errno));

    union block {
        uint8_t u8;
        uint16_t u16;
        uint32_t u32;
    } u;

    // Lon, lat, [alt]
    u.u32 = double_to_fixed3_7(lon);
    if (fwrite(&u, sizeof(uint32_t), 1, pcapng_file) != 1) 
        throw std::runtime_error(fmt::format("error writing packet gps: {} (errno {})",
                    strerror(errno), errno));

    u.u32 = double_to_fixed3_7(lat);
    if (fwrite(&u, sizeof(uint32_t), 1, pcapng_file) != 1) 
        throw std::runtime_error(fmt::format("error writing packet gps: {} (errno {})",
                    strerror(errno), errno));

    if (alt != 0) {
        u.u32 = double_to_fixed6_4(alt);
        if (fwrite(&u, sizeof(uint32_t), 1, pcapng_file) != 1) 
            throw std::runtime_error(fmt::format("error writing packet gps: {} (errno {})",
                        strerror(errno), errno));
    }

    // TS high and low
    uint64_t conv_ts = ((uint64_t) ts_sec * 1'000'000L) + ts_usec;

    u.u32 = (conv_ts >> 32);
    if (fwrite(&u, sizeof(uint32_t), 1, pcapng_file) != 1) 
        throw std::runtime_error(fmt::format("error writing packet gps: {} (errno {})",
                    strerror(errno), errno));

    u.u32 = conv_ts;
    if (fwrite(&u, sizeof(uint32_t), 1, pcapng_file) != 1) 
        throw std::runtime_error(fmt::format("error writing packet gps: {} (errno {})",
                    strerror(errno), errno));

    uint32_t pad = 0;
    auto pad_sz = PAD_TO_32BIT(gps.gps_len) - gps.gps_len;

    if (pad_sz > 0)
        if (fwrite(&pad, pad_sz, 1, pcapng_file) != 1)
            throw std::runtime_error(fmt::format("error writing pcapng packet option: {} (errno {})",
                        strerror(errno), errno));

    // No options
    pcapng_option_t opt;
    opt.option_code = PCAPNG_OPT_ENDOFOPT;
    opt.option_length = 0;

    if (fwrite(&opt, sizeof(pcapng_option_t), 1, pcapng_file) != 1) 
        throw std::runtime_error(fmt::format("error writing packet end-of-options: {} (errno {})",
                    strerror(errno), errno));

    data_sz += 4;

    if (fwrite(&data_sz, 4, 1, pcapng_file) != 1)
        throw std::runtime_error(fmt::format("error writing packet end-of-packet: {} (errno {})",
                    strerror(errno), errno));

}

void write_pcapng_packet(FILE *pcapng_file, const std::string& packet,
        unsigned long ts_sec, unsigned long ts_usec, const std::string& tag,
        unsigned int ngindex, double lat, double lon, double alt) {

    // Assemble the packet in the file in steps to avoid another memcpy
    pcapng_epb_t epb;

    // Always allocate an end-of-options option
    auto data_sz = sizeof(pcapng_epb_t) + PAD_TO_32BIT(packet.size()) + sizeof(pcapng_option_t);

    // Comment tag
    if (tag.length() > 0) 
        data_sz += sizeof(pcapng_option_t) + PAD_TO_32BIT(tag.length());

    if (lat != 0 && lon != 0) {
        // GPS header structure
        size_t gps_len = sizeof(kismet_pcapng_gps_chunk_t);

        // Lat, lon
        gps_len += 8;

        // Altitude
        if (alt != 0) {
            gps_len += 4;
        }

        data_sz += sizeof(pcapng_custom_option_t) + PAD_TO_32BIT(gps_len);
    }

    epb.block_type = PCAPNG_EPB_BLOCK_TYPE;
    epb.block_length = data_sz + 4;
    epb.interface_id = ngindex;

    uint64_t conv_ts = ((uint64_t) ts_sec * 1'000'000L) + ts_usec;
    epb.timestamp_high = (conv_ts >> 32);
    epb.timestamp_low = conv_ts;

    epb.captured_length = packet.size();
    epb.original_length = packet.size();

    if (fwrite(&epb, sizeof(pcapng_epb_t), 1, pcapng_file) != 1)
        throw std::runtime_error(fmt::format("error writing pcapng packet header: {} (errno {})",
                strerror(errno), errno));

    if (fwrite(packet.data(), packet.size(), 1, pcapng_file) != 1)
        throw std::runtime_error(fmt::format("error writing pcapng packet content: {} (errno {})",
                    strerror(errno), errno));

    // Data has to be 32bit padded
    uint32_t pad = 0;
    size_t pad_sz = 0;

    pad_sz = PAD_TO_32BIT(packet.size()) - packet.size();

    if (pad_sz > 0)
        if (fwrite(&pad, pad_sz, 1, pcapng_file) != 1)
            throw std::runtime_error(fmt::format("error writing pcapng packet padding: {} (errno {})",
                        strerror(errno), errno));

    pcapng_option_t opt;

    if (tag.length() > 0) {
        opt.option_code = PCAPNG_OPT_COMMENT;
        opt.option_length = tag.length();

        if (fwrite(&opt, sizeof(pcapng_option_t), 1, pcapng_file) != 1) 
            throw std::runtime_error(fmt::format("error writing pcapng packet option: {} (errno {})",
                        strerror(errno), errno));

        if (fwrite(tag.c_str(), tag.length(), 1, pcapng_file) != 1)
            throw std::runtime_error(fmt::format("error writing pcapng packet option: {} (errno {})",
                        strerror(errno), errno));

        pad_sz = PAD_TO_32BIT(tag.length()) - tag.length();

        if (pad_sz > 0)
            if (fwrite(&pad, pad_sz, 1, pcapng_file) != 1)
                throw std::runtime_error(fmt::format("error writing pcapng packet option: {} (errno {})",
                            strerror(errno), errno));
    }

    // If we have gps data, tag the packet with a kismet custom GPS entry under the kismet PEN
    if (lat != 0 && lon != 0) {
        pcapng_custom_option_t copt;
        uint32_t gps_fields = 0;

        copt.option_code = PCAPNG_OPT_CUSTOM_BINARY;
        copt.option_pen = KISMET_IANA_PEN;

        // lon, lat
        size_t gps_len = 8;

        gps_fields = PCAPNG_GPS_FLAG_LON | PCAPNG_GPS_FLAG_LAT;

        // Altitude
        if (alt != 0) {
            gps_len += 4;
            gps_fields |= PCAPNG_GPS_FLAG_ALT;
        }

        // PEN + gps header + content, without padding
        copt.option_length = 4 + sizeof(kismet_pcapng_gps_chunk_t) + gps_len;

        // Make a runt header since we can stream out the content
        kismet_pcapng_gps_chunk_t gps;

        gps.gps_magic = PCAPNG_GPS_MAGIC;
        gps.gps_verison = PCAPNG_GPS_VERSION;
        gps.gps_len = gps_len;
        gps.gps_fields_present = gps_fields;

        // Option + PEN custom option header
        if (fwrite(&copt, sizeof(pcapng_custom_option_t), 1, pcapng_file) != 1)
            throw std::runtime_error(fmt::format("error writing packet gps options: {} (errno {})",
                        strerror(errno), errno));

        // GPS header
        if (fwrite(&gps, sizeof(kismet_pcapng_gps_chunk_t), 1, pcapng_file) != 1)
            throw std::runtime_error(fmt::format("error writing packet gps options: {} (errno {})",
                        strerror(errno), errno));

        union block {
            uint8_t u8;
            uint16_t u16;
            uint32_t u32;
        } u;

        // Lon, lat, [alt]
        u.u32 = double_to_fixed3_7(lon);
        if (fwrite(&u, sizeof(uint32_t), 1, pcapng_file) != 1) 
            throw std::runtime_error(fmt::format("error writing packet gps: {} (errno {})",
                        strerror(errno), errno));

        u.u32 = double_to_fixed3_7(lat);
        if (fwrite(&u, sizeof(uint32_t), 1, pcapng_file) != 1) 
            throw std::runtime_error(fmt::format("error writing packet gps: {} (errno {})",
                        strerror(errno), errno));

        if (alt != 0) {
            u.u32 = double_to_fixed6_4(alt);
            if (fwrite(&u, sizeof(uint32_t), 1, pcapng_file) != 1) 
                throw std::runtime_error(fmt::format("error writing packet gps: {} (errno {})",
                            strerror(errno), errno));
        }

        pad_sz = PAD_TO_32BIT(copt.option_length) - copt.option_length;

        if (pad_sz > 0)
            if (fwrite(&pad, pad_sz, 1, pcapng_file) != 1)
                throw std::runtime_error(fmt::format("error writing pcapng packet option: {} (errno {})",
                            strerror(errno), errno));
    }

    opt.option_code = PCAPNG_OPT_ENDOFOPT;
    opt.option_length = 0;

    if (fwrite(&opt, sizeof(pcapng_option_t), 1, pcapng_file) != 1) 
        throw std::runtime_error(fmt::format("error writing packet end-of-options: {} (errno {})",
                    strerror(errno), errno));

    data_sz += 4;

    if (fwrite(&data_sz, 4, 1, pcapng_file) != 1)
        throw std::runtime_error(fmt::format("error writing packet end-of-packet: {} (errno {})",
                    strerror(errno), errno));
}
    

void print_help(char *argv) {
    printf("Kismetdb to pcap\n");
    printf("Convert packet data from KismetDB logs to standard pcap or pcapng logs for use in\n"
           "tools like Wireshark and tcpdump\n");
    printf("usage: %s [OPTION]\n", argv);
    printf(" -i, --in [filename]            Input kismetdb file\n"
           " -o, --out [filename]           Output file name\n"
           " -f, --force                    Overwrite any existing output files\n"
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
           "     --list-tags                List tags in kismetdb; do not create a pcap file\n"
           "     --tag [tag]                Only export packets which have a specific tag\n"
           "                                Specify multiple --tag options to include all packets with\n"
           "                                those tags.\n"
           "     --skip-gps                 When generating pcapng logs, don't include GPS information\n"
           "                                via the Kismet PEN custom fields\n"
           "     --skip-gps-track           When generating pcapng logs, don't include GPS movement\n"
           "                                track information\n"
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

int main(int argc, char *argv[]) {
#define OPT_LIST                1
#define OPT_INTERFACE           2
#define OPT_SPLIT_PKTS          3
#define OPT_SPLIT_SIZE          4
#define OPT_SPLIT_INTERFACE     5
#define OPT_OLD_PCAP            6
#define OPT_DLT                 7
#define OPT_SKIP_GPS            8
#define OPT_SKIP_GPSTRACK       9
#define OPT_LIST_TAGS           10
#define OPT_FILTER_TAG          11
    static struct option longopt[] = {
        { "in", required_argument, 0, 'i' },
        { "out", required_argument, 0, 'o' },
        { "verbose", no_argument, 0, 'v' },
        { "help", no_argument, 0, 'h' },
        { "skip-clean", no_argument, 0, 's' },
        { "force", no_argument, 0, 'f' },
        { "old-pcap", no_argument, 0, OPT_OLD_PCAP },
        { "list-datasources", no_argument, 0, OPT_LIST },
        { "list-tags", no_argument, 0, OPT_LIST_TAGS },
        { "tag", required_argument, 0, OPT_FILTER_TAG },
        { "datasource", required_argument, 0, OPT_INTERFACE },
        { "split-datasource", no_argument, 0, OPT_SPLIT_INTERFACE },
        { "split-packets", required_argument, 0, OPT_SPLIT_PKTS },
        { "split-size", required_argument, 0, OPT_SPLIT_SIZE },
        { "dlt", required_argument, 0, OPT_DLT },
        { "skip-gps", no_argument, 0, OPT_SKIP_GPS },
        { "skip-gps-track", no_argument, 0, OPT_SKIP_GPSTRACK },
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
    bool skip_gps = false;
    bool skip_gps_track = false;
    bool list_tags = false;
    unsigned int split_packets = 0;
    unsigned int split_size = 0;
    bool split_interface = false;
    std::vector<std::string> raw_interface_vec;
    int dlt = -1;
    std::map<std::string, bool> tag_filter_map;

    int sql_r = 0;
    char *sql_errmsg = NULL;
    sqlite3 *db = NULL;

    // Derived interfaces
    std::vector<std::shared_ptr<db_interface>> interface_vec;
    std::vector<std::shared_ptr<db_interface>> logging_interface_vec;

    // Log states
    std::map<std::string, std::shared_ptr<log_file>> per_interface_logs;
    std::shared_ptr<log_file> single_log = std::make_shared<log_file>();

    struct stat statbuf;

    while (1) {
        int r = getopt_long(argc, argv, 
                            "-hi:o:vhsnf", 
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
        } else if (r == OPT_LIST_TAGS) {
            list_only = true;
            list_tags = true;
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
        } else if (r == OPT_FILTER_TAG) {
            auto str = std::string(optarg);
            std::transform(str.begin(), str.end(), str.begin(), ::toupper);
            tag_filter_map[str] = true;
        } else if (r == OPT_SKIP_GPS) {
            fmt::print(stderr, "Skipping all GPS data\n");
            skip_gps = true;
        } else if (r == OPT_SKIP_GPSTRACK) {
            fmt::print(stderr, "Skipping GPS movement/track data\n");
            skip_gps_track = true;
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

    if (in_fname == "") {
        fmt::print(stderr, "ERROR:  Expected --in [kismetdb file]\n");
        exit(1);
    }

    if ((split_packets || split_size) && out_fname == "-") {
        fmt::print(stderr, "ERROR: Cannot split by packets or size when outputting to stdout\n");
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

    if (verbose) {
        try {
            auto data_q = _SELECT(db, "data", {"ts_sec"}, LIMIT, 1);
            if (data_q.begin() != data_q.end()) {
                fmt::print(stderr, "WARNING: KismetDB log contains non-packet data logs from datasources\n"
                        "which do not support traditional pcap, they will not currently be included\n"
                        "in the generated pcap file.\n");
            }
        } catch (...) {

        }
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

    if (list_tags) {
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

        if (tag_map.size() == 0) {
            fmt::print("No tagged packets found in log.\n");
            exit(0);
        }

        fmt::print("Packet tags found in log:\n");

        for (auto ti : tag_map) {
            fmt::print("    {}\n", ti.first);
        }

        exit(0);
    } else if (list_only) {
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

            if (i->dlts[0] != dlt && dlt != -1) {
                fmt::print(stderr, "ERROR:  Datasource {} {} ({}) specifically included, but "
                        "has a DLT of {} {} ({}), while the DLT {} {} ({}) was specified.  "
                        "Packets from this source will be ignored.\n",
                        i->uuid, i->name, i->interface,
                        i->dlts[0], pcap_datalink_val_to_name(i->dlts[0]),
                        pcap_datalink_val_to_description(i->dlts[0]),
                        common_dlt, pcap_datalink_val_to_name(common_dlt),
                        pcap_datalink_val_to_description(common_dlt));
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
            uuid_clause = _WHERE(uuid_clause, OR, "datasource", LIKE, i->uuid);

        packet_filter_q = _WHERE(packet_filter_q, AND, uuid_clause);
    }

    std::list<std::string> packet_fields;
    if (db_version < 6) {
        packet_fields = 
            std::list<std::string>{"ts_sec", "ts_usec", "dlt", "datasource", "packet", "lat", "lon", "alt"};
    } else {
        packet_fields = 
            std::list<std::string>{"ts_sec", "ts_usec", "dlt", "datasource", "packet", "lat", "lon", "alt", "tags"};
    }

    auto packets_q = _SELECT(db, "packets", 
            packet_fields,
            packet_filter_q);

    if (tag_filter_map.size() != 0) {
        for (auto ti : tag_filter_map) {
            packets_q.append_where(AND, _WHERE("tags", LIKE, fmt::format("%{}%", ti.first)));
        }
    }

    auto gps_q = _SELECT(db, "snapshots",
            {"ts_sec", "ts_usec", "json"},
            _WHERE("snaptype", EQ, "GPS"));

    auto pkt = packets_q.begin();
    auto gps = gps_q.begin();

    if (skip_gps_track)
        gps = gps_q.end();

    uint64_t pkt_time = 0, pkt_time_us = 0;
    uint64_t gps_time = 0, gps_time_us = 0;

    try {
        while (pkt != packets_q.end() || gps != gps_q.end()) {
            if (pkt_time == 0 && pkt != packets_q.end()) {
                pkt_time = sqlite3_column_as<unsigned long>(*pkt, 0);
                pkt_time_us = sqlite3_column_as<unsigned long>(*pkt, 1);
            }

            if (!skip_gps_track && gps_time == 0 && gps != gps_q.end()) {
                gps_time = sqlite3_column_as<unsigned long>(*gps, 0);
                gps_time_us = sqlite3_column_as<unsigned long>(*gps, 1);
            }

            if (pkt_time != 0 && (gps_time == 0 || (pkt_time < gps_time || 
                            ((pkt_time == gps_time && pkt_time_us < gps_time_us))))) {
                auto ts_sec = sqlite3_column_as<unsigned long>(*pkt, 0);
                auto ts_usec = sqlite3_column_as<unsigned long>(*pkt, 1);
                auto pkt_dlt = sqlite3_column_as<unsigned int>(*pkt, 2);
                auto datasource = sqlite3_column_as<std::string>(*pkt, 3);
                auto bytes = sqlite3_column_as<std::string>(*pkt, 4);
                auto lat = sqlite3_column_as<double>(*pkt, 5);
                auto lon = sqlite3_column_as<double>(*pkt, 6);
                auto alt = sqlite3_column_as<double>(*pkt, 7);

                std::string tags;

                if (db_version >= 6)
                    tags = sqlite3_column_as<std::string>(*pkt, 8);

                if (!pcapng) {
                    std::shared_ptr<log_file> log_interface;

                    if (split_interface) {
                        auto log_index = per_interface_logs.find(datasource);

                        if (log_index == per_interface_logs.end()) {
                            log_interface = std::make_shared<log_file>();
                            per_interface_logs[datasource] = log_interface;
                        } else {
                            log_interface = log_index->second;
                        }

                    } else {
                        log_interface = single_log;
                    }

                    if (log_interface->file == nullptr) {
                        int file_dlt = dlt;

                        if (file_dlt < 0)
                            file_dlt = pkt_dlt;

                        auto fname = out_fname;

                        if (split_interface)
                            fname = fmt::format("{}-{}", fname, datasource);

                        if (split_packets || split_size) {
                            fname = fmt::format("{}-{:06}", fname, log_interface->number);
                            log_interface->number++;
                        }

                        if (verbose)
                            fmt::print(stderr, "* Opening legacy pcap file {}\n", fname);

                        log_interface->name = fname;

                        try {
                            log_interface->file = open_pcap_file(fname, force, file_dlt);
                        } catch (const std::runtime_error& e) {
                            fmt::print(stderr, "ERROR: Couldn't open {} for writing ({})\n",
                                       log_interface->name, e.what());
                            break;
                        }
                    }

                    write_pcap_packet(log_interface->file, bytes, ts_sec, ts_usec);

                    log_interface->sz += bytes.size();
                    log_interface->count++;

                    if (split_packets && log_interface->count >= split_packets) {
                        if (verbose)
                            fmt::print(stderr, "* Closing pcap file {} after {} packets\n",
                                    log_interface->name, log_interface->count);

                        fclose(log_interface->file);
                        log_interface->file = nullptr;
                        log_interface->count = 0;
                    } else if (split_size && log_interface->sz >= split_size * 1024) {
                        if (verbose)
                            fmt::print(stderr, "* Closing pcap file {} after {}kb\n",
                                    log_interface->name, log_interface->sz / 1024);
                        fclose(log_interface->file);
                        log_interface->file = nullptr;
                        log_interface->sz = 0;
                    }
                } else {
                    // pcapng

                    std::shared_ptr<log_file> log_interface;

                    if (split_interface) {
                        auto log_index = per_interface_logs.find(datasource);

                        if (log_index == per_interface_logs.end()) {
                            log_interface = std::make_shared<log_file>();
                            per_interface_logs[datasource] = log_interface;
                        } else {
                            log_interface = log_index->second;
                        }

                    } else {
                        log_interface = single_log;
                    }

                    if (log_interface->file == nullptr) {
                        int file_dlt = dlt;

                        if (file_dlt < 0)
                            file_dlt = pkt_dlt;

                        auto fname = out_fname;

                        if (split_interface)
                            fname = fmt::format("{}-{}", fname, datasource);

                        if (split_packets || split_size) {
                            fname = fmt::format("{}-{:06}", fname, log_interface->number);
                            log_interface->number++;
                        }

                        if (verbose)
                            fmt::print(stderr, "* Opening pcapng file {}\n", fname);

                        log_interface->name = fname;

                        try {
                            log_interface->file = open_pcapng_file(fname, force);
                        } catch (const std::runtime_error& e) {
                            fmt::print(stderr, "ERROR: Couldn't open {} for writing ({})\n",
                                       log_interface->name, e.what());
                            break;
                        }
                    }

                    auto source_combo = fmt::format("{}-{}", datasource, pkt_dlt);
                    auto source_key = log_interface->ng_interface_map.find(source_combo);
                    unsigned int ngindex = 0;

                    if (source_key == log_interface->ng_interface_map.end()) {
                        std::shared_ptr<db_interface> dbinterface;

                        for (auto dbi : interface_vec) {
                            if (dbi->uuid == datasource) {
                                auto desc = fmt::format("Kismet datasource {} ({} - {})",
                                        dbi->name, dbi->interface, dbi->definition);
                                ngindex = log_interface->ng_interface_map.size();

                                log_interface->ng_interface_map[source_combo] = ngindex;

                                write_pcapng_interface(log_interface->file, ngindex,
                                        dbi->interface, pkt_dlt, desc);

                                break;
                            }
                        }
                    } else {
                        ngindex = source_key->second;
                    }

                    if (skip_gps) {
                        lat = 0;
                        lon = 0;
                        alt = 0;
                    }

                    write_pcapng_packet(log_interface->file, bytes, ts_sec, ts_usec, tags, ngindex,
                            lat, lon, alt);

                    log_interface->sz += bytes.size();
                    log_interface->count++;

                    if (split_packets && log_interface->count >= split_packets) {
                        if (verbose)
                            fmt::print(stderr, "* Closing pcapng file {} after {} packets\n",
                                    log_interface->name, log_interface->count);

                        fclose(log_interface->file);
                        log_interface->file = nullptr;
                        log_interface->count = 0;
                    } else if (split_size && log_interface->sz >= split_size * 1024) {
                        if (verbose)
                            fmt::print(stderr, "* Closing pcap file {} after {}kb\n",
                                    log_interface->name, log_interface->sz / 1024);
                        fclose(log_interface->file);
                        log_interface->file = nullptr;
                        log_interface->sz = 0;
                    }
                }

                // Advance the packet counter and reset its time
                ++pkt;

                pkt_time = 0;
                pkt_time_us = 0;
            } else if (gps_time != 0) {
                auto ts_sec = sqlite3_column_as<unsigned long>(*gps, 0);
                auto ts_usec = sqlite3_column_as<unsigned long>(*gps, 1);

                if (pcapng && !split_interface) {
                    nlohmann::json json;
                    std::stringstream ss(sqlite3_column_as<std::string>(*gps, 2));

                    try {
                        ss >> json;

                        auto alt = json["kismet.gps.last_location"].value("kismet.common.location.alt", (double) 0);
                        auto lat = json["kismet.gps.last_location"]["kismet.common.location.geopoint"][1].get<double>();
                        auto lon = json["kismet.gps.last_location"]["kismet.common.location.geopoint"][0].get<double>();

                        if (lat != 0 && lon != 0) {
                            try {
                                if (single_log->file == nullptr) {
                                    auto fname = out_fname;

                                    if (verbose)
                                        fmt::print(stderr, "* Opening pcapng file {}\n", fname);

                                    single_log->name = fname;
                                    single_log->file = open_pcapng_file(fname, force);
                                }
                            } catch (const std::runtime_error& e) {
                                fmt::print(stderr, "ERROR: Couldn't open {} for writing ({})\n",
                                        single_log->name, e.what());
                                break;
                            }

                            write_pcapng_gps(single_log->file, ts_sec, ts_usec, lat, lon, alt);
                        }
                    } catch (const std::exception& e) {
                        fmt::print(stderr, "WARNING: Could not process GPS JSON, skipping ({})\n", e.what());
                    }
                }

                // Advance and reset the gps query
                ++gps;

                gps_time = 0;
                gps_time_us = 0;
            }

        }
    } catch (const std::exception& e) {
        fmt::print(stderr, "*ERROR: Failed to extract and write packets: {}\n", e.what());
        exit(0);
    }

    fmt::print(stderr, "Done...\n");

    sqlite3_close(db);

    if (single_log != nullptr) {
        if (single_log->file != nullptr) {
            fflush(single_log->file);
            fclose(single_log->file);
        }
    }

    for (const auto& l : per_interface_logs) {
        if (l.second->file != nullptr) {
            fflush(l.second->file);
            fclose(l.second->file);
        }
    }

    return 0;
}

