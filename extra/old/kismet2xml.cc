#include "config.h"

#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include "getopt.h"
#include <unistd.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <zlib.h>

#include "gpsdump.h"

#define GPS_VERSION 5

// Lets just pretend v3 never existed.

// Sacred cows make the best hamburger.
#ifndef WORDS_BIGENDIAN
// Little endian magic
#define GPS_MAGIC 0xDEADBEEF
#else
// Big endian magic
#define GPS_MAGIC 0xEFEBADDE
#endif

// Number of networks in the header
#define HEADER_NUM 4096
// Offset of the data segment
#define DATA_OFFSET (sizeof(GPSDump::file_hdr) + (sizeof(GPSDump::net_hdr) * HEADER_NUM))

// Defines of the old binary formats
typedef struct {
    int32_t tv_sec;
    int32_t tv_usec;
} time_hdr;

typedef struct {
    uint32_t magic;
    uint8_t version;
    time_hdr start;
} file_hdr;

typedef struct {
    uint16_t number;
    uint8_t bssid[6];
    uint8_t ssid[SSID_SIZE];
} net_hdr;

typedef struct {
    uint16_t number;
    uint8_t bssid[6];
    uint8_t ssid[SSID_SIZE];
} net_hdr_v3;

typedef struct {
    uint8_t number;
    uint8_t bssid[6];
    uint8_t ssid[SSID_SIZE];
} net_hdr_v2;

typedef struct {
    uint8_t number;
    uint8_t bssid[6];
    uint8_t ssid[SSID_SIZE];
} net_hdr_v1;


typedef struct {
    uint16_t number;
    int16_t lat;
    int64_t lat_mant;
    int16_t lon;
    int64_t lon_mant;
    int16_t alt;
    int64_t alt_mant;
    int16_t spd;
    int64_t spd_mant;
    int16_t fix;
    uint16_t quality;
    uint16_t power;
    uint16_t noise;
    time_hdr ts;
} data_pkt;

typedef struct {
    uint8_t number;
    int16_t lat;
    int64_t lat_mant;
    int16_t lon;
    int64_t lon_mant;
    int16_t alt;
    int64_t alt_mant;
    int16_t spd;
    int64_t spd_mant;
    int16_t fix;
    uint16_t power;
    time_hdr ts;
} data_pkt_v3;

typedef struct {
    uint8_t number;
    int16_t lat;
    int64_t lat_mant;
    int16_t lon;
    int64_t lon_mant;
    int16_t alt;
    int64_t alt_mant;
    int16_t spd;
    int64_t spd_mant;
    int16_t fix;
    uint16_t power;
    time_hdr ts;
} data_pkt_v2;

typedef struct {
    uint8_t number;
    int16_t lat;
    int64_t lat_mant;
    int16_t lon;
    int64_t lon_mant;
    int16_t alt;
    int64_t alt_mant;
    int16_t spd;
    int64_t spd_mant;
    int16_t fix;
    time_hdr ts;
    } data_pkt_v1;


typedef struct gps_network {
    net_hdr header;

    double max_lat;
    double min_lat;
    double max_lon;
    double min_lon;
    double max_alt;
    double min_alt;

    int count;

    double avg_lat, avg_lon, avg_alt, avg_spd;

    double diagonal_distance, altitude_distance;

    // Index to the netcolors table
    int color_index;
};

string Mac2String(uint8_t *mac, char seperator) {
    char tempstr[MAC_STR_LEN];

    // There must be a better way to do this...
    if (seperator != '\0')
        snprintf(tempstr, MAC_STR_LEN, "%02X%c%02X%c%02X%c%02X%c%02X%c%02X",
                 mac[0], seperator, mac[1], seperator, mac[2], seperator,
                 mac[3], seperator, mac[4], seperator, mac[5]);
    else
        snprintf(tempstr, MAC_STR_LEN, "%02X%02X%02X%02X%02X%02X",
                 mac[0], mac[1], mac[2],
                 mac[3], mac[4], mac[5]);

    string temp = tempstr;
    return temp;
}

int ProcessGPSFile(char *in_fname, char *in_oname, char *in_netfname) {
    vector<gps_network> net_vec;

#ifdef HAVE_LIBZ
    gzFile gpsfz;
#else
     FILE *gpsf;
#endif

#ifdef HAVE_LIBZ
    if ((gpsfz = gzopen(in_fname, "rb")) == NULL) {
#else
    if ((gpsf = fopen(in_fname, "rb")) == NULL) {
#endif
        fprintf(stderr, "FATAL:  Could not open data file.\n");
        return -1;
    }

    FILE *outf;
    if (in_oname == NULL) {
        outf = stdout;
    } else {
        if ((outf = fopen(in_oname, "w")) == NULL) {
            fprintf(stderr, "FATAL:  Could not open output file (%s) for appending\n",
                    in_oname);
            return -1;
        }
    }

    file_hdr filhdr;

    /*
    if (fread(&filhdr, sizeof(file_hdr), 1, gpsf) < 1) {
        fprintf(stderr, "FATAL:  Could not read header.\n");
        return -1;
        }
        */
#ifdef HAVE_LIBZ
    if (gzread(gpsfz, &filhdr, sizeof(file_hdr)) < (int) sizeof(file_hdr))
#else
    if (fread(&filhdr, sizeof(file_hdr), 1, gpsf) < 1)
#endif
    {
        fprintf(stderr, "FATAL:  Could not read header.\n");
        return -1;
    }

    if (filhdr.magic != GPS_MAGIC) {
        fprintf(stderr, "FATAL:  Invalid gpsdump magic on %s.\n", in_fname);
        return -1;
    }

    if (filhdr.version > 4) {
        fprintf(stderr, "FATAL:  Unsupported version %d.\n", filhdr.version);
        return -1;
    }

    net_hdr nethdr[HEADER_NUM];
    memset(nethdr, 0, sizeof(net_hdr) * HEADER_NUM);

    // Yes this is a nasty repetition of code.
    // No I don't have a better way of doing it.
    if (filhdr.version == 1) {
        net_hdr_v1 nethdr_v1[254];
#ifdef HAVE_LIBZ
        if (gzread(gpsfz, &nethdr_v1, sizeof(net_hdr_v1) * 254) < (int) sizeof(net_hdr_v1) * 254)
#else
        if (fread(&nethdr_v1, sizeof(net_hdr_v1), 254, gpsf) < 254)
#endif
        {
            fprintf(stderr, "FATAL:  Could not read network headers.\n");
            return -1;
        }

        // These are easy since they didn't change but we'll read them seperately anyhow
        for (int x = 0; x < 254; x++) {
            /*
            typedef struct {
                uint8_t number;
                uint8_t bssid[6];
                uint8_t ssid[SSID_SIZE];
                } net_hdr;
                */

            nethdr[x].number = nethdr_v1[x].number;
            memcpy(nethdr[x].bssid, nethdr_v1[x].bssid, 6);
            memcpy(nethdr[x].ssid, nethdr_v1[x].ssid, SSID_SIZE);
        }

    } else if (filhdr.version == 2) {
        net_hdr_v2 nethdr_v2[254];
#ifdef HAVE_LIBZ
        if (gzread(gpsfz, &nethdr_v2, sizeof(net_hdr_v2) * 254) < (int) sizeof(net_hdr_v2) * 254)
#else
        if (fread(&nethdr_v2, sizeof(net_hdr_v2), 254, gpsf) < 254)
#endif
        {
            fprintf(stderr, "FATAL:  Could not read network headers.\n");
            return -1;
        }

        // These are easy since they didn't change but we'll read them seperately anyhow
        for (int x = 0; x < 254; x++) {
            nethdr[x].number = nethdr_v2[x].number;
            memcpy(nethdr[x].bssid, nethdr_v2[x].bssid, 6);
            memcpy(nethdr[x].ssid, nethdr_v2[x].ssid, SSID_SIZE);
        }
    } else if (filhdr.version == 3) {
        net_hdr_v3 nethdr_v3[254];
#ifdef HAVE_LIBZ
        if (gzread(gpsfz, &nethdr_v3, sizeof(net_hdr_v3) * 254) < (int) sizeof(net_hdr_v3) * 254)
#else
        if (fread(&nethdr_v3, sizeof(net_hdr_v3), 254, gpsf) < 254)
#endif
        {
            fprintf(stderr, "FATAL:  Could not read network headers.\n");
            return -1;
        }

        // These are easy since they didn't change but we'll read them seperately anyhow
        for (int x = 0; x < 254; x++) {
            nethdr[x].number = nethdr_v3[x].number;
            memcpy(nethdr[x].bssid, nethdr_v3[x].bssid, 6);
            memcpy(nethdr[x].ssid, nethdr_v3[x].ssid, SSID_SIZE);
        }

    } else {
#ifdef HAVE_LIBZ
        if (gzread(gpsfz, &nethdr, sizeof(net_hdr) * HEADER_NUM) < (int) sizeof(net_hdr) * HEADER_NUM)
#else
        if (fread(&nethdr, sizeof(net_hdr), HEADER_NUM, gpsf) < HEADER_NUM)
#endif
        {
            fprintf(stderr, "FATAL:  Could not read network headers.\n");
            return -1;
        }
    }

    for (int x = 0; x < HEADER_NUM; x++) {
        gps_network netw;

//        printf("Got header '%s'\n", nethdr[x].ssid);

        memset(&netw, 0, sizeof(gps_network));

        netw.header = nethdr[x];

        /*
        printf("got network header %d encode number %d '%s'\n",
        x, netw.header.number, netw.header.ssid);
        */

        net_vec.push_back(netw);
    }

    data_pkt dpkt;
    data_pkt_v1 dpkt_v1;
    data_pkt_v2 dpkt_v2;

    int read_ret = 1;


    time_t file_start = filhdr.start.tv_sec;

    // Write the XML headers
    fprintf(outf, "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<!DOCTYPE gps-run SYSTEM \"http://kismetwireless.net/kismet-gps-1.0.dtd\">\n\n");

    fprintf(outf, "<gps-run gps-version=\"%d\" start-time=\"%.24s\">\n\n",
            GPS_VERSION, ctime(&file_start));

    if (in_netfname != NULL) {
        fprintf(outf, "    <network-file>%s</network-file>\n\n", in_netfname);
    }

    int file_samples = 0;
    while (read_ret > 0) {

        file_samples++;

        if (filhdr.version == 1) {
#ifdef HAVE_LIBZ
            read_ret = gzread(gpsfz, &dpkt_v1, sizeof(dpkt_v1));
#else
            read_ret = fread(&dpkt_v1, sizeof(dpkt_v1), 1, gpsf);
#endif

            dpkt.number = dpkt_v1.number;
            dpkt.lat = dpkt_v1.lat;
            dpkt.lat_mant = dpkt_v1.lat_mant;
            dpkt.lon = dpkt_v1.lon;
            dpkt.lon_mant = dpkt_v1.lon_mant;
            dpkt.alt = dpkt_v1.alt;
            dpkt.alt_mant = dpkt_v1.alt_mant;
            dpkt.spd = dpkt_v1.spd;
            dpkt.spd_mant = dpkt_v1.spd_mant;
            dpkt.fix = dpkt_v1.fix;
            dpkt.power = 0;
            memcpy(&dpkt.ts, &dpkt_v1.ts, sizeof(time_hdr));
        } else if (filhdr.version == 2 || filhdr.version == 3) {
#ifdef HAVE_LIBZ
            read_ret = gzread(gpsfz, &dpkt_v2, sizeof(dpkt_v2));
#else
            read_ret = fread(&dpkt_v2, sizeof(dpkt_v2), 1, gpsf);
#endif

            dpkt.number = dpkt_v2.number;
            dpkt.lat = dpkt_v2.lat;
            dpkt.lat_mant = dpkt_v2.lat_mant;
            dpkt.lon = dpkt_v2.lon;
            dpkt.lon_mant = dpkt_v2.lon_mant;
            dpkt.alt = dpkt_v2.alt;
            dpkt.alt_mant = dpkt_v2.alt_mant;
            dpkt.spd = dpkt_v2.spd;
            dpkt.spd_mant = dpkt_v2.spd_mant;
            dpkt.fix = dpkt_v2.fix;
            dpkt.power = dpkt_v2.power;
            memcpy(&dpkt.ts, &dpkt_v1.ts, sizeof(time_hdr));

        } else {
#ifdef HAVE_LIBZ
            read_ret = gzread(gpsfz, &dpkt, sizeof(dpkt));
#else
            read_ret = fread(&dpkt, sizeof(dpkt), 1, gpsf);
#endif
        }

        // We can't trust packets that have no coordinate fix
        if (dpkt.fix == 0)
            continue;

        double lat, lon, alt, spd;

        // Convert the stored primary+mantissa into a double
        lat = (double) dpkt.lat + ((double) dpkt.lat_mant / 1000000);
        lon = (double) dpkt.lon + ((double) dpkt.lon_mant / 1000000);
        alt = (double) dpkt.alt + ((double) dpkt.alt_mant / 1000000);
        spd = (double) dpkt.spd + ((double) dpkt.spd_mant / 1000000);

        if (lat == 0 || lon == 0)
            continue;

        // If it's part of a track print it as a track entry
        if ((dpkt.number == 0xFF && filhdr.version <= 3) ||
            (dpkt.number == HEADER_NUM && filhdr.version > 3)) {

            fprintf(outf, "    <gps-point bssid=\"%s\" time-sec=\"%ld\" time-usec=\"%ld\" "
                    "lat=\"%f\" lon=\"%f\" alt=\"%f\" spd=\"%f\" fix=\"%d\" "
                    "signal=\"%d\" quality=\"%d\" noise=\"%d\"/>\n",
                    gps_track_bssid,
                    (long int) dpkt.ts.tv_sec, (long int) dpkt.ts.tv_usec,
                    lat, lon, alt, spd, dpkt.fix,
                    dpkt.power, dpkt.quality, dpkt.noise);
        } else {
            // Otherwise print a normal network

            fprintf(outf, "    <gps-point bssid=\"%s\" time-sec=\"%ld\" time-usec=\"%ld\" "
                    "lat=\"%f\" lon=\"%f\" alt=\"%f\" spd=\"%f\" fix=\"%d\" "
                    "signal=\"%d\" quality=\"%d\" noise=\"%d\"/>\n",
                    Mac2String(net_vec[dpkt.number].header.bssid, ':').c_str(),
                    (long int) dpkt.ts.tv_sec, (long int) dpkt.ts.tv_usec,
                    lat, lon, alt, spd, dpkt.fix,
                    dpkt.power, dpkt.quality, dpkt.noise);
        }
    }

    fprintf(outf, "</gps-run>\n\n");

#ifdef HAVE_LIBZ
    gzclose(gpsfz);
#else
    fclose(gpsf);
#endif

    fclose(outf);

    return 1;
}

int Usage(char *argv) {
    printf("Usage: %s [OPTION] <gpsfile>\n", argv);
    printf(
           "  -o, --output <file>          Output cwgd data to <file> (default stdout)\n"
           "  -n, --netfile <file>         Network XML file to reference\n"
           "  -h, --help                   What do you think you're reading?\n");
    exit(1);
}

char *exec_name;

int main(int argc, char *argv[]) {
    exec_name = argv[0];

    static struct option long_options[] = {   /* options table */
        { "output", required_argument, 0, 'o' },
        { "netfile", required_argument, 0, 'n' },
        { "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0 }
    };
    int option_index;

    char *foutname = NULL;
    char *noutname = NULL;

    while(1) {
        int r = getopt_long(argc, argv, "hn:o:",
                            long_options, &option_index);

        if (r < 0) break;

        switch(r) {
        case 'o':
            foutname = optarg;
            break;
        case 'n':
            noutname = optarg;
            break;
        default:
            Usage(argv[0]);
            break;
        }
    }

    if (optind == argc) {
        fprintf(stderr, "FATAL:  No gps files given.\n");
        exit(1);
    }

    if (ProcessGPSFile(argv[optind], foutname, noutname) < 0) {
        fprintf(stderr, "FATAL:  Unrecoverable error processing GPS data file \"%s\".\n",
                argv[optind]);
    }

    exit(0);
}

