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

// GPS dump file

#ifndef __GPSDUMP_H__
#define __GPSDUMP_H__

#include "config.h"

#ifdef HAVE_GPS

#include <stdio.h>
#include <errno.h>
#include <string.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <map>
#include <string>
#include "packet.h"
#include "packetracker.h"

// I need to make this better.  Extern globals is ugly.
// Link to last_info in kismet_server.cc
extern packet_info last_info;
// Link to decay rate in kismet_server.cc
extern int decay;

#define GPS_VERSION 5

#define gps_track_bssid     "GP:SD:TR:AC:KL:OG"

typedef struct {
    char bssid[MAC_STR_LEN];

    long tv_sec;
    long tv_usec;

    float lat;
    float lon;
    float alt;
    float spd;

    int fix;

    int signal;
    int quality;
    int noise;
} gps_point;

/*
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
    */

class GPSDump {
public:
    GPSDump();

    char *FetchError() { return(errstr); };

    int OpenDump(const char *in_fname, const char *in_netfname);
    int CloseDump(int in_unlink);

    void AddGPS(GPSD *in_gps) { gps = in_gps; };

    int DumpPacket(packet_info *in_packinfo);

protected:
    int num_packets;
    FILE *gpsf;
    const char *fname;
    char errstr[1024];

    GPSD *gps;

};

#endif

#endif
