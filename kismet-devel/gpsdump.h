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
    char source[MAC_STR_LEN];

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

class GPSDump {
public:
    GPSDump();

    char *FetchError() { return(errstr); };

    int OpenDump(const char *in_fname, const char *in_netfname);
    int CloseDump(int in_unlink);

    int DumpPacket(packet_info *in_packinfo);
    int DumpTrack(GPSD *in_gps);

protected:
    int num_packets;
    FILE *gpsf;
    const char *fname;
    char errstr[1024];

};

#endif

#endif
