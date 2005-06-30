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
#include "gpsdump.h"

#ifdef HAVE_GPS

GPSDump::GPSDump() {
    num_packets = 0;
    gpsf = NULL;
}

int GPSDump::OpenDump(const char *in_fname, const char *in_netfname) {
    if ((gpsf = fopen(in_fname, "wb")) == NULL) {
        snprintf(errstr, 1024, "GPSDump unable to open file: %s",
                 strerror(errno));
        return -1;
    }

    fname = in_fname;

    // Write the XML headers
    fprintf(gpsf, "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n<!DOCTYPE gps-run SYSTEM \"http://kismetwireless.net/kismet-gps-2.9.1.dtd\">\n\n");

    // Write the start of the run
    time_t cur_time = time(0);

    fprintf(gpsf, "<gps-run gps-version=\"%d\" start-time=\"%.24s\">\n\n",
            GPS_VERSION, ctime(&cur_time));

    if (in_netfname != NULL) {
        fprintf(gpsf, "    <network-file>%s</network-file>\n\n", in_netfname);
    }

    return 1;
}

int GPSDump::CloseDump(int in_unlink) {
    int ret = 1;

    fprintf(gpsf, "</gps-run>\n");

    if (gpsf)
        fclose(gpsf);

    if (num_packets == 0 && in_unlink) {
        unlink(fname);
        ret = -1;
    }

    gpsf = NULL;
    num_packets = 0;

    return ret;
}

int GPSDump::DumpPacket(packet_info *in_packinfo) {
    if (in_packinfo->gps_fix < 2)
        return 0;

    timeval ts;
    gettimeofday(&ts, NULL);

    fprintf(gpsf, "    <gps-point bssid=\"%s\" source=\"%s\" time-sec=\"%ld\" time-usec=\"%ld\" "
            "lat=\"%f\" lon=\"%f\" alt=\"%f\" spd=\"%f\" heading=\"%f\" fix=\"%d\" "
            "signal=\"%d\" noise=\"%d\"/>\n",
            in_packinfo->bssid_mac.Mac2String().c_str(),
            in_packinfo->source_mac.Mac2String().c_str(),
            (long int) in_packinfo->ts.tv_sec, (long int) in_packinfo->ts.tv_usec,
            in_packinfo->gps_lat, in_packinfo->gps_lon, in_packinfo->gps_alt,
            in_packinfo->gps_spd, in_packinfo->gps_heading, in_packinfo->gps_fix,
            in_packinfo->signal, in_packinfo->noise);

    num_packets++;

    return 1;
}

int GPSDump::DumpTrack(GPSDClient *in_gps) {
    float lat, lon, alt, spd, hed;
    int fix;

    // Bail if we don't have a lock
    if (in_gps->FetchMode() < 2)
        return 0;

    timeval ts;
    gettimeofday(&ts, NULL);

    in_gps->FetchLoc(&lat, &lon, &alt, &spd, &hed, &fix);

    int sig = 0, qual = 0, noise = 0;

    if (time(0) - last_info.ts.tv_sec < decay && last_info.quality != -1) {
        sig = last_info.signal;
        qual = last_info.quality;
        noise = last_info.noise;
    }

    fprintf(gpsf, "    <gps-point bssid=\"%s\" time-sec=\"%ld\" time-usec=\"%ld\" "
            "lat=\"%f\" lon=\"%f\" alt=\"%f\" spd=\"%f\" heading=\"%f\" fix=\"%d\" "
            "signal=\"%d\" quality=\"%d\" noise=\"%d\"/>\n",
            gps_track_bssid,
            (long int) ts.tv_sec, (long int) ts.tv_usec,
            lat, lon, alt, spd, hed, fix,
            sig, qual, noise);

    num_packets++;

    return 1;
}


#endif
