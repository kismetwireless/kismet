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

#include <stdio.h>
#include <errno.h>
#include "wtaplocaldump.h"

#ifdef USE_LOCAL_DUMP

int WtapDumpFile::OpenDump(const char *file) {
    snprintf(type, 64, "wiretap (local code) dump");
    snprintf(filename, 1024, "%s", file);

    num_dumped = 0;
    beacon_log = 1;

    if ((dump_file = fopen(file, "w")) == NULL) {
        snprintf(errstr, 1024, "Unable to open dump file %s (%s)", filename, strerror(errno));
        return -1;
    }

    uint32_t magic = PCAP_MAGIC;
    int nwritten;

    // Write the magic file identifier
    nwritten = fwrite(&magic, 1, sizeof(magic), dump_file);
    if (nwritten != sizeof(magic)) {
        if (nwritten == 0 && ferror(dump_file))
            snprintf(errstr, 1024, "Unable to write pcap magic header. (%s)", strerror(errno));
        else
            snprintf(errstr, 1024, "Short write on pcap magic header.");

        return -1;
    }

    pcap_hdr file_hdr;

    /* current "libpcap" format is 2.4 */
    file_hdr.version_major = 2;
    file_hdr.version_minor = 4;
    file_hdr.thiszone = 0;  /* XXX - current offset? */
    file_hdr.sigfigs = 0;   /* unknown, but also apparently unused */
    file_hdr.snaplen = 2344;
    file_hdr.network = 105; /* pcap file type */

    // Write the header
    nwritten = fwrite(&file_hdr, 1, sizeof(file_hdr), dump_file);
    if (nwritten != sizeof(file_hdr)) {
        if (nwritten == 0 && ferror(dump_file))
            snprintf(errstr, 1024, "Unable to write pcap file header. (%s)", strerror(errno));
        else
            snprintf(errstr, 1024, "Short write on pcap file header.");

        return -1;
    }

    return 1;
}

int WtapDumpFile::CloseDump() {
    fclose(dump_file);

    return num_dumped;
}

int WtapDumpFile::DumpPacket(const packet_info *in_info, const pkthdr *in_header,
                             const u_char *in_data) {

    if (in_info->type == packet_beacon && beacon_log == 0) {
        if (beacon_logged_map.find(in_info->bssid_mac) == beacon_logged_map.end()) {
            beacon_logged_map[in_info->bssid_mac] = 1;
        } else {
            return 1;
        }
    }

    pcaprec_hdr packhdr;
    unsigned int nwritten;

    // Convert it to a pcap header
    packhdr.ts_sec = in_header->ts.tv_sec;
    packhdr.ts_usec = in_header->ts.tv_usec;
    packhdr.incl_len = in_header->len;
    packhdr.orig_len = in_header->len;

    nwritten = fwrite(&packhdr, 1, sizeof(pcaprec_hdr), dump_file);
    if (nwritten != sizeof(pcaprec_hdr)) {
        if (nwritten == 0 && ferror(dump_file))
            snprintf(errstr, 1024, "Unable to write pcap packet header (%s)", strerror(errno));
        else
            snprintf(errstr, 1024, "Short write on pcap packet header");

        return -1;
    }

    nwritten = fwrite(in_data, 1, packhdr.incl_len, dump_file);
    if (nwritten != packhdr.incl_len) {
        if (nwritten == 0 && ferror(dump_file))
            snprintf(errstr, 1024, "Unable to write pcap packet (%s)", strerror(errno));
        else
            snprintf(errstr, 1024, "Short write on pcap packet");

        return -1;
    }


    num_dumped++;

    return 1;
}

#endif
