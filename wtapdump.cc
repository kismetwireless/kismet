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

#include "wtapdump.h"
#include <errno.h>

#if (defined(HAVE_LIBWIRETAP) && !defined(USE_LOCAL_DUMP))

int WtapDumpFile::OpenDump(const char *file) {
    snprintf(type, 64, "wiretap (ethereal libwiretap) dump");
    snprintf(filename, 1024, "%s", file);

    num_dumped = 0;
    beacon_log = 1;

    dump_file = wtap_dump_open(file, WTAP_FILE_PCAP, WTAP_ENCAP_IEEE_802_11,
                               2344, &wtap_error);

    if (!dump_file) {
        snprintf(errstr, 1024, "Unable to open wtap dump file: %s (%s)", filename,
                strerror(errno));
        return -1;
    }

    return 1;
}

int WtapDumpFile::CloseDump() {
    wtap_dump_close(dump_file, &wtap_error);

    return num_dumped;
}

int WtapDumpFile::DumpPacket(const packet_info *in_info, const pkthdr *in_header,
                             const u_char *in_data) {

    if ((in_info->type == packet_management && in_info->subtype == packet_sub_beacon) && beacon_log == 0) {
        map<mac_addr, string>::iterator blm = beacon_logged_map.find(in_info->bssid_mac);
        if (blm == beacon_logged_map.end()) {
            beacon_logged_map[in_info->bssid_mac] = in_info->ssid;
        } else if (blm->second == in_info->ssid) {
            return 1;
        }
    }

    Common2Wtap(in_header, in_data);

    wtap_dump(dump_file, &packet_header, NULL, packet_data, &wtap_error);

    num_dumped++;

    return 1;
}

int WtapDumpFile::Common2Wtap(const pkthdr *in_header, const u_char *in_data) {
    memset(&packet_header, 0, sizeof(wtap_pkthdr));
    memset(packet_data, 0, MAX_PACKET_LEN);

    packet_header.len = in_header->len;
    packet_header.caplen = in_header->caplen;
    packet_header.ts = in_header->ts;

    packet_header.pkt_encap = WTAP_ENCAP_IEEE_802_11;

    memcpy(packet_data, in_data, in_header->caplen);

    return(in_header->caplen);
}

#endif
