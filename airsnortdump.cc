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

#include "airsnortdump.h"
#include "packetracker.h"

int AirsnortDumpFile::OpenDump(const char *file) {
    snprintf(type, 64, "airsnort (weak packet) dump");
    snprintf(filename, 1024, "%s", file);

    num_dumped = 0;

    dumper = new WtapDumpFile;

    int ret;
    ret = dumper->OpenDump(file);

    if (ret < 0)
        snprintf(errstr, 1024, "%s", dumper->FetchError());

    return ret;
}

int AirsnortDumpFile::CloseDump() {
    int ret;
    ret = dumper->CloseDump();

    if (ret < 0)
        snprintf(errstr, 1024, "%s", dumper->FetchError());

//    delete dumper;

    return ret;
}

int AirsnortDumpFile::DumpPacket(const packet_info *in_info, const kis_packet *packet) {

    int ret = 1;

    // Is it a beacon?  Do we know about this network?  Log it if we don't.
    if (in_info->type == packet_management && in_info->subtype == packet_sub_beacon) {
        if (bssid_dumped_map.find(in_info->bssid_mac) == bssid_dumped_map.end()) {
            // We only count weak packets as logged, not the headers

            bssid_dumped_map[in_info->bssid_mac] = 1;

            ret = dumper->DumpPacket(in_info, packet);
            if (ret < 0)
                snprintf(errstr, 1024, "%s", dumper->FetchError());
            return ret;
        }
    }

    // Is it weak?  Always log them, and add it to our count
    if (in_info->type == packet_data && in_info->interesting == 1) {
        num_dumped++;

        ret = dumper->DumpPacket(in_info, packet);
        if (ret < 0)
            snprintf(errstr, 1024, "%s", dumper->FetchError());
        return ret;
    }

    return ret;
}

