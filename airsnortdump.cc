#include "airsnortdump.h"
#include "packetracker.h"

int AirsnortDumpFile::OpenDump(const char *file) {
    snprintf(type, 64, "airsnort (weak packet) dump");
    snprintf(filename, 1024, "%s", file);

    num_dumped = 0;

    dumper = new WtapDumpFile;

    int ret;
    ret = dumper->OpenDump(file);

    snprintf(errstr, 1024, "%s", dumper->FetchError());

    return ret;
}

int AirsnortDumpFile::CloseDump() {
    int ret;
    ret = dumper->CloseDump();

    snprintf(errstr, 1024, "%s", dumper->FetchError());

    return ret;
}

int AirsnortDumpFile::DumpPacket(const packet_info *in_info, const pkthdr *in_header,
                                 const u_char *in_data) {

    int ret = 1;

    // Is it a beacon?  Do we know about this network?  Log it if we don't.
    if (in_info->type == packet_beacon) {
        if (bssid_dumped_map.find(Packetracker::Mac2String((uint8_t *) in_info->bssid_mac, ':')) == bssid_dumped_map.end()) {
            // We only count weak packets as logged, not the headers

            bssid_dumped_map[Packetracker::Mac2String((uint8_t *) in_info->bssid_mac, ':')] = 1;

            ret = dumper->DumpPacket(in_info, in_header, in_data);
            snprintf(errstr, 1024, "%s", dumper->FetchError());
            return ret;
        }
    }

    // Is it weak?  Always log them, and add it to our count
        if ((in_info->type == packet_data ||
             in_info->type == packet_adhoc_data ||
             in_info->type == packet_ap_broadcast) &&
            in_info->interesting == 1) {

        num_dumped++;

        ret = dumper->DumpPacket(in_info, in_header, in_data);
        snprintf(errstr, 1024, "%s", dumper->FetchError());
        return ret;
    }

    return ret;
}

