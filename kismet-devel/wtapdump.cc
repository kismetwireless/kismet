#include "wtapdump.h"

#if (defined(HAVE_LIBWIRETAP) && !defined(USE_LOCAL_DUMP))

int WtapDumpFile::OpenDump(const char *file) {
    snprintf(type, 64, "wiretap (ethereal libwiretap) dump");
    snprintf(filename, 1024, "%s", file);

    num_dumped = 0;

    dump_file = wtap_dump_open(file, WTAP_FILE_PCAP, WTAP_ENCAP_IEEE_802_11,
                               2344, &wtap_error);

    if (!dump_file) {
        snprintf(errstr, 1024, "Unable to open wtap dump file");
        return wtap_error;
    }

    return 1;
}

int WtapDumpFile::CloseDump() {
    wtap_dump_close(dump_file, &wtap_error);

    return num_dumped;
}

int WtapDumpFile::DumpPacket(const packet_info *in_info, const pkthdr *in_header,
                             const u_char *in_data) {

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
