// Fake a wtap dump file.  If we have the wiretap library, so
// much the better, but if libwiretap isn't there this will
// override

#ifndef __WTAPLOCALDUMP_H__
#define __WTAPLOCALDUMP_H__

#include "config.h"

#include <stdio.h>
#include "packet.h"
#include "dumpfile.h"

#ifdef USE_LOCAL_DUMP

#ifndef WORDS_BIGENDIAN
// Little endian magic
#define PCAP_MAGIC          0xa1b2c3d4
#else
// Big endian magic
#define PCAP_MAGIC          0xd4c3b2a1
#endif

class WtapDumpFile : public virtual DumpFile {
public:
    int OpenDump(const char *file);

    int CloseDump();

    int DumpPacket(const packet_info *in_info, const pkthdr *in_header, const u_char *in_data);

protected:
    /* Stolen from libwiretap */

    /* "libpcap" file header (minus magic number). */
    struct pcap_hdr {
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;   /* GMT to local correction */
        uint32_t sigfigs;    /* accuracy of timestamps */
        uint32_t snaplen;    /* max length of captured packets, in octets */
        uint32_t network;    /* data link type */
    };
    /* "libpcap" record header. */
    struct pcaprec_hdr {
        uint32_t ts_sec;     /* timestamp seconds */
        uint32_t ts_usec;    /* timestamp microseconds */
        uint32_t incl_len;   /* number of octets of packet saved in file */
        uint32_t orig_len;   /* actual length of packet */
    };

    char errstr[1024];
    char type[64];

    FILE *dump_file;

};

#endif

#endif

