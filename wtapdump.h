#ifndef __WTAPDUMP_H__
#define __WTAPDUMP_H__

#include "config.h"

#include <stdio.h>

#include "packet.h"
#include "dumpfile.h"

#if (defined(HAVE_LIBWIRETAP) && !defined(USE_LOCAL_DUMP))

extern "C" {
#include "wtap.h"
}

class WtapDumpFile : public virtual DumpFile {
public:
    int OpenDump(const char *file);

    int CloseDump();

    int DumpPacket(const packet_info *in_info, const pkthdr *in_header, const u_char *in_data);

protected:
    int Common2Wtap(const pkthdr *in_header, const u_char *in_data);

    char errstr[1024];
    char type[64];

    wtap_pkthdr packet_header;
    u_char packet_data[MAX_PACKET_LEN];

    wtap_dumper *dump_file;
    int wtap_error;

};

#endif

#endif
