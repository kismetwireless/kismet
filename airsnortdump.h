// Dump a file in a format airsnort likes

#ifndef __AIRSNORTDUMP_H__
#define __AIRSNORTDUMP_H__

#include "config.h"

#include <stdio.h>
#include <string>
#include <map>

#include "dumpfile.h"
#include "wtapdump.h"
#include "wtaplocaldump.h"

class AirsnortDumpFile : public virtual DumpFile {
public:
    int OpenDump(const char *file);

    int CloseDump();

    int DumpPacket(const packet_info *in_info, const pkthdr *in_header, const u_char *in_data);

protected:

    DumpFile *dumper;

    map<string, int> bssid_dumped_map;

};

#endif
