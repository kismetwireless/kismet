#ifndef __DUMPFILE_H__
#define __DUMPFILE_H__

#include "config.h"
#include "packet.h"

// Packet capture source superclass
class DumpFile {
public:
    // Open the packet source
    virtual int OpenDump(const char *file) = 0;

    virtual int CloseDump() = 0;

    // Get a packet from the medium
    virtual int DumpPacket(const packet_info *in_info, const pkthdr *in_header,
                           const u_char *in_data) = 0;

    // Get the number of packets
    int FetchDumped() { return(num_dumped); };

    // Say what we are
    char *FetchType() { return(type); };

    // Get the error
    char *FetchError() { return(errstr); };

    // Get the file name
    char *FetchFilename() { return(filename); };

protected:
    char errstr[1024];
    char type[64];
    char filename[1024];

    int num_dumped;

};

#endif
