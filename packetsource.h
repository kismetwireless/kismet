#ifndef __PACKETSOURCE_H__
#define __PACKETSOURCE_H__

#include "packet.h"

// Packet capture source superclass
class PacketSource {
public:
    // Open the packet source
    virtual int OpenSource(const char *dev) = 0;

    virtual int CloseSource() = 0;

    // Get the FD of our packet source
    virtual int FetchDescriptor() = 0;

    // Get a packet from the medium
    virtual int FetchPacket(pkthdr *in_header, u_char *in_data) = 0;

    // Say what we are
    char *FetchType() { return(type); };

    // Get the error
    char *FetchError() { return(errstr); };

    // Ignore incoming packets
    void Pause() { paused = 1; };

    // Stop ignoring incoming packets
    void Resume() { paused = 0; };

protected:
    char errstr[1024];
    pkthdr header;
    u_char data[MAX_PACKET_LEN];
    int paused;

    char type[64];

};

#endif
