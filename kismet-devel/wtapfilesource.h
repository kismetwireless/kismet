#ifndef __WTAPFILESOURCE_H__
#define __WTAPFILESOURCE_H__

#include "config.h"

#ifdef HAVE_LIBWIRETAP

#include "packet.h"
#include "packetsource.h"

extern "C" {
#include "wtap.h"
}

class WtapFileSource : public PacketSource {
public:
    int OpenSource(const char *dev);
    int CloseSource();

    int FetchDescriptor() { return wtap_fd(packfile); }

    int FetchPacket(pkthdr *in_header, u_char *in_data);

    static void Callback(u_char *bp, const struct pcap_pkthdr *header,
                         const u_char *data);

protected:
    int Wtap2Common(pkthdr *in_header, u_char *in_data);

    struct wtap *packfile;
    const struct wtap_pkthdr *packet_header;
    const u_char *packet_data;

};

#endif

#endif
