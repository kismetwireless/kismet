#ifndef __PRISM2SOURCE_H__
#define __PRISM2SOURCE_H__

#include "config.h"

#ifdef HAVE_LINUX_NETLINK

#include <stdio.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <unistd.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include "packet.h"
#include "packetsource.h"

#define PRISM2_READ_TIMEOUT 100
#define MCAST_GRP_SNIFF 2
#define PRISM_ERR_TIMEOUT -2

class Prism2Source : public PacketSource {
public:
    int OpenSource(const char *dev);
    int CloseSource();

    int FetchDescriptor() { return fd; }

    int FetchPacket(pkthdr *in_header, u_char *in_data);

protected:
    int Prism2Common(pkthdr *in_header, u_char *in_data);

    typedef struct {
        uint32_t did __attribute__ ((packed));
	uint16_t status __attribute__ ((packed));
	uint16_t len __attribute__ ((packed));
	uint32_t data __attribute__ ((packed));
    } p80211item_t;

    typedef struct {
        uint32_t msgcode __attribute__ ((packed));
        uint32_t msglen __attribute__ ((packed));
        uint8_t devname[DEVNAME_LEN] __attribute__ ((packed));
        p80211item_t hosttime __attribute__ ((packed));
        p80211item_t mactime __attribute__ ((packed));
        p80211item_t channel __attribute__ ((packed));
        p80211item_t rssi __attribute__ ((packed));
        p80211item_t sq __attribute__ ((packed));
        p80211item_t signal __attribute__ ((packed));
        p80211item_t noise __attribute__ ((packed));
        p80211item_t rate __attribute__ ((packed));
        p80211item_t istx __attribute__ ((packed));
        p80211item_t frmlen __attribute__ ((packed));
    } sniff_packet_t;

    int read_sock;
    int write_sock;
    int fd;

    u_char buffer[MAX_PACKET_LEN];
};

#endif

#endif

