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

#ifndef __PCAPSOURCE_H__
#define __PCAPSOURCE_H__

#include "config.h"

#ifdef HAVE_LIBPCAP

#include "packet.h"
#include "packetsource.h"

extern "C" {
#ifndef HAVE_PCAPPCAP_H
#include <pcap.h>
#include <net/bpf.h>
#else
#include <pcap/pcap.h>
#include <pcap/net/bpf.h>
#endif
}

// We care about:
// DLT_EN10MB (1) (encapsulated ethernet only, not useful.)
// DLT_IEEE802_11 (105) (raw 802.11b like linux cisco gives us)
// DLT_PRISM_HEADER (119) (linux prism2 headers)
// DLT_AIRONET_HEADER (120) (BSD patch)

// Define this for wlan-ng DLT_PRISM_HEADER support
#define WLAN_DEVNAMELEN_MAX 16

// The BSD datalink that doesn't report a sane value
#define KDLT_BSD802_11 -100

class PcapSource : public KisPacketSource {
public:
    int OpenSource(const char *dev, card_type ctype);
    int CloseSource();

    int FetchDescriptor() { return pcap_fileno(pd); }

    int FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata);

    static void Callback(u_char *bp, const struct pcap_pkthdr *header,
                         const u_char *in_data);

    int SetChannel(unsigned int chan);

protected:
    // Prism 802.11 headers from wlan-ng tacked on to the beginning of a
    // pcap packet... Snagged from the wlan-ng source
    typedef struct {
        uint32_t did __attribute__ ((packed));
        uint16_t status __attribute__ ((packed));
        uint16_t len __attribute__ ((packed));
        uint32_t data __attribute__ ((packed));
    } p80211item_uint32_t;

    typedef struct {
        uint32_t msgcode __attribute__ ((packed));
        uint32_t msglen __attribute__ ((packed));
        uint8_t devname[WLAN_DEVNAMELEN_MAX] __attribute__ ((packed));
        p80211item_uint32_t hosttime __attribute__ ((packed));
        p80211item_uint32_t mactime __attribute__ ((packed));
        p80211item_uint32_t channel __attribute__ ((packed));
        p80211item_uint32_t rssi __attribute__ ((packed));
        p80211item_uint32_t sq __attribute__ ((packed));
        p80211item_uint32_t signal __attribute__ ((packed));
        p80211item_uint32_t noise __attribute__ ((packed));
        p80211item_uint32_t rate __attribute__ ((packed));
        p80211item_uint32_t istx __attribute__ ((packed));
        p80211item_uint32_t frmlen __attribute__ ((packed));
    } wlan_ng_prism2_header;

    // Prism 802.11 headers from the openbsd Hermes drivers, even though they don't return
    // a valid linktype yet.  Structure lifted from bsd_airtools by dachb0den labs.
    typedef struct {
        u_int16_t wi_status;
        u_int16_t wi_ts0;
        u_int16_t wi_ts1;
        u_int8_t  wi_silence;
        u_int8_t  wi_signal;
        u_int8_t  wi_rate;
        u_int8_t  wi_rx_flow;
        u_int16_t wi_rsvd0;
        u_int16_t wi_rsvd1;
    } bsd_80211_header;

    // wlan-ng (and hopefully others) AVS header, version one.  Fields in
    // network byte order.
    typedef struct {
        uint32_t version;
        uint32_t length;
        uint64_t mactime;
        uint64_t hosttime;
        uint32_t phytype;
        uint32_t channel;
        uint32_t datarate;
        uint32_t antenna;
        uint32_t priority;
        uint32_t ssi_type;
        int32_t ssi_signal;
        int32_t ssi_noise;
        uint32_t preamble;
        uint32_t encoding;
    } avs_80211_1_header;

    int Pcap2Common(kis_packet *packet, uint8_t *data, uint8_t *moddata);

    int PcapShellCmd(char *in_cmd);

    pcap_t *pd;

    // What kind of netlink is it
    int datalink_type;
};

#endif

#endif

