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

class PcapSource : public PacketSource {
public:
    int OpenSource(const char *dev);
    int CloseSource();

    int FetchDescriptor() { return pcap_fileno(pd); }

    int FetchPacket(pkthdr *in_header, u_char *in_data);

    static void Callback(u_char *bp, const struct pcap_pkthdr *header,
                         const u_char *data);

protected:
    // Prism 802.11 headers from wlan-ng tacked on to the beginning of a
    // pcap packet... Snagged from the wlan-ng source
    typedef struct {
        uint32_t did;
        uint16_t status;
        uint16_t len;
        uint32_t data;
    } p80211item_uint32_t;

    typedef struct {
        uint32_t msgcode;
        uint32_t msglen;
        uint8_t devname[WLAN_DEVNAMELEN_MAX];
        p80211item_uint32_t hosttime;
        p80211item_uint32_t mactime;
        p80211item_uint32_t channel;
        p80211item_uint32_t rssi;
        p80211item_uint32_t sq;
        p80211item_uint32_t signal;
        p80211item_uint32_t noise;
        p80211item_uint32_t rate;
        p80211item_uint32_t istx;
        p80211item_uint32_t frmlen;
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

    int Pcap2Common(pkthdr *in_header, u_char *in_data);

    pcap_t *pd;

    // What kind of netlink is it
    int datalink_type;

};

#endif

#endif

