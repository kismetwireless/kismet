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

// pcapsource is probably the most complex source handing the largest number of
// card types.  Ideally, everything should be part of the pcap source except
// wsp100 and drones.

#ifndef __PCAPSOURCE_H__
#define __PCAPSOURCE_H__

#include "config.h"

#ifdef HAVE_LIBPCAP

#include "packet.h"
#include "packetsource.h"
#include "ifcontrol.h"
#include "iwcontrol.h"

extern "C" {
#ifndef HAVE_PCAPPCAP_H
#include <pcap.h>
//#include <net/bpf.h>
#else
#include <pcap/pcap.h>
#include <pcap/net/bpf.h>
#endif
}

// Custom packet stream headers

// Define this for the max length of a ssid, not counting os-trailing null
#define MAX_SSID_LEN 32

// Define this for wlan-ng DLT_PRISM_HEADER support
#define WLAN_DEVNAMELEN_MAX 16

// The BSD datalink that doesn't report a sane value
#define KDLT_BSD802_11 -100

#ifndef DLT_PRISM_HEADER
#define DLT_PRISM_HEADER        119 /* prism header, not defined on some platforms */
#endif

#ifndef DLT_IEEE802_11_RADIO
#define	DLT_IEEE802_11_RADIO	127	/* 802.11 plus WLAN header */
#endif

// Generic pcapsource
class PcapSource : public KisPacketSource {
public:
    PcapSource(GlobalRegistry *in_globalreg, string in_name, string in_dev) : 
        KisPacketSource(in_globalreg, in_name, in_dev) { }

    int OpenSource();
    int CloseSource();

    int FetchDescriptor();

    int FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata);

    static void Callback(u_char *bp, const struct pcap_pkthdr *header,
                         const u_char *in_data);

    int FetchChannel();
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

    // Carrier setting
    virtual carrier_type IEEE80211Carrier();
    // Datalink checker
    virtual int DatalinkType();
    // Signal level fetcher
    virtual int FetchSignalLevels(int *in_siglev, int *in_noiselev);
    // Mangler
    virtual int ManglePacket(kis_packet *packet, uint8_t *data, uint8_t *moddata);
    // Mangle a prism2 datalink to a kismet packet
    int Prism2KisPack(kis_packet *packet, uint8_t *data, uint8_t *moddata);
    // Mangle a BSD header
    int BSD2KisPack(kis_packet *packet, uint8_t *data, uint8_t *moddata);
    // Mangle a radiotap header
#ifdef HAVE_RADIOTAP
    int Radiotap2KisPack(kis_packet *packet, uint8_t *data, uint8_t *moddata);
#endif
    
    pcap_t *pd;
    int datalink_type;

    // Some toggles for subclasses to use
    int toggle0;
    int toggle1;
};

// Open with pcap_dead for pcapfiles - we have a different open and we
// have to kluge fetching the packet descriptor
class PcapSourceFile : public PcapSource {
public:
    PcapSourceFile(GlobalRegistry *in_globalreg, string in_name, string in_dev) : 
        PcapSource(in_globalreg, in_name, in_dev) { }
    int OpenSource();
    int FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata);
    // int FetchDescriptor();
    int FetchChannel();
};

#ifdef SYS_LINUX
// What we need to track on a linux interface to restore the settings
typedef struct linux_ifparm {
    short flags;
    char essid[MAX_SSID_LEN + 1];
    int channel;
    int mode;
    int privmode;
    int prismhdr;
};
#endif

// Wireless extention pcapsource - use wext to get the channels.  Everything
// else is straight pcapsource
#ifdef HAVE_LINUX_WIRELESS
class PcapSourceWext : public PcapSource {
public:
    PcapSourceWext(GlobalRegistry *in_globalreg, string in_name, string in_dev) : 
        PcapSource(in_globalreg, in_name, in_dev) { 
        modern_chancontrol = -1;
    }
    int FetchChannel();

    // Small tracker var for intelligent channel control in orinoco.  I don't want to make
    // a new class for 1 int
    int modern_chancontrol;
protected:
    int FetchSignalLevels(int *in_siglev, int *in_noiselev);
};

// FCS trimming for wext cards
class PcapSourceWextFCS : public PcapSourceWext {
public:
    PcapSourceWextFCS(GlobalRegistry *in_globalreg, string in_name, string in_dev) :
        PcapSourceWext(in_globalreg, in_name, in_dev) { 
            fcsbytes = 4;
        }
};

// Override carrier detection for 11g cards like madwifi and prism54g.
class PcapSource11G : public PcapSourceWext {
public:
    PcapSource11G(GlobalRegistry *in_globalreg, string in_name, string in_dev) : 
        PcapSourceWext(in_globalreg, in_name, in_dev) { }
protected:
    carrier_type IEEE80211Carrier();
};

// Override madwifi 11g for FCS
class PcapSource11GFCS : public PcapSource11G {
public:
    PcapSource11GFCS(GlobalRegistry *in_globalreg, string in_name, string in_dev) :
        PcapSource11G(in_globalreg, in_name, in_dev) { 
            fcsbytes = 4;
        }
};
#endif

#ifdef SYS_LINUX
// Override fcs controls to add 4 bytes on wlanng
class PcapSourceWlanng : public PcapSource {
public:
    PcapSourceWlanng(GlobalRegistry *in_globalreg, string in_name, string in_dev) :
        PcapSource(in_globalreg, in_name, in_dev) { 
            fcsbytes = 4;
        }
    int FetchChannel();
protected:
    // Signal levels are pulled from the prism2 or avs headers so leave that as 0
    int last_channel;

    friend int chancontrol_wlanng_avs(CHCONTROL_PARMS);
    friend int chancontrol_wlanng(CHCONTROL_PARMS);
};

// Override packet fetching logic on this one to discard jumbo corrupt packets
// that it likes to generate
class PcapSourceWrt54g : public PcapSource {
public:
    PcapSourceWrt54g(GlobalRegistry *in_globalreg, string in_name, string in_dev) : 
        PcapSource(in_globalreg, in_name, in_dev) { 
        fcsbytes = 4;
    }
    int FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata);
protected:
    carrier_type IEEE80211Carrier();
};
#endif

#ifdef SYS_OPENBSD
class PcapSourceOpenBSDPrism : public PcapSource {
public:
    PcapSourceOpenBSDPrism(GlobalRegistry *in_globalreg, string in_name, string in_dev) :
        PcapSource(in_globalreg, in_name, in_dev) { }
    int FetchChannel();
};
#endif

#if (defined(SYS_FREEBSD) && defined(HAVE_RADIOTAP))
class FreeBSD {
public:
    FreeBSD(const char *ifname);
    virtual ~FreeBSD();

    const char *geterror() const;

    bool monitor_enable(int initch);
    bool monitor_reset(int initch);
    bool chancontrol(int in_ch);

    bool getmediaopt(int& options, int& mode);
    bool setmediaopt(int options, int mode);
    bool getifflags(int& flags);
    bool setifflags(int value);
    bool get80211(int type, int& val, int len, u_int8_t *data);
    bool set80211(int type, int val, int len, u_int8_t *data);
private:
    void perror(const char *, ...);
    void seterror(const char *, ...);
    bool checksocket();

    int s;
    int prev_flags;
    int prev_options;
    int prev_mode;
    int prev_chan;
    char errstr[256];
    string ifname;
};
#endif

#ifdef HAVE_RADIOTAP
class PcapSourceRadiotap : public PcapSource {
public:
    PcapSourceRadiotap(GlobalRegistry *in_globalreg, string in_name, string in_dev) :
        PcapSource(globalreg, in_name, in_dev) { }
    int OpenSource();
protected:
    bool CheckForDLT(int dlt);
};
#endif

// ----------------------------------------------------------------------------
// Registrant and control functions
KisPacketSource *pcapsource_registrant(REGISTRANT_PARMS);

KisPacketSource *pcapsource_file_registrant(REGISTRANT_PARMS);

#ifdef HAVE_LINUX_WIRELESS
KisPacketSource *pcapsource_wext_registrant(REGISTRANT_PARMS);
KisPacketSource *pcapsource_wextfcs_registrant(REGISTRANT_PARMS);
KisPacketSource *pcapsource_ciscowifix_registrant(REGISTRANT_PARMS);
KisPacketSource *pcapsource_11g_registrant(REGISTRANT_PARMS);
KisPacketSource *pcapsource_11gfcs_registrant(REGISTRANT_PARMS);
#endif

#ifdef SYS_LINUX
KisPacketSource *pcapsource_wlanng_registrant(REGISTRANT_PARMS);
KisPacketSource *pcapsource_wrt54g_registrant(REGISTRANT_PARMS);
#endif

#ifdef SYS_OPENBSD
KisPacketSource *pcapsource_openbsdprism2_registrant(REGISTRANT_PARMS);
#endif

#ifdef HAVE_RADIOTAP
KisPacketSource *pcapsource_radiotap_registrant(REGISTRANT_PARMS);
#endif

// Monitor activation
int unmonitor_pcapfile(MONITOR_PARMS);

#ifdef HAVE_LINUX_WIRELESS
// Cisco (old) 
int monitor_cisco(MONITOR_PARMS);
int unmonitor_cisco(MONITOR_PARMS);
// Cisco (new)
int monitor_cisco_wifix(MONITOR_PARMS);
// hostap prism2
int monitor_hostap(MONITOR_PARMS);
int unmonitor_hostap(MONITOR_PARMS);
// orinoco
int monitor_orinoco(MONITOR_PARMS);
int unmonitor_orinoco(MONITOR_PARMS);
// acx100
int monitor_acx100(MONITOR_PARMS);
int unmonitor_acx100(MONITOR_PARMS);
// admtek
int monitor_admtek(MONITOR_PARMS);
int unmonitor_admtek(MONITOR_PARMS);
// ar5k
int monitor_vtar5k(MONITOR_PARMS);
// Madwifi group of cards
int monitor_madwifi_a(MONITOR_PARMS);
int monitor_madwifi_b(MONITOR_PARMS);
int monitor_madwifi_g(MONITOR_PARMS);
int monitor_madwifi_comb(MONITOR_PARMS);
int unmonitor_madwifi(MONITOR_PARMS);
// prism54 needs to override the error messages it gets setting channels
int monitor_prism54g(MONITOR_PARMS);
int unmonitor_prism54g(MONITOR_PARMS);
// Centrino
int monitor_ipw2100(MONITOR_PARMS);
int unmonitor_ipw2100(MONITOR_PARMS);
// "Standard" wext monitor sequence - mostly a helper for other functions
// since most cards that use wext still have custom initialization that
// needs to be done...  Take the errstr here instead of injecting straight
// into the messagebus for non-fatal attempts for some multi-drivers
int monitor_wext(MONITOR_PARMS, char *in_err);
int unmonitor_wext(MONITOR_PARMS);
#endif

#ifdef SYS_LINUX
// wlan-ng modern standard
int monitor_wlanng(MONITOR_PARMS);
// wlan-ng avs
int monitor_wlanng_avs(MONITOR_PARMS);
// linksys wrt54g monitoring
int monitor_wrt54g(MONITOR_PARMS);
#endif

// This should be expanded to handle BSD...
#ifdef SYS_OPENBSD
// Cisco (bsd)
int monitor_openbsd_cisco(MONITOR_PARMS);
// openbsd prism2
int monitor_openbsd_prism2(MONITOR_PARMS);
#endif

// Channel controls
#ifdef HAVE_LINUX_WIRELESS
// Standard wireless extension controls
int chancontrol_wext(CHCONTROL_PARMS);
// Orinoco iwpriv control
int chancontrol_orinoco(CHCONTROL_PARMS);
// Madwifi needs to set mode
int chancontrol_madwifi_ab(CHCONTROL_PARMS);
int chancontrol_madwifi_ag(CHCONTROL_PARMS);
// Prism54 apparently returns a fail code on an iwconfig channel change but
// then works so we need to override the wext failure code
int chancontrol_prism54g(CHCONTROL_PARMS);
// We need a delay here like orinoco
int chancontrol_ipw2100(CHCONTROL_PARMS);
#endif

#ifdef SYS_LINUX
// Modern wlan-ng and wlan-ng avs
int chancontrol_wlanng(CHCONTROL_PARMS);
int chancontrol_wlanng_avs(CHCONTROL_PARMS);
#endif

#ifdef SYS_OPENBSD
// openbsd prism2 controls
int chancontrol_openbsd_prism2(CHCONTROL_PARMS);
#endif

#if (defined(SYS_FREEBSD) && defined(HAVE_RADIOTAP))
int monitor_freebsd(CHCONTROL_PARMS);
int unmonitor_freebsd(CHCONTROL_PARMS);
int chancontrol_freebsd(CHCONTROL_PARMS);
#endif


#endif

#endif

