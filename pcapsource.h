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

extern "C" {
#ifndef HAVE_PCAPPCAP_H
#include <pcap.h>
#include <net/bpf.h>
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

#ifndef DLT_IEEE802_11_RADIO
#define	DLT_IEEE802_11_RADIO	127	/* 802.11 plus WLAN header */
#endif

// Generic pcapsource
class PcapSource : public KisPacketSource {
public:
    PcapSource(string in_name, string in_dev) : KisPacketSource(in_name, in_dev) { }

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
    // FCS byte checker (override)
    virtual int FCSBytes();
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
};

// Open with pcap_dead for pcapfiles - we have a different open and we
// have to kluge fetching the packet descriptor
class PcapSourceFile : public PcapSource {
public:
    PcapSourceFile(string in_name, string in_dev) : PcapSource(in_name, in_dev) { }
    int OpenSource();
    int FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata);
    int FetchDescriptor();
    int FetchChannel();
};

#ifdef SYS_LINUX
// What we need to track on a linux interface to restore the settings
typedef struct linux_ifparm {
    struct sockaddr_in ifaddr; 
    struct sockaddr_in dstaddr; 
    struct sockaddr_in broadaddr; 
    struct sockaddr_in maskaddr; 
    short flags;
    char essid[MAX_SSID_LEN + 1];
    int channel;
};
#endif

// Wireless extention pcapsource - use wext to get the channels.  Everything
// else is straight pcapsource
#ifdef HAVE_LINUX_WIRELESS
class PcapSourceWext : public PcapSource {
public:
    PcapSourceWext(string in_name, string in_dev) : PcapSource(in_name, in_dev) { }
    int FetchChannel();
protected:
    int FetchSignalLevels(int *in_siglev, int *in_noiselev);
};

// FCS trimming for wext cards
class PcapSourceWextFCS : public PcapSourceWext {
public:
    PcapSourceWextFCS(string in_name, string in_dev) :
        PcapSourceWext(in_name, in_dev) { }
protected:
    int FCSBytes();
};

// Override carrier detection for 11g cards like madwifi and prism54g.
class PcapSource11G : public PcapSourceWext {
public:
    PcapSource11G(string in_name, string in_dev) : 
        PcapSourceWext(in_name, in_dev) { }
protected:
    carrier_type IEEE80211Carrier();
};

// Override madwifi 11g for FCS
class PcapSource11GFCS : public PcapSource11G {
public:
    PcapSource11GFCS(string in_name, string in_dev) :
        PcapSource11G(in_name, in_dev) { }
protected:
    int FCSBytes();
};
#endif

#ifdef SYS_LINUX
// Override fcs controls to add 4 bytes on wlanng
class PcapSourceWlanng : public PcapSource {
public:
    PcapSourceWlanng(string in_name, string in_dev) :
        PcapSource(in_name, in_dev) { }
    int FetchChannel();
protected:
    // Signal levels are pulled from the prism2 or avs headers so leave that as 0
    int FCSBytes();
    int last_channel;

    friend int chancontrol_wlanng_avs(const char *in_dev, int in_ch, char *in_err, 
                                      void *in_ext);
    friend int chancontrol_wlanng(const char *in_dev, int in_ch, char *in_err, 
                                  void *in_ext);
};

// Override packet fetching logic on this one to discard jumbo corrupt packets
// that it likes to generate
class PcapSourceWrt54g : public PcapSource {
public:
    PcapSourceWrt54g(string in_name, string in_dev) : PcapSource(in_name, in_dev) { }
    int FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata);
protected:
    carrier_type IEEE80211Carrier();
    int FCSBytes();
};
#endif

#ifdef SYS_OPENBSD
class PcapSourceOpenBSDPrism : public PcapSource {
public:
    PcapSourceOpenBSDPrism(string in_name, string in_dev) :
        PcapSource(in_name, in_dev) { }
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
    char errstr[256];
    string ifname;
};
#endif

#ifdef HAVE_RADIOTAP
class PcapSourceRadiotap : public PcapSource {
public:
    PcapSourceRadiotap(string in_name, string in_dev) :
        PcapSource(in_name, in_dev) { }
    int OpenSource();
    int FetchChannel();
protected:
    bool CheckForDLT(int dlt);
};
#endif

// ----------------------------------------------------------------------------
// Registrant and control functions
KisPacketSource *pcapsource_registrant(string in_name, string in_device,
                                       char *in_err);

KisPacketSource *pcapsource_file_registrant(string in_name, string in_device, 
                                            char *in_err);

#ifdef HAVE_LINUX_WIRELESS
KisPacketSource *pcapsource_wext_registrant(string in_name, string in_device, 
                                            char *in_err);
KisPacketSource *pcapsource_wextfcs_registrant(string in_name, string in_device,
                                               char *in_err);
KisPacketSource *pcapsource_ciscowifix_registrant(string in_name, string in_device, 
                                                  char *in_err);
KisPacketSource *pcapsource_11g_registrant(string in_name, string in_device,
                                           char *in_err);
KisPacketSource *pcapsource_11gfcs_registrant(string in_name, string in_device,
                                              char *in_err);
#endif

#ifdef SYS_LINUX
KisPacketSource *pcapsource_wlanng_registrant(string in_name, string in_device,
                                              char *in_err);
KisPacketSource *pcapsource_wrt54g_registrant(string in_name, string in_device,
                                              char *in_err);
#endif

#ifdef SYS_OPENBSD
KisPacketSource *pcapsource_openbsdprism2_registrant(string in_name, string in_device,
                                                     char *in_err);
#endif

#ifdef HAVE_RADIOTAP
KisPacketSource *pcapsource_radiotap_registrant(string in_name, string in_device,
                                                char *in_err);
#endif

// Monitor activation
#ifdef HAVE_LINUX_WIRELESS
// Cisco (old) 
int monitor_cisco(const char *in_dev, int initch, char *in_err, void **in_if);
// Cisco (new)
int monitor_cisco_wifix(const char *in_dev, int initch, char *in_err, void **in_if);
// hostap prism2
int monitor_hostap(const char *in_dev, int initch, char *in_err, void **in_if);
int unmonitor_hostap(const char *in_dev, int initch, char *in_err, void **in_if);
// orinoco
int monitor_orinoco(const char *in_dev, int initch, char *in_err, void **in_if);
// acx100
int monitor_acx100(const char *in_dev, int initch, char *in_err, void **in_if);
// ar5k
int monitor_vtar5k(const char *in_dev, int initch, char *in_err, void **in_if);
// Madwifi group of cards
int monitor_madwifi_a(const char *in_dev, int initch, char *in_err, void **in_if);
int monitor_madwifi_b(const char *in_dev, int initch, char *in_err, void **in_if);
int monitor_madwifi_g(const char *in_dev, int initch, char *in_err, void **in_if);
int monitor_madwifi_comb(const char *in_dev, int initch, char *in_err, void **in_if);
// prism54 needs to override the error messages it gets setting channels
int monitor_prism54g(const char *in_dev, int initch, char *in_err, void **in_if);
// "Standard" wext monitor sequence - mostly a helper for other functions
// since most cards that use wext still have custom initialization that
// needs to be done.
int monitor_wext(const char *in_dev, int initch, char *in_err, void **in_if);
#endif

#ifdef SYS_LINUX
// wlan-ng modern standard
int monitor_wlanng(const char *in_dev, int initch, char *in_err, void **in_if);
// wlan-ng avs
int monitor_wlanng_avs(const char *in_dev, int initch, char *in_err, void **in_if);
int unmonitor_wlanng_avs(const char *in_dev, int initch, char *in_err, void **in_if);
// linksys wrt54g monitoring
int monitor_wrt54g(const char *in_dev, int initch, char *in_err, void **in_if);
#endif

// This should be expanded to handle BSD...
#ifdef SYS_OPENBSD
// Cisco (bsd)
int monitor_openbsd_cisco(const char *in_dev, int initch, char *in_err, void **in_if);
// openbsd prism2
int monitor_openbsd_prism2(const char *in_dev, int initch, char *in_err, void **in_if);
#endif

// Channel controls
#ifdef HAVE_LINUX_WIRELESS
// Standard wireless extension controls
int chancontrol_wext(const char *in_dev, int in_ch, char *in_err, void *in_ext);
// Orinoco iwpriv control
int chancontrol_orinoco(const char *in_dev, int in_ch, char *in_err, void *in_ext);
// Madwifi needs to set mode
int chancontrol_madwifi_ab(const char *in_dev, int in_ch, char *in_err, void *in_ext);
int chancontrol_madwifi_ag(const char *in_dev, int in_ch, char *in_err, void *in_ext);
// Prism54 apparently returns a fail code on an iwconfig channel change but
// then works so we need to override the wext failure code
int chancontrol_prism54g(const char *in_dev, int in_ch, char *in_err, void *in_ext);
#endif

#ifdef SYS_LINUX
// Modern wlan-ng and wlan-ng avs
int chancontrol_wlanng(const char *in_dev, int in_ch, char *in_err, void *in_ext);
int chancontrol_wlanng_avs(const char *in_dev, int in_ch, char *in_err, void *in_ext);
#endif

#ifdef SYS_OPENBSD
// openbsd prism2 controls
int chancontrol_openbsd_prism2(const char *in_dev, int in_ch, char *in_err, 
                               void *in_ext);
#endif

#if (defined(SYS_FREEBSD) && defined(HAVE_RADIOTAP))
int monitor_freebsd(const char *in_dev, int initch, char *in_err, void **in_if);
int unmonitor_freebsd(const char *in_dev, int initch, char *in_err, void **in_if);
int chancontrol_freebsd(const char *in_dev, int in_ch, char *in_err, void *in_ext);
#endif


#endif

#endif

