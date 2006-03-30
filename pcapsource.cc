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

#include "config.h"

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#ifdef HAVE_LINUX_WIRELESS
// Because some kernels include ethtool which breaks horribly...
// The stock ones don't but others seem to
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

#include <linux/wireless.h>
#endif

#if defined(SYS_OPENBSD) || defined(SYS_NETBSD)
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_media.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <dev/ic/if_wi_ieee.h>

#ifdef HAVE_RADIOTAP
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_radiotap.h>
#endif

#endif

#ifdef SYS_FREEBSD
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_media.h>

#ifdef HAVE_RADIOTAP
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_radiotap.h>
#endif

#endif

#if (defined(SYS_LINUX) && defined(HAVE_RADIOTAP))
// We have to use a local include for now
#include "linux_ieee80211_radiotap.h"
#endif

#ifdef HAVE_RADIOTAP
// Hack around some headers that don't seem to define all of these
#ifndef IEEE80211_CHAN_TURBO
#define IEEE80211_CHAN_TURBO    0x0010  /* Turbo channel */
#endif
#ifndef IEEE80211_CHAN_CCK
#define IEEE80211_CHAN_CCK      0x0020  /* CCK channel */ 
#endif
#ifndef IEEE80211_CHAN_OFDM
#define IEEE80211_CHAN_OFDM     0x0040  /* OFDM channel */
#endif
#ifndef IEEE80211_CHAN_2GHZ
#define IEEE80211_CHAN_2GHZ     0x0080  /* 2 GHz spectrum channel. */
#endif
#ifndef IEEE80211_CHAN_5GHZ
#define IEEE80211_CHAN_5GHZ     0x0100  /* 5 GHz spectrum channel */
#endif
#ifndef IEEE80211_CHAN_PASSIVE
#define IEEE80211_CHAN_PASSIVE  0x0200  /* Only passive scan allowed */
#endif
#ifndef IEEE80211_CHAN_DYN
#define IEEE80211_CHAN_DYN      0x0400  /* Dynamic CCK-OFDM channel */
#endif
#ifndef IEEE80211_CHAN_GFSK
#define IEEE80211_CHAN_GFSK     0x0800  /* GFSK channel (FHSS PHY) */
#endif

#include "tcpdump-extract.h"
#include <stdarg.h>
#endif

#include "pcapsource.h"
#include "util.h"

#ifdef HAVE_LIBPCAP

// This is such a bad thing to do...
// #include <pcap-int.h>

// Pcap global callback structs
pcap_pkthdr callback_header;
u_char callback_data[MAX_PACKET_LEN];

// Open a source
int PcapSource::OpenSource() {
    channel = 0;

    errstr[0] = '\0';

    char *unconst = strdup(interface.c_str());

    pd = pcap_open_live(unconst, MAX_PACKET_LEN, 1, 1000, errstr);

    #if defined (SYS_OPENBSD) || defined(SYS_NETBSD) && defined(HAVE_RADIOTAP)
    /* Request desired DLT on multi-DLT systems that default to EN10MB. We do this
       later anyway but doing it here ensures we have the desired DLT from the get go. */
     pcap_set_datalink(pd, DLT_IEEE802_11_RADIO);
    #endif

    free(unconst);

    if (strlen(errstr) > 0)
        return -1; // Error is already in errstr

    paused = 0;

    errstr[0] = '\0';

    num_packets = 0;

    if (DatalinkType() < 0)
        return -1;

#ifdef HAVE_PCAP_NONBLOCK
    pcap_setnonblock(pd, 1, errstr);
#elif !defined(SYS_OPENBSD)
    // do something clever  (Thanks to Guy Harris for suggesting this).
    int save_mode = fcntl(pcap_get_selectable_fd(pd), F_GETFL, 0);
    if (fcntl(pcap_get_selectable_fd(pd), F_SETFL, save_mode | O_NONBLOCK) < 0) {
        snprintf(errstr, 1024, "fcntl failed, errno %d (%s)",
                 errno, strerror(errno));
    }
#endif

    if (strlen(errstr) > 0)
        return -1; // Ditto
    
    return 1;
}

// Datalink, override as appropriate
carrier_type PcapSource::IEEE80211Carrier() {
    int ch = FetchChannel();

    if (ch > 0 && ch <= 14)
        return carrier_80211b;
    else if (ch > 34)
        return carrier_80211a;

    return carrier_unknown;
}

// Signal levels
int PcapSource::FetchSignalLevels(int *in_siglev, int *in_noiselev) {
    *in_siglev = 0;
    *in_noiselev = 0;
    return 0;
}

// Errorcheck the datalink type
int PcapSource::DatalinkType() {
    datalink_type = pcap_datalink(pd);

    // Blow up if we're not valid 802.11 headers
#if (defined(SYS_FREEBSD) || defined(SYS_OPENBSD)) || defined(SYS_NETBSD)
    if (datalink_type == DLT_EN10MB) {
        fprintf(stderr, "WARNING:  pcap reports link type of EN10MB but we'll fake "
                "it on BSD.\n"
                "This may not work the way we want it to.\n");
#if (defined(SYS_FREEBSD) || defined(SYS_NETBSD) && !defined(HAVE_RADIOTAP))
        fprintf(stderr, "WARNING:  Some Free- and Net- BSD drivers do not report "
                "rfmon packets\n"
                "correctly.  Kismet will probably not run correctly.  For better\n"
                "support, you should upgrade to a version of *BSD with Radiotap.\n");
#endif
        datalink_type = KDLT_BSD802_11;
    }
#else
    if (datalink_type == DLT_EN10MB) {
        snprintf(errstr, 1024, "pcap reported netlink type 1 (EN10MB) for %s.  "
                 "This probably means you're not in RFMON mode or your drivers are "
                 "reporting a bad value.  Make sure you have the correct drivers "
                 "and that entering monitor mode succeeded.", interface.c_str());
        return -1;
    }
#endif

    // Little hack to give an intelligent error report for radiotap
#ifndef HAVE_RADIOTAP
    if (datalink_type == DLT_IEEE802_11_RADIO) {
        snprintf(errstr, 1024, "FATAL: Radiotap link type reported but radiotap "
                 "support was not compiled into Kismet.");
        return -1;
    }
#endif
    
    if (datalink_type != KDLT_BSD802_11 && datalink_type != DLT_IEEE802_11 &&
        datalink_type != DLT_PRISM_HEADER &&
        datalink_type != DLT_IEEE802_11_RADIO) {
        fprintf(stderr, "WARNING:  Unknown link type %d reported.  Continuing on "
                "blindly...\n", datalink_type);
    }

    return 1;
}

int PcapSource::CloseSource() {
    pcap_close(pd);
    return 1;
}

int PcapSource::FetchDescriptor() {
    return pcap_get_selectable_fd(pd);
}

void PcapSource::Callback(u_char *bp, const struct pcap_pkthdr *header,
                                 const u_char *in_data) {
    memcpy(&callback_header, header, sizeof(pcap_pkthdr));
    memcpy(callback_data, in_data, kismin(header->len, MAX_PACKET_LEN));
}

int PcapSource::FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    int ret;
    //unsigned char *udata = '\0';

    if ((ret = pcap_dispatch(pd, 1, PcapSource::Callback, NULL)) < 0) {
        // Is the interface still here and just not running?  Lets give a more intelligent
        // error if that looks to be the case.
        ret = 0;

        // Do something smarter here in the future
#ifdef SYS_LINUX
        short flags = 0;
        // Are we able to fetch the interface, and is it running?
        ret = Ifconfig_Get_Flags(interface.c_str(), errstr, &flags);
        if (ret >= 0 && (flags & IFF_UP) == 0) {
            snprintf(errstr, 1024, "Reading packet from pcap failed, interface is no longer up.  Usually this "
                     "happens when a DHCP client times out and turns off the interface.  See the Troubleshooting "
                     "section of the README for more information.");
        } else {
#endif
            snprintf(errstr, 1024, "Reading packet from pcap failed, interface no longer available.");
#ifdef SYS_LINUX
        }
        return -1;
#endif
    }

    if (ret == 0)
        return 0;

    if (paused || ManglePacket(packet, data, moddata) == 0) {
        return 0;
    }

    num_packets++;

    // Set the name
    snprintf(packet->sourcename, 32, "%s", name.c_str());
    
    // Set the parameters
    memcpy(&packet->parm, &parameters, sizeof(packet_parm));
    
    return(packet->caplen);
}

int PcapSource::ManglePacket(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    int ret = 0;
    memset(packet, 0, sizeof(kis_packet));
    
    packet->ts = callback_header.ts;
    packet->data = data;
    packet->moddata = moddata;
    packet->modified = 0;

    if (gpsd != NULL) {
        gpsd->FetchLoc(&packet->gps_lat, &packet->gps_lon, &packet->gps_alt,
                       &packet->gps_spd, &packet->gps_heading, &packet->gps_fix);
    }

    if (datalink_type == DLT_PRISM_HEADER) {
        ret = Prism2KisPack(packet, data, moddata);
    } else if (datalink_type == KDLT_BSD802_11) {
        ret = BSD2KisPack(packet, data, moddata);
#ifdef HAVE_RADIOTAP
    } else if (datalink_type == DLT_IEEE802_11_RADIO) {
        ret = Radiotap2KisPack(packet, data, moddata);
#endif
    } else {
        packet->caplen = kismin(callback_header.caplen, (uint32_t) MAX_PACKET_LEN);
        packet->len = packet->caplen;
        memcpy(packet->data, callback_data, packet->caplen);
        ret = 1;
    }

    // Fetch the signal levels if we know how and it hasn't been already
    if (packet->signal == 0 && packet->noise == 0)
        FetchSignalLevels(&(packet->signal), &(packet->noise));
    
    // Fetch the channel if we know how and it hasn't been filled in already
    if (packet->channel == 0)
        packet->channel = FetchChannel();

#if 0
	// Maybe this isn't a great idea
    if (packet->carrier == carrier_unknown)
        packet->carrier = IEEE80211Carrier();
#endif

    return ret;
}

int PcapSource::Prism2KisPack(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    int header_found = 0;
    unsigned int callback_offset = 0;

    // See if we have an AVS wlan header...
    avs_80211_1_header *v1hdr = (avs_80211_1_header *) callback_data;
    if (callback_header.caplen >= sizeof(avs_80211_1_header) &&
        ntohl(v1hdr->version) == 0x80211001 && header_found == 0) {

        if (ntohl(v1hdr->length) > callback_header.caplen) {
            snprintf(errstr, 1024, "pcap prism2 converter got corrupted AVS header length");
            packet->len = 0;
            packet->caplen = 0;
            return 0;
        }

        header_found = 1;

        // Get the FCS for this subclass
        int fcs = FCSBytes();

        // Subtract the packet FCS since kismet doesn't do anything terribly bright
        // with it right now

		if (callback_header.caplen < (ntohl(v1hdr->length) + fcs)) {
			fprintf(stderr, "*** WARNING - Strangeness with prism2 avs v1hdr->length "
					"and FCS size\n");
            snprintf(errstr, 1024, "pcap prism2 converter got corrupted AVS "
					 "header length");
            packet->len = 0;
            packet->caplen = 0;
            return 0;
        }
	
		// This should still be protected since a negative rollover on an unsigned
		// should go super-positive and overflow the max packet len and get trimmed
        packet->caplen = kismin(callback_header.caplen - ntohl(v1hdr->length) - fcs, 
                                (uint32_t) MAX_PACKET_LEN);
        packet->len = packet->caplen;

        /*
        packet->caplen = kismin(callback_header.caplen - 4 - ntohl(v1hdr->length), (uint32_t) MAX_PACKET_LEN);
        packet->len = packet->caplen;
        */

        callback_offset = ntohl(v1hdr->length);

        // We REALLY need to do something smarter about this and handle the RSSI
        // type instead of just copying
        packet->signal = ntohl(v1hdr->ssi_signal);
        packet->noise = ntohl(v1hdr->ssi_noise);

        packet->channel = ntohl(v1hdr->channel);

        switch (ntohl(v1hdr->phytype)) {
            case 1:
                packet->carrier = carrier_80211fhss;
				break;
            case 2:
                packet->carrier = carrier_80211dsss;
                break;
            case 4:
            case 5:
                packet->carrier = carrier_80211b;
                break;
            case 6:
            case 7:
                packet->carrier = carrier_80211g;
                break;
            case 8:
                packet->carrier = carrier_80211a;
                break;
            default:
                packet->carrier = carrier_unknown;
                break;
        }

        packet->encoding = (encoding_type) ntohl(v1hdr->encoding);

        packet->datarate = (int) ntohl(v1hdr->datarate);
    }

    // See if we have a prism2 header
    wlan_ng_prism2_header *p2head = (wlan_ng_prism2_header *) callback_data;
    if (callback_header.caplen >= sizeof(wlan_ng_prism2_header) &&
        header_found == 0) {

        header_found = 1;

        // Get the FCS
        int fcs = FCSBytes();

		/* We don't *really* have to pay attention to the wlanng-prism2 frame
		 * lengths, as long as we obey the capture frame lengths, so we'll
		 * ignore this for now.  Ethereal also ignores this length field. */
#if 0
        if (p2head->frmlen.data > callback_header.caplen) {
            snprintf(errstr, 1024, "pcap prism2 converter got corrupted prism2 "
					 "header length");
            packet->len = 0;
            packet->caplen = 0;
			printf("debug - corrupt avs header len %d vs %d\n",
				   p2head->frmlen.data, callback_header.caplen);
            return 0;
        }
#endif

		// Do a little more checking just in case
		if (callback_header.caplen < (sizeof(wlan_ng_prism2_header) + fcs)) {
			fprintf(stderr, "*** WARNING - Strangeness with prism2 header len "
					"and FCS size\n");
            snprintf(errstr, 1024, "pcap prism2 converter got corrupted prism2 "
					 "header length");
            packet->len = 0;
            packet->caplen = 0;
            return 0;
        }

		// We're safe here because of the initial test -- no matter what garbage
		// is in here, we're bigger than a prism2 header, so we can read the data
		// and set the offset.

        // Subtract the packet FCS since kismet doesn't do anything terribly bright
        // with it right now
        packet->caplen = kismin(callback_header.caplen - 
								sizeof(wlan_ng_prism2_header) - fcs,
								(uint32_t) MAX_PACKET_LEN);
        packet->len = packet->caplen;

        // Set our offset for extracting the actual data
        callback_offset = sizeof(wlan_ng_prism2_header);

        // packet->quality = p2head->sq.data;
        packet->signal = p2head->signal.data;
        packet->noise = p2head->noise.data;

        packet->channel = p2head->channel.data;
    }

    if (header_found == 0) {
        snprintf(errstr, 1024, "pcap prism2 converter saw undersized capture frame");
        packet->len = 0;
        packet->caplen = 0;
        return 0;
    }

	// This should be set up safely since all of the prior adjustments to caplen
	// take it into account
    memcpy(packet->data, callback_data + callback_offset, packet->caplen);

    return 1;

}

int PcapSource::BSD2KisPack(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    int callback_offset = 0;

    // Process our hacked in BSD type
    if (callback_header.caplen < sizeof(bsd_80211_header)) {
        snprintf(errstr, 1024, "pcap bsd converter saw undersized capture frame for bsd header.");
        packet->len = 0;
        packet->caplen = 0;
        return 0;
    }

    packet->caplen = kismin(callback_header.caplen - sizeof(bsd_80211_header), 
                            (uint32_t) MAX_PACKET_LEN);
    packet->len = packet->caplen;

    bsd_80211_header *bsdhead = (bsd_80211_header *) callback_data;

    packet->signal = bsdhead->wi_signal;
    packet->noise = bsdhead->wi_silence;

    // Set our offset
    callback_offset = sizeof(bsd_80211_header);
    memcpy(packet->data, callback_data + callback_offset, 24);

    // Adjust for driver appended headers
    if (packet->data[0] > 0x08) {
        packet->len -= 22;
        packet->caplen -= 22;
        memcpy(packet->data + 24, callback_data + callback_offset + 46, 
               packet->caplen - 2);
    } else {
        packet->len -= 30;
        packet->caplen -= 30;
        memcpy(packet->data + 24, callback_data + callback_offset + 46, 
               packet->caplen - 2);
    }

    return 1;
}

#ifdef HAVE_RADIOTAP
/*
 * Convert MHz frequency to IEEE channel number.
 */
static u_int ieee80211_mhz2ieee(u_int freq, u_int flags) {
    if (flags & IEEE80211_CHAN_2GHZ) {		/* 2GHz band */
	if (freq == 2484)
	    return 14;
	if (freq < 2484)
	    return (freq - 2407) / 5;
	else
	    return 15 + ((freq - 2512) / 20);
    } else if (flags & IEEE80211_CHAN_5GHZ) {	/* 5Ghz band */
	return (freq - 5000) / 5;
    } else {					/* either, guess */
	if (freq == 2484)
	    return 14;
	if (freq < 2484)
	    return (freq - 2407) / 5;
	if (freq < 5000)
	    return 15 + ((freq - 2512) / 20);
	return (freq - 5000) / 5;
    }
}

/*
 * Useful combinations of channel characteristics.
 */
#define	IEEE80211_CHAN_FHSS \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_GFSK)
#define	IEEE80211_CHAN_A \
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_B \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK)
#define	IEEE80211_CHAN_PUREG \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_G \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)
#define	IEEE80211_CHAN_T \
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM | IEEE80211_CHAN_TURBO)

#define	IEEE80211_IS_CHAN_FHSS(_flags) \
	((_flags & IEEE80211_CHAN_FHSS) == IEEE80211_CHAN_FHSS)
#define	IEEE80211_IS_CHAN_A(_flags) \
	((_flags & IEEE80211_CHAN_A) == IEEE80211_CHAN_A)
#define	IEEE80211_IS_CHAN_B(_flags) \
	((_flags & IEEE80211_CHAN_B) == IEEE80211_CHAN_B)
#define	IEEE80211_IS_CHAN_PUREG(_flags) \
	((_flags & IEEE80211_CHAN_PUREG) == IEEE80211_CHAN_PUREG)
#define	IEEE80211_IS_CHAN_G(_flags) \
	((_flags & IEEE80211_CHAN_G) == IEEE80211_CHAN_G)
#define	IEEE80211_IS_CHAN_T(_flags) \
	((_flags & IEEE80211_CHAN_T) == IEEE80211_CHAN_T)

int PcapSource::Radiotap2KisPack(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
#define BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define BITNO_2(x) (((x) & 2) ? 1 : 0)
#define BIT(n)	(1 << n)
    union {
        int8_t	i8;
        int16_t	i16;
        u_int8_t	u8;
        u_int16_t	u16;
        u_int32_t	u32;
        u_int64_t	u64;
    } u;
    union {
        int8_t		i8;
        int16_t		i16;
        u_int8_t	u8;
        u_int16_t	u16;
        u_int32_t	u32;
        u_int64_t	u64;
    } u2;
    struct ieee80211_radiotap_header *hdr;
    u_int32_t present, next_present;
    u_int32_t *presentp, *last_presentp;
    enum ieee80211_radiotap_type bit;
    int bit0;
    const u_char *iter;
	// do we cut the FCS?  this is influenced by the radiotap headers and 
	// by the class fcsbytes value in case of forced fcs settings (like openbsd
	// atheros and Ralink USB at the moment)
	int fcs_cut = 0;

    if (callback_header.caplen < sizeof(*hdr)) {
        packet->len = 0;
        packet->caplen = 0;
        return 0;
    }
    hdr = (struct ieee80211_radiotap_header *) callback_data;
    if (callback_header.caplen < hdr->it_len) {
        packet->len = 0;
        packet->caplen = 0;
        return 0;
    }

    for (last_presentp = &hdr->it_present;
         (*last_presentp & BIT(IEEE80211_RADIOTAP_EXT)) != 0 &&
         (u_char*)(last_presentp + 1) <= data + hdr->it_len;
         last_presentp++);

    /* are there more bitmap extensions than bytes in header? */
    if ((*last_presentp & BIT(IEEE80211_RADIOTAP_EXT)) != 0) {
        packet->len = 0;
        packet->caplen = 0;
        return 0;
    }

    packet->caplen = packet->len = callback_header.caplen;

    iter = (u_char*)(last_presentp + 1);

    for (bit0 = 0, presentp = &hdr->it_present; presentp <= last_presentp;
         presentp++, bit0 += 32) {
        for (present = *presentp; present; present = next_present) {
            /* clear the least significant bit that is set */
            next_present = present & (present - 1);

            /* extract the least significant bit that is set */
            bit = (enum ieee80211_radiotap_type)
                (bit0 + BITNO_32(present ^ next_present));

            switch (bit) {
                case IEEE80211_RADIOTAP_FLAGS:
                case IEEE80211_RADIOTAP_RATE:
                case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
                case IEEE80211_RADIOTAP_DB_ANTNOISE:
                case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                case IEEE80211_RADIOTAP_DBM_ANTNOISE:
                case IEEE80211_RADIOTAP_ANTENNA:
                    u.u8 = *iter++;
                    break;
                case IEEE80211_RADIOTAP_DBM_TX_POWER:
                    u.i8 = *iter++;
                    break;
                case IEEE80211_RADIOTAP_CHANNEL:
                    u.u16 = EXTRACT_LE_16BITS(iter);
                    iter += sizeof(u.u16);
                    u2.u16 = EXTRACT_LE_16BITS(iter);
                    iter += sizeof(u2.u16);
                    break;
                case IEEE80211_RADIOTAP_FHSS:
                case IEEE80211_RADIOTAP_LOCK_QUALITY:
                case IEEE80211_RADIOTAP_TX_ATTENUATION:
                case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
                    u.u16 = EXTRACT_LE_16BITS(iter);
                    iter += sizeof(u.u16);
                    break;
                case IEEE80211_RADIOTAP_TSFT:
                    u.u64 = EXTRACT_LE_64BITS(iter);
                    iter += sizeof(u.u64);
                    break;
                default:
                    /* this bit indicates a field whose
                     * size we do not know, so we cannot
                     * proceed.
                     */
                    next_present = 0;
                    continue;
            }

            switch (bit) {
                case IEEE80211_RADIOTAP_CHANNEL:
                    packet->channel = ieee80211_mhz2ieee(u.u16, u2.u16);
                    if (IEEE80211_IS_CHAN_FHSS(u2.u16))
                        packet->carrier = carrier_80211dsss;
                    else if (IEEE80211_IS_CHAN_A(u2.u16))
                        packet->carrier = carrier_80211a;
                    else if (IEEE80211_IS_CHAN_B(u2.u16))
                        packet->carrier = carrier_80211b;
                    else if (IEEE80211_IS_CHAN_PUREG(u2.u16))
                        packet->carrier = carrier_80211g;
                    else if (IEEE80211_IS_CHAN_G(u2.u16))
                        packet->carrier = carrier_80211g;
                    else if (IEEE80211_IS_CHAN_T(u2.u16))
                        packet->carrier = carrier_80211a;/*XXX*/
                    else
                        packet->carrier = carrier_unknown;
                    break;
                case IEEE80211_RADIOTAP_RATE:
		    /* strip basic rate bit & convert to kismet units */
                    packet->datarate = ((u.u8 &~ 0x80) / 2) * 10;
                    break;
                case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
                    packet->signal = u.i8;
                    break;
                case IEEE80211_RADIOTAP_DB_ANTNOISE:
                    packet->noise = u.i8;
                    break;
				case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
					packet->signal = u.i8;
					break;
				case IEEE80211_RADIOTAP_DBM_ANTNOISE:
					packet->noise = u.i8;
					break;
                case IEEE80211_RADIOTAP_FLAGS:
                    if (u.u8 & IEEE80211_RADIOTAP_F_FCS)
                         fcs_cut = 4;
                    break;
#if 0
                case IEEE80211_RADIOTAP_FHSS:
                    printf("fhset %d fhpat %d ", u.u16 & 0xff,
                           (u.u16 >> 8) & 0xff);
                    break;
                case IEEE80211_RADIOTAP_LOCK_QUALITY:
                    printf("%u sq ", u.u16);
                    break;
                case IEEE80211_RADIOTAP_TX_ATTENUATION:
                    printf("%d tx power ", -(int)u.u16);
                    break;
                case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
                    printf("%ddB tx power ", -(int)u.u16);
                    break;
                case IEEE80211_RADIOTAP_DBM_TX_POWER:
                    printf("%ddBm tx power ", u.i8);
                    break;
                case IEEE80211_RADIOTAP_FLAGS:
                    if (u.u8 & IEEE80211_RADIOTAP_F_CFP)
                        printf("cfp ");
                    if (u.u8 & IEEE80211_RADIOTAP_F_SHORTPRE)
                        printf("short preamble ");
                    if (u.u8 & IEEE80211_RADIOTAP_F_WEP)
                        printf("wep ");
                    if (u.u8 & IEEE80211_RADIOTAP_F_FRAG)
                        printf("fragmented ");
                    break;
                case IEEE80211_RADIOTAP_ANTENNA:
                    printf("antenna %u ", u.u8);
                    break;
                case IEEE80211_RADIOTAP_TSFT:
                    printf("%llus tsft ", u.u64);
                    break;
#endif
                default:
                    break;
            }
        }
    }

	/* Check the fcs for the source */
	if (FCSBytes() != 0)
		fcs_cut = FCSBytes();

    /* copy data down over radiotap header */
    packet->caplen -= (hdr->it_len + fcs_cut);
    packet->len -= (hdr->it_len + fcs_cut);
    memcpy(packet->data, callback_data + hdr->it_len, packet->caplen);

    return 1;
#undef BITNO_32
#undef BITNO_16
#undef BITNO_8
#undef BITNO_4
#undef BITNO_2
#undef BIT
}
#endif

int PcapSource::FetchChannel() {
    return 0;
}

// Open an offline file with pcap
int PcapSourceFile::OpenSource() {
    channel = 0;

    errstr[0] = '\0';

    pd = pcap_open_offline(interface.c_str(), errstr);

    if (strlen(errstr) > 0)
        return -1; // Error is already in errstr

    paused = 0;

    errstr[0] = '\0';

    num_packets = 0;

    if (DatalinkType() < 0)
        return -1;
    
    return 1;
}

// Nasty hack into pcap priv functions to get the file descriptor.  This
// most likely is a bad idea.
#if 0
int PcapSourceFile::FetchDescriptor() {
    return fileno(pd->sf.rfile);
}
#endif

int PcapSourceFile::FetchChannel() {
    return 0;
}

int PcapSourceFile::FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    int ret;
    //unsigned char *udata = '\0';

    ret = pcap_dispatch(pd, 1, PcapSource::Callback, NULL);

    if (ret < 0) {
        snprintf(errstr, 1024, "Pcap Get Packet pcap_dispatch() failed");
        return -1;
    } else if (ret == 0) {
        snprintf(errstr, 1024, "Pcap file reached end of capture.");
        return -1;
    }

    if (paused || ManglePacket(packet, data, moddata) == 0) {
        return 0;
    }

    // Set the name
    snprintf(packet->sourcename, 32, "%s", name.c_str());
    
    // Set the parameters
    memcpy(&(packet->parm), &parameters, sizeof(packet_parm));
    

    num_packets++;

    return(packet->caplen);
}

#ifdef HAVE_LINUX_WIRELESS
// Simple alias to our ifcontrol interface
int PcapSourceWext::FetchChannel() {
    // Use wireless extensions to get the channel
    return Iwconfig_Get_Channel(interface.c_str(), errstr);
}

int PcapSourceWext::FetchSignalLevels(int *in_siglev, int *in_noiselev) {
    int raw_siglev, raw_noiselev, ret;

    if ((ret = Iwconfig_Get_Levels(interface.c_str(), errstr, 
                                   &raw_siglev, &raw_noiselev)) < 0)
        return ret;

    (*in_siglev) = raw_siglev;
    (*in_noiselev) = raw_noiselev;

    return 0;
}

// Carrier override
carrier_type PcapSource11G::IEEE80211Carrier() {
    int ch = FetchChannel();

    if (ch > 0 && ch <= 14)
        return carrier_80211g;
    else if (ch > 34)
        return carrier_80211a;

    return carrier_unknown;
}

#endif

#ifdef SYS_LINUX

int PcapSourceWlanng::FetchChannel() {
    // Use wireless extensions to get the channel if we can
#ifdef HAVE_LINUX_WIRELESS
    return Iwconfig_Get_Channel(interface.c_str(), errstr);
#else
    return last_channel;
#endif
}

// Handle badly formed jumbo packets from the drivers
int PcapSourceWrt54g::FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    int ret;
    //unsigned char *udata = '\0';

    if ((ret = pcap_dispatch(pd, 1, PcapSource::Callback, NULL)) < 0) {
        snprintf(errstr, 1024, "Pcap Get Packet pcap_dispatch() failed");
        return -1;
    }

    if (ret == 0)
        return 0;

    if (paused || ManglePacket(packet, data, moddata) == 0) {
        return 0;
    }

    // Junk packets that are too big, this is the only real way to detect crap
    // packets...
    if (packet->caplen == MAX_PACKET_LEN) {
        // printf("debug - dropping large wrt54g packet\n");
        return 0;
    }
    
    num_packets++;

    // Set the name
    snprintf(packet->sourcename, 32, "%s", name.c_str());
    
    // Set the parameters
    memcpy(&packet->parm, &parameters, sizeof(packet_parm));
    
    return(packet->caplen);
}

carrier_type PcapSourceWrt54g::IEEE80211Carrier() {
    int ch = FetchChannel();

    if (ch > 0 && ch <= 14)
        return carrier_80211g;
    else if (ch > 34)
        return carrier_80211a;

    return carrier_unknown;
}
#endif

#ifdef SYS_OPENBSD
int PcapSourceOpenBSDPrism::FetchChannel() {
    struct wi_req wreq;                                                     
    struct ifreq ifr;                                                       
    int skfd;

	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, 1024, "Failed to create AF_INET socket: %s",
                 strerror(errno));
		return -1;
	}

    bzero((char *)&wreq, sizeof(wreq));                                     
    wreq.wi_len = WI_MAX_DATALEN;                                           
    wreq.wi_type = WI_RID_CURRENT_CHAN; 

    bzero((char *)&ifr, sizeof(ifr));                                       
    strlcpy(ifr.ifr_name, interface.c_str(), sizeof(ifr.ifr_name));
    ifr.ifr_data = (caddr_t)&wreq;                                          

	if (ioctl(skfd, SIOCGWAVELAN, &ifr) < 0) {
        close(skfd);
		snprintf(errstr, 1024, "Channel get ioctl failed: %s",
                 strerror(errno));
		return -1;
	}

    close(skfd);
    return wreq.wi_val[0];                                                  
}
#endif

#if (defined(HAVE_RADIOTAP) && (defined(SYS_NETBSD) || defined(SYS_OPENBSD) || defined(SYS_FREEBSD)))
int PcapSourceRadiotap::OpenSource() {
    // XXX this is a hack to avoid duplicating code
    int s = PcapSource::OpenSource();
    if (s < 0)
	return s;
    if (!CheckForDLT(DLT_IEEE802_11_RADIO)) {
	snprintf(errstr, 1024, "No support for radiotap data link");
	return -1;
    } else {
	(void) pcap_set_datalink(pd, DLT_IEEE802_11_RADIO);
	datalink_type = DLT_IEEE802_11_RADIO;
	return s;
    }
}

// Check for data link type support
bool PcapSourceRadiotap::CheckForDLT(int dlt)
{
    bool found = false;
    int i, n, *dl;
    n = pcap_list_datalinks(pd, &dl);
    for (i = 0; i < n; i++)
	if (dl[i] == dlt) {
	    found = true;
	    break;
	}
    free(dl);
    return found;
}

int PcapSourceRadiotap::FetchChannel() {
    int chan;
    RadiotapBSD bsd(interface.c_str());
    if (!bsd.get80211(IEEE80211_IOC_CHANNEL, chan, 0, NULL)) {
        return -1;
    }
    return chan;
}

#endif

// ----------------------------------------------------------------------------
// Registrant and control functions outside of the class

KisPacketSource *pcapsource_registrant(string in_name, string in_device,
                                       char *in_err) {
    return new PcapSource(in_name, in_device);
}

KisPacketSource *pcapsource_file_registrant(string in_name, string in_device,
                                            char *in_err) {
    return new PcapSourceFile(in_name, in_device);
}

#ifdef HAVE_LINUX_WIRELESS
KisPacketSource *pcapsource_wext_registrant(string in_name, string in_device, 
                                            char *in_err) {
    return new PcapSourceWext(in_name, in_device);
}

KisPacketSource *pcapsource_wextfcs_registrant(string in_name, string in_device,
                                               char *in_err) {
    return new PcapSourceWextFCS(in_name, in_device);
}

KisPacketSource *pcapsource_ciscowifix_registrant(string in_name, string in_device, char *in_err) {
    vector<string> devbits = StrTokenize(in_device, ":");

    if (devbits.size() < 2) {
        snprintf(in_err, STATUS_MAX, "Invalid device pair '%s'", in_device.c_str());
        return NULL;
    }

    return new PcapSourceWext(in_name, devbits[1]);
}

KisPacketSource *pcapsource_11g_registrant(string in_name, string in_device,
                                           char *in_err) {
    return new PcapSource11G(in_name, in_device);
}

KisPacketSource *pcapsource_11gfcs_registrant(string in_name, string in_device,
                                              char *in_err) {
    return new PcapSource11GFCS(in_name, in_device);
}

#endif

#ifdef SYS_LINUX
KisPacketSource *pcapsource_wlanng_registrant(string in_name, string in_device,
                                              char *in_err) {
    return new PcapSourceWlanng(in_name, in_device);
}

KisPacketSource *pcapsource_wrt54g_registrant(string in_name, string in_device,
                                              char *in_err) {
    vector<string> devbits = StrTokenize(in_device, ":");

    if (devbits.size() < 2) {
		return new PcapSourceWrt54g(in_name, in_device);
    }

	return new PcapSourceWrt54g(in_name, devbits[1]);
}
#endif

#ifdef SYS_OPENBSD
KisPacketSource *pcapsource_openbsdprism2_registrant(string in_name, string in_device,
                                                     char *in_err) {
    return new PcapSourceOpenBSDPrism(in_name, in_device);
}
#endif

#if (defined(HAVE_RADIOTAP) && (defined(SYS_NETBSD) || defined(SYS_OPENBSD) || defined(SYS_FREEBSD)))
KisPacketSource *pcapsource_radiotap_registrant(string in_name, string in_device,
                                                     char *in_err) {
    return new PcapSourceRadiotap(in_name, in_device);
}
#endif

int unmonitor_pcapfile(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    return 0;
}

// Monitor commands
#ifdef HAVE_LINUX_WIRELESS
// Cisco uses its own config file in /proc to control modes
int monitor_cisco(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    FILE *cisco_config;
    char cisco_path[128];

    linux_ifparm *ifparm = (linux_ifparm *) malloc(sizeof(linux_ifparm));
    (*in_if) = ifparm;

    if (Ifconfig_Get_Flags(in_dev, in_err, &ifparm->flags) < 0) {
        return -1;
    }

    if (Iwconfig_Get_SSID(in_dev, in_err, ifparm->essid) < 0)
        return -1;

    if ((ifparm->channel = Iwconfig_Get_Channel(in_dev, in_err)) < 0)
        return -1;

    if (Iwconfig_Get_Mode(in_dev, in_err, &ifparm->mode) < 0)
        return -1;

    if (Ifconfig_Delta_Flags(in_dev, in_err, IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0)
        return -1;

    // Try the iwpriv
    if (Iwconfig_Set_IntPriv(in_dev, "setRFMonitor", 1, 0, in_err) >= 0) {
        return 0;
    }

    // Zero the ssid - nonfatal
    Iwconfig_Set_SSID(in_dev, in_err, NULL);
   
    // Build the proc control path
    snprintf(cisco_path, 128, "/proc/driver/aironet/%s/Config", in_dev);

    if ((cisco_config = fopen(cisco_path, "w")) == NULL) {
        snprintf(in_err, STATUS_MAX, "Unable to open cisco control file '%s' %d:%s",
                 cisco_path, errno, strerror(errno));
        return -1;
    }

    fprintf(cisco_config, "Mode: r\n");
    fprintf(cisco_config, "Mode: y\n");
    fprintf(cisco_config, "XmitPower: 1\n");

    fclose(cisco_config);

    // Channel can't be set on cisco with these drivers.

    return 0;
}

int unmonitor_cisco(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    linux_ifparm *ifparm = (linux_ifparm *) (*in_if);
    int ret = -1;

    // Try the iwpriv
    if (Iwconfig_Set_IntPriv(in_dev, "setRFMonitor", 0, 0, in_err) >= 0) {
        // If we're the new drivers, unmonitor
        if (Ifconfig_Set_Flags(in_dev, in_err, ifparm->flags) < 0) {
            return -1;
        }

        // Reset the SSID since monitor mode nukes it
        if (Iwconfig_Set_SSID(in_dev, in_err, ifparm->essid) < 0)
            return -1;

        if (ifparm->channel > 0) {
            if (Iwconfig_Set_Channel(in_dev, ifparm->channel, in_err) < 0)
                return -1;
        }

        ret = 1;
    }

    free(ifparm);

    return ret;
}

// Cisco uses its own config file in /proc to control modes
//
// I was doing this with ioctls but that seems to cause lockups while
// this method doesn't.  I don't think I like these drivers.
int monitor_cisco_wifix(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    FILE *cisco_config;
    char cisco_path[128];
    vector<string> devbits = StrTokenize(in_dev, ":");

    if (devbits.size() < 2) {
        snprintf(in_err, STATUS_MAX, "Invalid device pair '%s'.  Proper device "
				 "for cisco_wifix is eth?:wifi?.", in_dev);
        return -1;
    }

    // Bring the device up, zero its ip, and set promisc
    if (Ifconfig_Delta_Flags(devbits[0].c_str(), in_err, 
                             IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0)
        return -1;
    if (Ifconfig_Delta_Flags(devbits[1].c_str(), in_err, 
                             IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0)
        return -1;

    // Zero the ssid, nonfatally
    Iwconfig_Set_SSID(devbits[0].c_str(), in_err, NULL);
    Iwconfig_Set_SSID(devbits[1].c_str(), in_err, NULL);
    
    // Build the proc control path
    snprintf(cisco_path, 128, "/proc/driver/aironet/%s/Config", devbits[0].c_str());

    if ((cisco_config = fopen(cisco_path, "w")) == NULL) {
        snprintf(in_err, STATUS_MAX, "Unable to open cisco control file '%s' %d:%s",
                 cisco_path, errno, strerror(errno));
        return -1;
    }

    fprintf(cisco_config, "Mode: r\n");
    fprintf(cisco_config, "Mode: y\n");
    fprintf(cisco_config, "XmitPower: 1\n");

    fclose(cisco_config);

    // Channel can't be set on cisco with these drivers.

    return 0;
}

// Hostap uses iwpriv and iwcontrol settings to control monitor mode
int monitor_hostap(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    int ret;
  
    // Allocate a tracking record for the interface settings and remember our
    // setup
    linux_ifparm *ifparm = (linux_ifparm *) malloc(sizeof(linux_ifparm));
    (*in_if) = ifparm;

    if (Ifconfig_Get_Flags(in_dev, in_err, &ifparm->flags) < 0)
        return -1;

    // Don't try to fetch the channel or mode if we're not configured to be up,
    // hostap doesn't like this.  silly hostap.
    if ((ifparm->flags & IFF_UP)) {
        if ((ifparm->channel = Iwconfig_Get_Channel(in_dev, in_err)) < 0)
            return -1;

        if (Iwconfig_Get_Mode(in_dev, in_err, &ifparm->mode) < 0)
            return -1;
    } else {
        ifparm->channel = -1;
        ifparm->mode = -1;
    }
    
    // Try to use the iwpriv command to set monitor mode.  Some versions of
    // hostap require this, some don't, so don't fail on the monitor ioctl
    // if we can't find it, it might get removed in the future.
    if ((ret = Iwconfig_Set_IntPriv(in_dev, "monitor", 3, 0, in_err)) < 0) {
        if (ret != -2)
            return -1;
    }
   
    // Try to set wext monitor mode.  We're good if one of these succeeds...
    if (monitor_wext(in_dev, initch, in_err, in_if, in_ext) < 0 && ret < 0)
        return -1;

    // If we didn't set wext mode, set the channel manually
    if (chancontrol_wext(in_dev, initch, in_err, NULL) < 0)
        return -1;

    return 0;
}

int unmonitor_hostap(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {

    // Restore the IP settings
    linux_ifparm *ifparm = (linux_ifparm *) (*in_if);

    if (Ifconfig_Set_Flags(in_dev, in_err, ifparm->flags) < 0) {
        return -1;
    }

    if (ifparm->channel > 0) {
        if (Iwconfig_Set_Channel(in_dev, ifparm->channel, in_err) < 0)
            return -1;
    }

    // Ignore errors from both of these, since one might fail with other versions
    // of hostap
    Iwconfig_Set_IntPriv(in_dev, "monitor", 0, 0, in_err);
    if (ifparm->mode > 0) {
        Iwconfig_Set_Mode(in_dev, in_err, ifparm->mode);
    }

    free(ifparm);

    return 1;
}

// Orinoco uses iwpriv and iwcontrol settings to control monitor mode
int monitor_orinoco(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    int ret;
    
    // Allocate a tracking record for the interface settings and remember our
    // setup
    linux_ifparm *ifparm = (linux_ifparm *) malloc(sizeof(linux_ifparm));
    (*in_if) = ifparm;
    
    if (Ifconfig_Get_Flags(in_dev, in_err, &ifparm->flags) < 0) {
        return -1;
    }

    if ((ifparm->channel = Iwconfig_Get_Channel(in_dev, in_err)) < 0)
        return -1;

    if (Iwconfig_Get_Mode(in_dev, in_err, &ifparm->mode) < 0)
        return -1;

    // Bring the device up and set promisc
    if (Ifconfig_Delta_Flags(in_dev, in_err, IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0)
        return -1;

    // Socket lowpower cards seem to need a little time for the firmware to settle
    // down between these calls, so we'll just sleep for everyone.  It won't hurt
    // to add a few more ms onto an indefinitely blocking ioctl setup
    usleep(5000);

    // Set monitor mode with iwpriv for orinoco_cs 0.13 with Snax patches
    if ((ret = Iwconfig_Set_IntPriv(in_dev, "monitor", 1, initch, in_err)) < 0) {
        if (ret != -2)
            return -1;
    }

    // Try to turn on my patches to the new orinoco drivers to give us some signal
    // levels if they're available.  We don't care if we fail at this.
    if (ret < 0) {
        usleep(5000);
        Iwconfig_Set_IntPriv(in_dev, "set_prismheader", 2, 0, in_err);
    }
   
    usleep(5000);
    // Try to set wext monitor mode.  We're good if one of these succeeds...
    if (ret < 0 && monitor_wext(in_dev, initch, in_err, in_if, in_ext) < 0) {
        snprintf(in_err, 1024, "Could not find 'monitor' private ioctl or use "
                 "the newer style 'mode monitor' command.  This typically means "
                 "that the drivers have not been patched or the "
                 "correct drivers are being loaded. See the troubleshooting "
                 "section of the README for more information.");
        return -1;
    }

    usleep(5000);
    // If we didn't use iwpriv, set the channel directly
    if (ret < 0 && chancontrol_wext(in_dev, initch, in_err, NULL) < 0)
        return -1;
    
    return 0;
}

int unmonitor_orinoco(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    // Restore the IP settings
    linux_ifparm *ifparm = (linux_ifparm *) (*in_if);

    if (Ifconfig_Set_Flags(in_dev, in_err, ifparm->flags) < 0) {
        return -1;
    }

    // Ignore errors from both of these, since one might fail with other versions
    // of orinoco_cs
    Iwconfig_Set_IntPriv(in_dev, "monitor", 0, ifparm->channel, in_err);
    Iwconfig_Set_Mode(in_dev, in_err, ifparm->mode);

    free(ifparm);

    return 1;

}

// Acx100 uses the packhdr iwpriv control to set link state, rest is normal
int monitor_acx100(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    int ret;

    // Allocate a tracking record for the interface settings and remember our
    // setup
    linux_ifparm *ifparm = (linux_ifparm *) malloc(sizeof(linux_ifparm));
    (*in_if) = ifparm;

    if (Ifconfig_Get_Flags(in_dev, in_err, &ifparm->flags) < 0) {
        return -1;
    }

    if (Iwconfig_Get_SSID(in_dev, in_err, ifparm->essid) < 0)
        return -1;

    if ((ifparm->channel = Iwconfig_Get_Channel(in_dev, in_err)) < 0)
        return -1;

    if (Iwconfig_Get_Mode(in_dev, in_err, &ifparm->mode) < 0)
        return -1;

    // it looks like an orinoco now, apparently
    if ((ret = Iwconfig_Set_IntPriv(in_dev, "monitor", 1, initch, in_err)) < 0) {
        if (ret == -2)
            snprintf(in_err, 1024, "Could not find 'monitor' private ioctl "
                     "Make sure you have the latest ACX100 development release.");
        return -1;
    }

    if (chancontrol_wext(in_dev, initch, in_err, NULL) < 0)
        return -1;

    return 0;
}

int unmonitor_acx100(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    // Restore the IP settings
    linux_ifparm *ifparm = (linux_ifparm *) (*in_if);

    if (Ifconfig_Set_Flags(in_dev, in_err, ifparm->flags) < 0) {
        return -1;
    }

    Iwconfig_Set_IntPriv(in_dev, "monitor", 0, ifparm->channel, in_err);
    Iwconfig_Set_Mode(in_dev, in_err, ifparm->mode);

    if (Iwconfig_Set_SSID(in_dev, in_err, ifparm->essid) < 0)
        return -1;
    
    free(ifparm);

    return 1;
}

int monitor_admtek(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    // Allocate a tracking record for the interface settings and remember our
    // setup
    linux_ifparm *ifparm = (linux_ifparm *) malloc(sizeof(linux_ifparm));
    (*in_if) = ifparm;

    // Try to figure out the name so we know if we have fcs bytes or not
    char iwname[IFNAMSIZ+1];
    if (Iwconfig_Get_Name(in_dev, in_err, iwname) < 0)
        return -1;

    if (strncmp(iwname, "IEEE 802.11b", IFNAMSIZ) == 0) {
        // Looks like the GPL driver, we need to adjust the fcsbytes
        PcapSource *psrc = (PcapSource *) in_ext;
        psrc->fcsbytes = 4;
    }

    if (Ifconfig_Get_Flags(in_dev, in_err, &ifparm->flags) < 0) {
        return -1;
    }

    if ((ifparm->flags & IFF_UP)) {
        if ((ifparm->channel = Iwconfig_Get_Channel(in_dev, in_err)) < 0)
            return -1;

        if (Iwconfig_Get_Mode(in_dev, in_err, &ifparm->mode) < 0)
            return -1;

        if (Iwconfig_Get_SSID(in_dev, in_err, ifparm->essid) < 0)
            return -1;
    
    } else {
        ifparm->channel = -1;
        ifparm->mode = -1;
    }

    int ret = monitor_wext(in_dev, initch, in_err, in_if, in_ext);

    if (ret < 0 && ret != -2)
        return ret;

    if (Iwconfig_Set_SSID(in_dev, in_err, "") < 0)
        return -1;
    
    return 0;
}

int unmonitor_admtek(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    linux_ifparm *ifparm = (linux_ifparm *) (*in_if);

    if (unmonitor_wext(in_dev, initch, in_err, in_if, in_ext))
        return -1;

    if (Iwconfig_Set_SSID(in_dev, in_err, ifparm->essid) < 0)
        return -1;
   
    return 1;
}
// vtar5k iwpriv control to set link state, rest is normal
int monitor_vtar5k(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    // Set the prism iwpriv control to 1
    if (Iwconfig_Set_IntPriv(in_dev, "prism", 1, 0, in_err) < 0) {
        return -1;
    }
    
    // The rest is standard wireless extensions
    if (monitor_wext(in_dev, initch, in_err, in_if, in_ext) < 0)
        return -1;

    return 0;
}

/* Madwifi NG ioctls from net80211 */
#define	SIOC80211IFCREATE		(SIOCDEVPRIVATE+7)
#define	SIOC80211IFDESTROY	 	(SIOCDEVPRIVATE+8)
int monitor_madwifi_ng(const char *in_dev, char *in_err, void **in_if, 
					   void *in_ext) {
	/* from net80211 headers */
	struct ieee80211_clone_params {
		char		icp_name[IFNAMSIZ];
		u_int16_t	icp_opmode;
		u_int16_t	icp_flags;
#define	IEEE80211_CLONE_BSSID	0x0001
#define	IEEE80211_NO_STABEACONS	0x0002
#define IEEE80211_M_MONITOR 	8
	};
	struct ieee80211_clone_params cp;
	struct ifreq ifr;
	char newdev[IFNAMSIZ];
	int s;

	memset(&ifr, 0, sizeof(ifr));
	memset(&cp, 0, sizeof(cp));

	strncpy(cp.icp_name, "kis", IFNAMSIZ);
	cp.icp_opmode = (u_int16_t) IEEE80211_M_MONITOR;
	cp.icp_flags = IEEE80211_CLONE_BSSID;

	strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);
	ifr.ifr_data = (caddr_t) &cp;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		return -1;
	}

	if (ioctl(s, SIOC80211IFCREATE, &ifr) < 0) {
		close(s);
		return -1;
	}

	// Extract the interface name we got back */
	strncpy(newdev, ifr.ifr_name, IFNAMSIZ);

	((KisPacketSource *) in_ext)->SetInterface(newdev);

	close(s);

	fprintf(stderr, "NOTICE:  Created Madwifi-NG VAP %s\n", newdev);

	return 1;
}

int unmonitor_madwifi_ng(const char *in_dev, char *in_err, void **in_if, 
						 void *in_ext) {
	struct ifreq ifr;
	int s;

	// Just destroy our dynamic interface
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, in_dev, IFNAMSIZ);
	if (ioctl(s, SIOC80211IFDESTROY, &ifr) < 0) {
		close(s);
		return -1;
	}

	close(s);

	return 1;
}

// Madwifi stuff uses iwpriv mode
int monitor_madwifi_a(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
	// Try to enable the madwifi-ng mode
	if (monitor_madwifi_ng(in_dev, in_err, in_if, in_ext) < 0) {
		fprintf(stderr, "WARNING: %s appears to not accept the Madwifi-NG controls. "
				"Will attempt to configure it as a standard Madwifi-old interface.\n",
				in_dev);
		// Allocate a tracking record for the interface settings and remember our
		// setup
		linux_ifparm *ifparm = (linux_ifparm *) malloc(sizeof(linux_ifparm));
		(*in_if) = ifparm;

		if (Ifconfig_Get_Flags(in_dev, in_err, &ifparm->flags) < 0) {
			return -1;
		}

		if ((ifparm->channel = Iwconfig_Get_Channel(in_dev, in_err)) < 0)
			return -1;

		if (Iwconfig_Get_Mode(in_dev, in_err, &ifparm->mode) < 0)
			return -1;

		if (Iwconfig_Get_IntPriv(in_dev, "get_mode", &ifparm->privmode, in_err) < 0)
			return -1;

		if (Iwconfig_Set_IntPriv(in_dev, "mode", 1, 0, in_err) < 0)
			return -1;
	} else {
		fprintf(stderr, "WARNING: %s appears to be using Madwifi-NG.  Some versions "
				"of the Madwifi-NG drivers have problems in monitor mode, especially "
				"if non-monitor VAPs are active.  If you experience problems, be "
				"sure to try the latest versions of Madwifi-NG and remove other "
				"VAPs\n", in_dev);

		in_dev = ((KisPacketSource *) in_ext)->FetchInterface();

		sleep(1);
	}

    // The rest is standard wireless extensions
    if (monitor_wext(in_dev, initch, in_err, in_if, in_ext) < 0) {
		snprintf(in_err, STATUS_MAX, "Unable to enter monitor mode.  This can "
				 "happen if your drivers have been compiled without the proper "
				 "wireless extensions support or if you are running a very old "
				 "version of the drivers or kernels.  Please see the troubleshooting "
				 "section of the README for more information.");
        return -1;
    }

    return 0;
}

int monitor_madwifi_b(const char *in_dev, int initch, char *in_err, 
					  void **in_if, void *in_ext) {
	// Try to enable the madwifi-ng mode
	if (monitor_madwifi_ng(in_dev, in_err, in_if, in_ext) < 0) {
		fprintf(stderr, "WARNING: %s appears to not accept the Madwifi-NG controls. "
				"Will attempt to configure it as a standard Madwifi-old interface.\n",
				in_dev);
		// Allocate a tracking record for the interface settings and remember our
		// setup
		linux_ifparm *ifparm = (linux_ifparm *) malloc(sizeof(linux_ifparm));
		(*in_if) = ifparm;

		if (Ifconfig_Get_Flags(in_dev, in_err, &ifparm->flags) < 0) {
			return -1;
		}

		if ((ifparm->channel = Iwconfig_Get_Channel(in_dev, in_err)) < 0)
			return -1;

		if (Iwconfig_Get_Mode(in_dev, in_err, &ifparm->mode) < 0)
			return -1;

		if (Iwconfig_Get_IntPriv(in_dev, "get_mode", &ifparm->privmode, in_err) < 0)
			return -1;

		if (Iwconfig_Set_IntPriv(in_dev, "mode", 2, 0, in_err) < 0)
			return -1;
	} else {
		fprintf(stderr, "WARNING: %s appears to be using Madwifi-NG.  Some versions "
				"of the Madwifi-NG drivers have problems in monitor mode, especially "
				"if non-monitor VAPs are active.  If you experience problems, be "
				"sure to try the latest versions of Madwifi-NG and remove other "
				"VAPs\n", in_dev);

		in_dev = ((KisPacketSource *) in_ext)->FetchInterface();

		sleep(1);
	}

    // The rest is standard wireless extensions
    if (monitor_wext(in_dev, initch, in_err, in_if, in_ext) < 0)
        return -1;

    return 0;
}

int monitor_madwifi_g(const char *in_dev, int initch, char *in_err, 
					  void **in_if, void *in_ext) {
	// Try to enable the madwifi-ng mode
	if (monitor_madwifi_ng(in_dev, in_err, in_if, in_ext) < 0) {
		fprintf(stderr, "WARNING: %s appears to not accept the Madwifi-NG controls. "
				"Will attempt to configure it as a standard Madwifi-old interface.\n",
				in_dev);
		// Allocate a tracking record for the interface settings and remember our
		// setup
		linux_ifparm *ifparm = (linux_ifparm *) malloc(sizeof(linux_ifparm));
		(*in_if) = ifparm;

		if (Ifconfig_Get_Flags(in_dev, in_err, &ifparm->flags) < 0) {
			return -1;
		}

		if ((ifparm->channel = Iwconfig_Get_Channel(in_dev, in_err)) < 0)
			return -1;

		if (Iwconfig_Get_Mode(in_dev, in_err, &ifparm->mode) < 0)
			return -1;

		if (Iwconfig_Get_IntPriv(in_dev, "get_mode", &ifparm->privmode, in_err) < 0)
			return -1;

		if (Iwconfig_Set_IntPriv(in_dev, "mode", 3, 0, in_err) < 0)
			return -1;
	} else {
		fprintf(stderr, "WARNING: %s appears to be using Madwifi-NG.  Some versions "
				"of the Madwifi-NG drivers have problems in monitor mode, especially "
				"if non-monitor VAPs are active.  If you experience problems, be "
				"sure to try the latest versions of Madwifi-NG and remove other "
				"VAPs\n", in_dev);

		in_dev = ((KisPacketSource *) in_ext)->FetchInterface();

		sleep(1);
	}

    // The rest is standard wireless extensions
    if (monitor_wext(in_dev, initch, in_err, in_if, in_ext) < 0)
        return -1;

    return 0;
}

int monitor_madwifi_comb(const char *in_dev, int initch, char *in_err, 
						 void **in_if, void *in_ext) {
	// Try to enable the madwifi-ng mode
	if (monitor_madwifi_ng(in_dev, in_err, in_if, in_ext) < 0) {
		fprintf(stderr, "WARNING: %s appears to not accept the Madwifi-NG controls. "
				"Will attempt to configure it as a standard Madwifi-old interface.\n",
				in_dev);

		// Allocate a tracking record for the interface settings and remember our
		// setup
		linux_ifparm *ifparm = (linux_ifparm *) malloc(sizeof(linux_ifparm));
		(*in_if) = ifparm;

		if (Ifconfig_Get_Flags(in_dev, in_err, &ifparm->flags) < 0) {
			return -1;
		}

		if ((ifparm->channel = Iwconfig_Get_Channel(in_dev, in_err)) < 0)
			return -1;

		if (Iwconfig_Get_Mode(in_dev, in_err, &ifparm->mode) < 0)
			return -1;

		if (Iwconfig_Get_IntPriv(in_dev, "get_mode", &ifparm->privmode, in_err) < 0)
			return -1;

		if (Iwconfig_Set_IntPriv(in_dev, "mode", 0, 0, in_err) < 0)
			return -1;
	} else {
		fprintf(stderr, "WARNING: %s appears to be using Madwifi-NG.  Some versions "
				"of the Madwifi-NG drivers have problems in monitor mode, especially "
				"if non-monitor VAPs are active.  If you experience problems, be "
				"sure to try the latest versions of Madwifi-NG and remove other "
				"VAPs\n", in_dev);

		in_dev = ((KisPacketSource *) in_ext)->FetchInterface();

		sleep(1);
	}

    // The rest is standard wireless extensions
    if (monitor_wext(in_dev, initch, in_err, in_if, in_ext) < 0)
        return -1;

    return 0;
}

// Unmonitor madwifi (shared)
int unmonitor_madwifi(const char *in_dev, int initch, char *in_err, 
					  void **in_if, void *in_ext) {
    // Restore the stored mode
    linux_ifparm *ifparm = (linux_ifparm *) (*in_if);

    if (Iwconfig_Set_IntPriv(in_dev, "mode", ifparm->privmode, 0, in_err) < 0) {
        return -1;
    }

    // Call the standard unmonitor
    return unmonitor_wext(in_dev, initch, in_err, in_if, in_ext);
}

// Call the standard monitor but ignore error codes since channel
// setting won't work.  This is a temp kluge.
int monitor_prism54g(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    // Allocate a tracking record for the interface settings and remember our
    // setup
    linux_ifparm *ifparm = (linux_ifparm *) malloc(sizeof(linux_ifparm));
    (*in_if) = ifparm;

    if (Ifconfig_Get_Flags(in_dev, in_err, &ifparm->flags) < 0) {
        return -1;
    }

    // Remember monitor header setting if we can
    if (Iwconfig_Get_IntPriv(in_dev, "get_prismhdr", &ifparm->prismhdr, in_err) >= 0) {
        // Select AVS monitor header
        if (Iwconfig_Set_IntPriv(in_dev, "set_prismhdr", 1, 0, in_err) < 0)
            return -1;
    } else {
        ifparm->prismhdr = -1;
    }

    if ((ifparm->channel = Iwconfig_Get_Channel(in_dev, in_err)) < 0)
        return -1;

    if (Iwconfig_Get_Mode(in_dev, in_err, &ifparm->mode) < 0)
        return -1;

    // Call the normal monitor mode
    return (monitor_wext(in_dev, initch, in_err, in_if, in_ext));

}

int unmonitor_prism54g(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    // Restore initial monitor header
    linux_ifparm *ifparm = (linux_ifparm *) (*in_if);

    if (ifparm->prismhdr >= 0)
        Iwconfig_Set_IntPriv(in_dev, "set_prismhdr", ifparm->prismhdr, 0, in_err);

    return unmonitor_wext(in_dev, initch, in_err, in_if, in_ext);
}

int monitor_ipw2100(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    // Allocate a tracking record for the interface settings and remember our
    // setup
    linux_ifparm *ifparm = (linux_ifparm *) malloc(sizeof(linux_ifparm));
    (*in_if) = ifparm;

    if (Ifconfig_Get_Flags(in_dev, in_err, &ifparm->flags) < 0) {
        return -1;
    }

    if ((ifparm->channel = Iwconfig_Get_Channel(in_dev, in_err)) < 0)
        return -1;

    if (Iwconfig_Get_Mode(in_dev, in_err, &ifparm->mode) < 0)
        return -1;

    // Call the normal monitor mode
    return (monitor_wext(in_dev, initch, in_err, in_if, in_ext));
}

int unmonitor_ipw2100(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    // Restore initial monitor header
    // linux_ifparm *ifparm = (linux_ifparm *) (*in_if);

    linux_ifparm *ifparm = (linux_ifparm *) (*in_if);

    if (Ifconfig_Set_Flags(in_dev, in_err, ifparm->flags) < 0) {
        return -1;
    }

    if (Iwconfig_Set_Mode(in_dev, in_err, ifparm->mode) < 0)
        return -1;

    free(ifparm);

    return 1;
}

int monitor_ipw2200(const char *in_dev, int initch, char *in_err, 
					void **in_if, void *in_ext) {
    // Allocate a tracking record for the interface settings and remember our
    // setup
    linux_ifparm *ifparm = (linux_ifparm *) malloc(sizeof(linux_ifparm));
    (*in_if) = ifparm;

    if (Ifconfig_Get_Flags(in_dev, in_err, &ifparm->flags) < 0) {
        return -1;
    }

    if ((ifparm->channel = Iwconfig_Get_Channel(in_dev, in_err)) < 0)
        return -1;

    if (Iwconfig_Get_Mode(in_dev, in_err, &ifparm->mode) < 0)
        return -1;

    // Call the normal monitor mode
    return (monitor_wext(in_dev, initch, in_err, in_if, in_ext));
}

int unmonitor_ipw2200(const char *in_dev, int initch, char *in_err, 
					  void **in_if, void *in_ext) {
    // Restore initial monitor header
    // linux_ifparm *ifparm = (linux_ifparm *) (*in_if);

    linux_ifparm *ifparm = (linux_ifparm *) (*in_if);

    if (Ifconfig_Set_Flags(in_dev, in_err, ifparm->flags) < 0) {
        return -1;
    }

    if (Iwconfig_Set_Mode(in_dev, in_err, ifparm->mode) < 0)
        return -1;

	// James says this wants to be set to channel 0 for proper scanning operation
	if (Iwconfig_Set_Channel(in_dev, 0, in_err) < 0)
		return -1;

    free(ifparm);

    return 1;
}

// (Unless we learn different) the 3945 in full rfmon acts the same as
// an ipw2200, so we'll use the same control mechanisms
int monitor_ipw3945(const char *in_dev, int initch, char *in_err, 
					void **in_if, void *in_ext) {
    // Allocate a tracking record for the interface settings and remember our
    // setup
    linux_ifparm *ifparm = (linux_ifparm *) malloc(sizeof(linux_ifparm));
    (*in_if) = ifparm;

    if (Ifconfig_Get_Flags(in_dev, in_err, &ifparm->flags) < 0) {
        return -1;
    }

    if ((ifparm->channel = Iwconfig_Get_Channel(in_dev, in_err)) < 0)
        return -1;

    if (Iwconfig_Get_Mode(in_dev, in_err, &ifparm->mode) < 0)
        return -1;

    // Call the normal monitor mode
    return (monitor_wext(in_dev, initch, in_err, in_if, in_ext));
}

int unmonitor_ipw3945(const char *in_dev, int initch, char *in_err, 
					  void **in_if, void *in_ext) {
    // Restore initial monitor header
    // linux_ifparm *ifparm = (linux_ifparm *) (*in_if);

    linux_ifparm *ifparm = (linux_ifparm *) (*in_if);

    if (Ifconfig_Set_Flags(in_dev, in_err, ifparm->flags) < 0) {
        return -1;
    }

    if (Iwconfig_Set_Mode(in_dev, in_err, ifparm->mode) < 0)
        return -1;

	// James says this wants to be set to channel 0 for proper scanning operation
	if (Iwconfig_Set_Channel(in_dev, 0, in_err) < 0)
		return -1;

    free(ifparm);

    return 1;
}

// The 3945 in "parasite" mode (until James names it) is a different
// beast entirely.  It uses a dynamically added tap interface to give us
// realtime rtap formatted frames off the interface, so we need to
// turn it on via sysfs and then push the new rtapX interface into the source
// before the open happens
int monitor_ipwlivetap(const char *in_dev, int initch, char *in_err, 
					   void **in_if, void *in_ext) {
	// We don't try to remember settings because we aren't going to do
	// anything with them, we're leeching off a dynamic interface made
	// just for us.
	char dynif[32];
	FILE *sysf;
	char path[1024];
	short int ifflags;

	// Try to get the flags off the master interface
    if (Ifconfig_Get_Flags(in_dev, in_err, &ifflags) < 0) {
        return -1;
    }

	// If the master interface isn't even up, blow up.
	if ((ifflags & IFF_UP) == 0) {
		snprintf(in_err, 1024, "The ipw control interface (%s) is not "
				 "configured as 'up'.  The ipwlivetap mode reports "
				 "traffic from a currently running interface.  For pure "
				 "rfmon monitor mode, use ipwXXXX instead.", in_dev);
		return -1;
	}

	// Use the .../net/foo/device symlink into the .../bus/pci/drivers/
	// ipw3945/foo/ pci bus interface
	snprintf(path, 1024, "/sys/class/net/%s/device/rtap_iface",
			 in_dev);

	// Open it in RO mode first and get the current state.  I'm not sure
	// how well frewind works on a dynamic system file so we'll just
	// close it off and re-open it when we go to set modes, if we need
	// to.
	if ((sysf = fopen(path, "r")) == NULL) {
		snprintf(in_err, 1024, "Failed to open ipw sysfs tap control file, "
				 "check that the version of the ipw drivers you are running "
				 "is recent enough, and that your system has sysfs properly "
				 "set up.");
		return -1;
	}

	fgets(dynif, 32, sysf);

	// We're done with the RO 
	fclose(sysf);

	// If it's -1, we aren't turned on and we need to.
	if (strncmp(dynif, "-1", 32) == 0) {
		if ((sysf = fopen(path, "w")) == NULL) {
			snprintf(in_err, 1024, "Failed to open the ipw sysfs tap control "
					 "file for writing (%s).  Check that Kismet has the proper "
					 "privilege levels and that you are running a version of the "
					 "ipw drivers which supports associated rfmon.", strerror(errno));
			return -1;
		}

		fprintf(sysf, "1\n");
		fclose(sysf);

		// Reopen it again for reading for the last time, and get the
		// interface we changed to.  Do some minor error checking to make
		// sure the new interface isn't called -1, 0, or 1, which I'm going
		// to guess would imply an older driver
		if ((sysf = fopen(path, "r")) == NULL) {
			snprintf(in_err, 1024, "Failed to open the ipw sysfs tap "
					 "control to find the interface allocated.  Something strange "
					 "has happened, because the control file was available "
					 "previously for setting.  Check your system messages.");
			return -1;
		}

		fgets(dynif, 32, sysf);

		fclose(sysf);

		// Wait for the distro to settle if its going to rename an interface
		sleep(1);
	}

	// Sanity check the interface we were told to use.  A 0, 1, -1 probably
	// means a bad driver version.
	if (strncmp(dynif, "-1", 32) == 0 || strncmp(dynif, "0", 32) == 0 ||
		strncmp(dynif, "1", 32) == 0) {
		snprintf(in_err, 1024, "Got a nonsense interface from the ipw "
				 "sysfs tap control file.  This probably means your ipw "
				 "drivers are out of date, or that there is something strange "
				 "happening in the drivers.  Check your system messages.");
		return -1;
	}

	// Now that we've gone through that nonsense, make sure the
	// dynamic rtap interface is up
	if (Ifconfig_Delta_Flags(dynif, in_err, IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0)
        return -1;

	// And push the config into the packetsoure
	((KisPacketSource *) in_ext)->SetInterface(dynif);

	return 1;
}

int unmonitor_ipwlivetap(const char *in_dev, int initch, char *in_err, 
						 void **in_if, void *in_ext) {
	// Actually there isn't anything to do here.  Right now, I don't
	// think I care if we leave the parasite rtap interface hanging around.
	// Newcore might do this better, but this isn't newcore.

    return 1;
}

// "standard" wireless extension monitor mode
int monitor_wext(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    int mode;

    // Bring the device up, zero its ip, and set promisc
    if (Ifconfig_Delta_Flags(in_dev, in_err, IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0)
        return -1;

    // Get mode and see if we're already in monitor, don't try to go in
    // if we are (cisco doesn't like rfmon rfmon)
    if (Iwconfig_Get_Mode(in_dev, in_err, &mode) < 0)
        return -1;
    
    if (mode != LINUX_WLEXT_MONITOR) {
        // Set it
        if (Iwconfig_Set_Mode(in_dev, in_err, LINUX_WLEXT_MONITOR) < 0) {
            snprintf(in_err, STATUS_MAX, "Failed to set monitor mode: %s.  This usually "
                     "means your drivers either do not support monitor mode, or use a "
                     "different mechanism for getting to it.  Make sure you have a "
                     "version of your drivers that support monitor mode, and consult "
                     "the troubleshooting section of the README.", 
                     strerror(errno));
            return -1;
        }
    }
    
    // Set the initial channel - if we ever get a pcapsource that needs a hook
    // back into the class, this will have to be rewritten
    if (chancontrol_wext(in_dev, initch, in_err, NULL) < 0) {
        return -2;
    }
    
    return 0;
}

int unmonitor_wext(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    // Restore the IP settings
    linux_ifparm *ifparm = (linux_ifparm *) (*in_if);

    if (Ifconfig_Set_Flags(in_dev, in_err, ifparm->flags) < 0) {
        return -1;
    }

    if (ifparm->mode >= 0) {
        if (Iwconfig_Set_Mode(in_dev, in_err, ifparm->mode) < 0)
            return -1;
    }

    if (ifparm->channel > 0) {
        if (Iwconfig_Set_Channel(in_dev, ifparm->channel, in_err) < 0)
            return -1;
    }
    
    free(ifparm);

    return 1;
}

#endif

#ifdef SYS_LINUX
// wlan-ng modern standard
int monitor_wlanng(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    // I really didn't want to do this...
    char cmdline[2048];

    // Sanitize the device just to be safe.  The ifconfig should fail if
    // the device is invalid, but why take risks
    for (unsigned int x = 0; x < strlen(in_dev); x++) {
        if (!isalnum(in_dev[x])) {
            snprintf(in_err, STATUS_MAX, "Invalid device '%s'", in_dev);
            return -1;
        }
    }
    
    if (Ifconfig_Delta_Flags(in_dev, in_err, IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0)
        return -1;

    // Enable the interface
    snprintf(cmdline, 2048, "wlanctl-ng %s lnxreq_ifstate ifstate=enable >/dev/null 2>/dev/null", in_dev);
    if (RunSysCmd(cmdline) < 0) {
        snprintf(in_err, 1024, "Unable to execute '%s'", cmdline);
        return -1;
    }

    // Turn off WEP
    snprintf(cmdline, 2048, "wlanctl-ng %s dot11req_mibset "
             "mibattribute=dot11PrivacyInvoked=false >/dev/null 2>/dev/null", in_dev);
    if (RunSysCmd(cmdline) < 0) {
        snprintf(in_err, 1024, "Unable to execute '%s'", cmdline);
        return -1;
    }

    // Don't exclude packets
    snprintf(cmdline, 2048, "wlanctl-ng %s dot11req_mibset "
             "mibattribute=dot11ExcludeUnencrypted=false >/dev/null 2>/dev/null", in_dev);
    if (RunSysCmd(cmdline) < 0) {
        snprintf(in_err, 1024, "Unable to execute '%s'", cmdline);
        return -1;
    }

    // Turn on rfmon on the initial channel
    snprintf(cmdline, 2048, "wlanctl-ng %s lnxreq_wlansniff channel=%d "
             "enable=true prismheader=true >/dev/null 2>/dev/null", in_dev, initch);
    if (RunSysCmd(cmdline) < 0) {
        snprintf(in_err, 1024, "Unable to execute '%s'", cmdline);
        return -1;
    }
    
    return 0;
}

// wlan-ng avs
int monitor_wlanng_avs(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    // I really didn't want to do this...
    char cmdline[2048];

    // Sanitize the device just to be safe.  The ifconfig should fail if
    // the device is invalid, but why take risks
    for (unsigned int x = 0; x < strlen(in_dev); x++) {
        if (!isalnum(in_dev[x])) {
            snprintf(in_err, STATUS_MAX, "Invalid device '%s'", in_dev);
            return -1;
        }
    }

    if (Ifconfig_Delta_Flags(in_dev, in_err, IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0)
        return -1;

    // Enable the interface
    snprintf(cmdline, 2048, "wlanctl-ng %s lnxreq_ifstate ifstate=enable >/dev/null 2>/dev/null", in_dev);
    if (RunSysCmd(cmdline) < 0) {
        snprintf(in_err, 1024, "Unable to execute '%s'", cmdline);
        return -1;
    }

    // Turn off WEP
    snprintf(cmdline, 2048, "wlanctl-ng %s dot11req_mibset "
             "mibattribute=dot11PrivacyInvoked=false >/dev/null 2>/dev/null", in_dev);
    if (RunSysCmd(cmdline) < 0) {
        snprintf(in_err, 1024, "Unable to execute '%s'", cmdline);
        return -1;
    }

    // Don't exclude packets
    snprintf(cmdline, 2048, "wlanctl-ng %s dot11req_mibset "
             "mibattribute=dot11ExcludeUnencrypted=false >/dev/null 2>/dev/null", in_dev);
    if (RunSysCmd(cmdline) < 0) {
        snprintf(in_err, 1024, "Unable to execute '%s'", cmdline);
        return -1;
    }

    // Turn on rfmon on the initial channel
    snprintf(cmdline, 2048, "wlanctl-ng %s lnxreq_wlansniff channel=%d prismheader=false "
             "wlanheader=true stripfcs=false keepwepflags=false enable=true >/dev/null 2>/dev/null", in_dev, initch);
    if (RunSysCmd(cmdline) < 0) {
        snprintf(in_err, 1024, "Unable to execute '%s'", cmdline);
        return -1;
    }
    
    return 0;
}

int monitor_wrt54g(const char *in_dev, int initch, char *in_err, void **in_if, 
				   void *in_ext) {
    char cmdline[2048];
	int mode;
	int wlmode = 0;

#ifdef HAVE_LINUX_WIRELESS
    vector<string> devbits = StrTokenize(in_dev, ":");

    if (devbits.size() < 2) {
		snprintf(cmdline, 2048, "/usr/sbin/wl monitor 1");
		if (RunSysCmd(cmdline) < 0) {
			snprintf(in_err, 1024, "Unable to set mode using 'wl monitor 1'.  Some "
					 "custom firmware images require you to specify the origial "
					 "device and a new dynamic device and use the iwconfig controls. "
					 "see the README for how to configure your capture source.");
			return -1;
		}
    } else {
		// Get the mode ... If this doesn't work, try the old wl method.
		if (Iwconfig_Get_Mode(devbits[0].c_str(), in_err, &mode) < 0) {
			fprintf(stderr, "WARNING:  Getting wireless mode via ioctls failed, "
					"defaulting to trying the 'wl' command.\n");
			wlmode = 1;
		}

		if (wlmode == 1) {
			snprintf(cmdline, 2048, "/usr/sbin/wl monitor 1");
			if (RunSysCmd(cmdline) < 0) {
				snprintf(in_err, 1024, "Unable to execute '%s'", cmdline);
				return -1;
			}
		} else if (mode != LINUX_WLEXT_MONITOR) {
			// Set it
			if (Iwconfig_Set_Mode(devbits[0].c_str(), in_err, 
								  LINUX_WLEXT_MONITOR) < 0) {
				snprintf(in_err, STATUS_MAX, "Unable to set iwconfig monitor "
						 "mode.  If you are using an older wrt54g, try specifying "
						 "only the ethernet device, not ethX:prismX");
				return -1;
			}
		}
	}
#else
	snprintf(cmdline, 2048, "/usr/sbin/wl monitor 1");
	if (RunSysCmd(cmdline) < 0) {
		snprintf(in_err, 1024, "Unable to set mode using 'wl monitor 1'.  Some "
				 "custom firmware images require you to specify the origial "
				 "device and a new dynamic device and use the iwconfig controls. "
				 "see the README for how to configure your capture source. "
				 "Support for wireless extensions was not compiled in, so more "
				 "advanced modes of setting monitor mode are not available.");
		return -1;
	}
	fprintf(stderr, "WARNING:  Support for wireless extensions was not compiled "
			"into this binary.  Using the iw* tools to set monitor mode will not "
			"be available.  This may cause opening the source to fail on some "
			"firmware versions.  To fix this, make sure wireless extensions are "
			"available and found by the configure script when building Kismet.");
#endif

	return 1;
}

#endif

#ifdef SYS_OPENBSD
// This should be done programattically...
int monitor_openbsd_cisco(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    char cmdline[2048];

    // Sanitize the device just to be safe.  The ifconfig should fail if
    // the device is invalid, but why take risks
    for (unsigned int x = 0; x < strlen(in_dev); x++) {
        if (!isalnum(in_dev[x])) {
            snprintf(in_err, STATUS_MAX, "Invalid device '%s'", in_dev);
            return -1;
        }
    }

    snprintf(cmdline, 2048, "ancontrol -i %s -o 1", in_dev);
    if (RunSysCmd(cmdline) < 0) {
        snprintf(in_err, 1024, "Unable to execute '%s'", cmdline);
        return -1;
    }

    snprintf(cmdline, 2048, "ancontrol -i %s -p 1", in_dev);
    if (RunSysCmd(cmdline) < 0) {
        snprintf(in_err, 1024, "Unable to execute '%s'", cmdline);
        return -1;
    }

    snprintf(cmdline, 2048, "ancontrol -i %s -M 7", in_dev);
    if (RunSysCmd(cmdline) < 0) {
        snprintf(in_err, 1024, "Unable to execute '%s'", cmdline);
        return -1;
    }
    
    return 0;
}

int monitor_openbsd_prism2(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    struct wi_req wreq;
    struct ifreq ifr;
    int s, flags;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == -1) {
        snprintf(in_err, 1024, "Failed to create AF_INET socket: %s",
                 strerror(errno));
        return -1;
    }
    //Make sure our interface is up
    strlcpy(ifr.ifr_name, in_dev, sizeof(ifr.ifr_name));
    if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) == -1) {
        close(s);
        snprintf(in_err, 1024, "Failed to get interface flags: %s",
                 strerror(errno));
        return -1;
    }
    flags = ifr.ifr_flags;
    if ((flags & IFF_UP) == 0) {
        ifr.ifr_flags = (flags | IFF_UP);
        strlcpy(ifr.ifr_name, in_dev, sizeof(ifr.ifr_name));
        if (ioctl(s, SIOCSIFFLAGS, (caddr_t)&ifr) == -1) {
            close(s);
            snprintf(in_err, 1024, "Failed to ioctl interface up: %s",
                     strerror(errno));
            return -1;
        }
        usleep(5000); // Allow interface to settle
    }

    // Set our initial channel
    bzero((char *)&wreq, sizeof(wreq));
    wreq.wi_len = WI_MAX_DATALEN;
    wreq.wi_type = WI_DEBUG_CHAN;
    wreq.wi_val[0] = htole16(initch);

    bzero((char *)&ifr, sizeof(ifr));
    strlcpy(ifr.ifr_name, in_dev, sizeof(ifr.ifr_name));
    ifr.ifr_data = (caddr_t)&wreq;

    if (ioctl(s, SIOCSPRISM2DEBUG, &ifr) < 0) {
        close(s);
        snprintf(in_err, 1024, "Channel set ioctl failed: %s",
                 strerror(errno));
        return -1;
    }

    // Disable power managment
    bzero((char *)&wreq, sizeof(wreq));
    wreq.wi_len = WI_MAX_DATALEN;
    wreq.wi_type = WI_RID_PM_ENABLED;
    wreq.wi_val[0] = 0;

    if (ioctl(s, SIOCSWAVELAN, &ifr) < 0) {
        close(s);
        snprintf(in_err, 1024, "Power management ioctl failed: %s",
                 strerror(errno));
    }

    // Lower AP density, better radio threshold settings? 
    bzero((char *)&wreq, sizeof(wreq));
    wreq.wi_len = WI_MAX_DATALEN;
    wreq.wi_type = WI_RID_SYSTEM_SCALE;
    wreq.wi_val[0] = 1;

    if (ioctl(s, SIOCSWAVELAN, &ifr) < 0) {
        close(s);
        snprintf(in_err, 1024, "AP Density ioctl failed: %s",
                 strerror(errno));
    }

    // Enable driver processing of 802.11b frames
    bzero((char *)&wreq, sizeof(wreq));
    wreq.wi_len = WI_MAX_DATALEN;
    wreq.wi_type = WI_RID_PROCFRAME;
    wreq.wi_val[0] = 1;

    if (ioctl(s, SIOCSWAVELAN, &ifr) < 0) {
        close(s);
        snprintf(in_err, 1024, "Driver processing ioctl failed: %s",
                 strerror(errno));
        return -1;
    }

    // Disable roaming, we don't want the card to probe
    bzero((char *)&wreq, sizeof(wreq));
    wreq.wi_len = WI_MAX_DATALEN;
    wreq.wi_type = WI_RID_ROAMING_MODE;
    wreq.wi_val[0] = 3;

    if (ioctl(s, SIOCSWAVELAN, &ifr) < 0) {
        close(s);
        snprintf(in_err, 1024, "Roaming disable ioctl failed: %s",
                 strerror(errno));
    }

    // Enable monitor mode
    bzero((char *)&wreq, sizeof(wreq));
    wreq.wi_len = WI_MAX_DATALEN;
    wreq.wi_type = WI_DEBUG_MONITOR;
    wreq.wi_val[0] = 1;

    if (ioctl(s, SIOCSPRISM2DEBUG, &ifr) < 0) {
        close(s);
        snprintf(in_err, 1024, "Monitor mode ioctl failed: %s",
                 strerror(errno));
        return -1;
    }

    close(s);

    return 0;
}
#endif

// Channel change commands
#ifdef HAVE_LINUX_WIRELESS
// Generic wireless "iwconfig channel x" 
int chancontrol_wext(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
    return(Iwconfig_Set_Channel(in_dev, in_ch, in_err));
}

// Use iwpriv to control the channel for orinoco
int chancontrol_orinoco(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
    int ret;
    PcapSourceWext *source = (PcapSourceWext *) in_ext;
 
    // Learn how to control our channel
    if (source->modern_chancontrol == -1) {
        if ((ret = Iwconfig_Set_IntPriv(in_dev, "monitor", 1, in_ch, in_err)) == -2) {
	  usleep(5000);
            if (Iwconfig_Set_Channel(in_dev, in_ch, in_err) < 0) {
                snprintf(in_err, 1024, "Could not find 'monitor' private ioctl or use "
                         "the newer style 'channel X' command.  This typically means "
                         "that the drivers have not been patched or the "
                         "correct drivers are being loaded. See the troubleshooting "
                         "section of the README for more information.");
                return -1;
            }
            source->modern_chancontrol = 1;
        } else if (ret >= 0) {
            source->modern_chancontrol = 0;
        } else {
            return ret;
        }
        usleep(5000);
    } 
    
    if (source->modern_chancontrol == 0) {
        // Set the monitor mode iwpriv controls.  Explain more if we fail on monitor.
        if ((ret = Iwconfig_Set_IntPriv(in_dev, "monitor", 1, in_ch, in_err)) < 0) {
            if (ret == -2) 
                snprintf(in_err, 1024, "Could not find 'monitor' private ioctl.  This "
                         "typically means that the drivers have not been patched or the "
                         "patched drivers are being loaded.  See the troubleshooting "
                         "section of the README for more information.");
            return -1;
        }

        // The channel is set by the iwpriv so we're done.
        return 0;
    } 

    // Otherwise use iwconfig to set the channel
    return(Iwconfig_Set_Channel(in_dev, in_ch, in_err));
}

// Madwifi needs to change modes accordinly
int chancontrol_madwifi_ab(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
    /*
    if (in_ch > 0 && in_ch <= 14) {
        if (Iwconfig_Set_IntPriv(in_dev, "mode", 2, 0, in_err) < 0)
            return -1;
    } else {
        if (Iwconfig_Set_IntPriv(in_dev, "mode", 1, 0, in_err) < 0)
            return -1;
    }
    */
    return chancontrol_wext(in_dev, in_ch, in_err, in_ext);
}

int chancontrol_madwifi_ag(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
	/* This seems to not be needed 
    if (in_ch > 0 && in_ch <= 14) {
        if (Iwconfig_Set_IntPriv(in_dev, "mode", 3, 0, in_err) < 0)
            return -1;
    } else {
        if (Iwconfig_Set_IntPriv(in_dev, "mode", 1, 0, in_err) < 0)
            return -1;
    }
	*/

    return chancontrol_wext(in_dev, in_ch, in_err, in_ext);
}

int chancontrol_prism54g(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
    // Run the wireless extention stuff and scrap the error codes
    chancontrol_wext(in_dev, in_ch, in_err, in_ext);

    return 0;
}

int chancontrol_ipw2100(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
    // Introduce a slight delay to let the driver settle, a la orinoco.  I don't
    // like doing this at all since it introduces hiccups into the channel control
    // process, but....

    int ret = 0;

    ret = chancontrol_wext(in_dev, in_ch, in_err, in_ext);
    usleep(5000);

    return ret;
}

int chancontrol_ipw2200(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
	// Lets see if this really needs the channel change delay like the 2100 did
    int ret = 0;

    ret = chancontrol_wext(in_dev, in_ch, in_err, in_ext);
	// Drop a tiny sleep in here to let the channel set settle, otherwise we
	// run the risk of the card freaking out
	usleep(7000);

    return ret;
}

#endif

#ifdef SYS_LINUX
int chancontrol_wlanng(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
    // I really didn't want to do this...
    char cmdline[2048];

    // Turn on rfmon on the initial channel
    snprintf(cmdline, 2048, "wlanctl-ng %s lnxreq_wlansniff channel=%d enable=true "
             "prismheader=true >/dev/null 2>&1", in_dev, in_ch);
    if (RunSysCmd(cmdline) < 0) {
        snprintf(in_err, 1024, "Unable to execute '%s'", cmdline);
        return -1;
    }

    if (in_ext != NULL) {
        PcapSourceWlanng *src = (PcapSourceWlanng *) in_ext;
        src->last_channel = in_ch;
    }
    
    return 0;
}

int chancontrol_wlanng_avs(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
    // I really didn't want to do this...
    char cmdline[2048];

    // Turn on rfmon on the initial channel
    snprintf(cmdline, 2048, "wlanctl-ng %s lnxreq_wlansniff channel=%d "
             "prismheader=false wlanheader=true stripfcs=false keepwepflags=false "
             "enable=true >/dev/null 2>&1", in_dev, in_ch);

    if (RunSysCmd(cmdline) < 0) {
        snprintf(in_err, 1024, "Unable to execute '%s'", cmdline);
        return -1;
    }

    if (in_ext != NULL) {
        PcapSourceWlanng *src = (PcapSourceWlanng *) in_ext;
        src->last_channel = in_ch;
    }
    
    return 0;
}
#endif

#ifdef SYS_OPENBSD
int chancontrol_openbsd_prism2(const char *in_dev, int in_ch, char *in_err, 
                               void *in_ext) {

	struct wi_req		wreq;
	struct ifreq		ifr;
	int		s;

	bzero((char *)&wreq, sizeof(wreq));
	wreq.wi_len = WI_MAX_DATALEN;
	wreq.wi_type = WI_DEBUG_CHAN;
	wreq.wi_val[0] = htole16(in_ch);

	bzero((char *)&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, in_dev, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&wreq;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1) {
		snprintf(in_err, 1024, "Failed to create AF_INET socket: %s",
                 strerror(errno));
		return -1;
	}

	if (ioctl(s, SIOCSPRISM2DEBUG, &ifr) < 0) {
        close(s);
		snprintf(in_err, 1024, "Channel set ioctl failed: %s", strerror(errno));
		return -1;
	}

	close(s);

	return 0;
}
#endif

#if (defined(HAVE_RADIOTAP) && (defined(SYS_NETBSD) || defined(SYS_OPENBSD) || defined(SYS_FREEBSD)))
RadiotapBSD::RadiotapBSD(const char *name) : ifname(name) {
    s = -1;
}

RadiotapBSD::~RadiotapBSD() {
    if (s >= 0)
        close(s);
}

const char *RadiotapBSD::geterror() const {
	return errstr;
}

void RadiotapBSD::perror(const char *fmt, ...) {
	char *cp;

	snprintf(errstr, sizeof(errstr), "%s: ", ifname.c_str());
	cp = strchr(errstr, '\0');
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(cp, sizeof(errstr) - (cp - errstr), fmt, ap);
	va_end(ap);
	cp = strchr(cp, '\0');
	snprintf(cp, sizeof(errstr) - (cp - errstr), ": %s", strerror(errno));
}

void RadiotapBSD::seterror(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(errstr, sizeof(errstr), fmt, ap);
	va_end(ap);
}

bool RadiotapBSD::checksocket() {
    if (s < 0) {
        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) {
            perror("Failed to create AF_INET socket");
            return false;
        }
    }
    return true;
}

bool RadiotapBSD::getmediaopt(int& options, int& mode) {
    struct ifmediareq ifmr;

    if (!checksocket())
        return false;

    memset(&ifmr, 0, sizeof(ifmr));
    strncpy(ifmr.ifm_name, ifname.c_str(), sizeof(ifmr.ifm_name));

    /*
     * We must go through the motions of reading all
     * supported media because we need to know both
     * the current media type and the top-level type.
     */
    if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
        perror("cannot get ifmedia");
        return false;
    }
    options = IFM_OPTIONS(ifmr.ifm_current);
    mode = IFM_MODE(ifmr.ifm_current);
    return true;
}

bool RadiotapBSD::setmediaopt(int options, int mode) {
    struct ifmediareq ifmr;
    struct ifreq ifr;
    int *mwords;

    if (!checksocket())
        return false;

    memset(&ifmr, 0, sizeof(ifmr));
    strncpy(ifmr.ifm_name, ifname.c_str(), sizeof(ifmr.ifm_name));

    /*
     * We must go through the motions of reading all
     * supported media because we need to know both
     * the current media type and the top-level type.
     */
    if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
        perror("cannot get ifmedia");
        return false;
    }
    if (ifmr.ifm_count == 0) {
        seterror("%s: no media types?", ifname.c_str());
        return false;
    }
    mwords = new int[ifmr.ifm_count];
    if (mwords == NULL) {
        seterror("cannot malloc");
        return false;
    }
    ifmr.ifm_ulist = mwords;
    if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) {
        perror("cannot get ifmedia");
        return false;
    }
    delete mwords;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname.c_str(), sizeof(ifr.ifr_name));
    ifr.ifr_media = (ifmr.ifm_current &~ IFM_OMASK) | options;
    ifr.ifr_media = (ifr.ifr_media &~ IFM_MMASK) | IFM_MAKEMODE(mode);

    if (ioctl(s, SIOCSIFMEDIA, (caddr_t)&ifr) < 0) {
        perror("cannot set ifmedia");
        return false;
    }
    return true;
}

#if defined(SYS_OPENBSD) || defined(SYS_NETBSD)

     /* A simple 802.11 ioctl replacement for OpenBSD/NetBSD
        Only used for channel set/get.
        This should be re-written to be *BSD agnostic.  */

bool RadiotapBSD::get80211(int type, int& val, int len, u_int8_t *data) {
    struct ieee80211chanreq channel;

    if (!checksocket())
        return false;
    memset(&channel, 0, sizeof(channel));
    strlcpy(channel.i_name, ifname.c_str(), sizeof(channel.i_name));
    if (ioctl(s, SIOCG80211CHANNEL, (caddr_t)&channel) < 0) {
        perror("SIOCG80211CHANNEL ioctl failed");
        return false;
    }
    val = channel.i_channel;
    return true;
}

bool RadiotapBSD::set80211(int type, int val, int len, u_int8_t *data) {
    struct ieee80211chanreq channel;

    if (!checksocket())
        return false;
    strlcpy(channel.i_name, ifname.c_str(), sizeof(channel.i_name));
    channel.i_channel = (u_int16_t)val;
    if (ioctl(s, SIOCS80211CHANNEL, (caddr_t)&channel) == -1) {
        perror("SIOCS80211CHANNEL ioctl failed");
        return false;
    }
    return true;
}

#elif defined(SYS_FREEBSD) /* FreeBSD has a generic 802.11 ioctl */

bool RadiotapBSD::get80211(int type, int& val, int len, u_int8_t *data) {
    struct ieee80211req ireq;

    if (!checksocket())
        return false;
    memset(&ireq, 0, sizeof(ireq));
    strncpy(ireq.i_name, ifname.c_str(), sizeof(ireq.i_name));
    ireq.i_type = type;
    ireq.i_len = len;
    ireq.i_data = data;
    if (ioctl(s, SIOCG80211, &ireq) < 0) {
        perror("SIOCG80211 ioctl failed");
        return false;
    }
    val = ireq.i_val;
    return true;
}

bool RadiotapBSD::set80211(int type, int val, int len, u_int8_t *data) {
    struct ieee80211req ireq;

    if (!checksocket())
	return false;
    memset(&ireq, 0, sizeof(ireq));
    strncpy(ireq.i_name, ifname.c_str(), sizeof(ireq.i_name));
    ireq.i_type = type;
    ireq.i_val = val;
    ireq.i_len = len;
    ireq.i_data = data;
    return (ioctl(s, SIOCS80211, &ireq) >= 0);
}

#endif

bool RadiotapBSD::getifflags(int& flags) {
    struct ifreq ifr;

    if (!checksocket())
        return false;

    strncpy(ifr.ifr_name, ifname.c_str(), sizeof (ifr.ifr_name));
    if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
        perror("SIOCGIFFLAGS ioctl failed");
        return false;
    }
#if defined(SYS_FREEBSD)
    flags = (ifr.ifr_flags & 0xffff) | (ifr.ifr_flagshigh << 16);
#elif defined(SYS_OPENBSD) || defined(SYS_NETBSD)
    flags = ifr.ifr_flags;
#endif
    return true;
}

bool RadiotapBSD::setifflags(int flags) {
    struct ifreq ifr;

    if (!checksocket())
        return false;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname.c_str(), sizeof (ifr.ifr_name));
#if defined(SYS_FREEBSD)
    ifr.ifr_flags = flags & 0xffff;
    ifr.ifr_flagshigh = flags >> 16;
#elif defined(SYS_OPENBSD) || (SYS_NETBSD)
    ifr.ifr_flags = flags;
#endif
    if (ioctl(s, SIOCSIFFLAGS, (caddr_t)&ifr) < 0) {
        perror("SIOCSIFFLAGS ioctl failed");
        return false;
    }
    return true;
}

bool RadiotapBSD::monitor_enable(int initch) {
    /*
     * Collect current state.
     */
    (void) getmediaopt(prev_options, prev_mode);
    (void) get80211(IEEE80211_IOC_CHANNEL, prev_chan, 0, NULL);
    (void) getifflags(prev_flags);
    /*
     * Enter monitor mode, set the specified channel,
     * enable promiscuous reception, and force the
     * interface up since otherwise bpf won't work.
     */
    if (!setmediaopt(IFM_IEEE80211_MONITOR, IFM_AUTO))
        return false;
    if (!set80211(IEEE80211_IOC_CHANNEL, initch, 0, NULL)) {
	perror("failed to set channel %u", initch);
	(void) setmediaopt(prev_options, prev_mode);
        return false;
    }
#if defined(SYS_FREEBSD)
    if (!setifflags(prev_flags | IFF_PPROMISC | IFF_UP)) {
#elif defined(SYS_OPENBSD) || defined(SYS_NETBSD)
    if (!setifflags(prev_flags | IFF_PROMISC | IFF_UP)) {
#endif
	(void) set80211(IEEE80211_IOC_CHANNEL, prev_chan, 0, NULL);
	(void) setmediaopt(prev_options, prev_mode);
        return false;
    }
    return true;
}

bool RadiotapBSD::monitor_reset(int initch) {
    (void) setifflags(prev_flags);
    /* NB: reset the current channel before switching modes */
    (void) set80211(IEEE80211_IOC_CHANNEL, prev_chan, 0, NULL);
    (void) setmediaopt(prev_options, prev_mode);
    return true;
}

bool RadiotapBSD::chancontrol(int in_ch) {
    if (!set80211(IEEE80211_IOC_CHANNEL, in_ch, 0, NULL)) {
	perror("failed to set channel %u", in_ch);
	return false;
    } else
	return true;
}

int monitor_bsd(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
	RadiotapBSD *bsd = new RadiotapBSD(in_dev);
	if (!bsd->monitor_enable(initch)) {
		strlcpy(in_err, bsd->geterror(), 1024);
		delete bsd;
		return -1;
	} else {
		*(RadiotapBSD **)in_if = bsd;
#ifdef SYS_OPENBSD
		// Temporary hack around OpenBSD drivers not standardising on whether FCS
		// bytes are appended, nor having any method to indicate their presence. 
		if (strncmp(in_dev, "ath", 3) == 0 || strncmp(in_dev, "ural", 4) == 0) {
			PcapSource *psrc = (PcapSource *) in_ext;
			psrc->fcsbytes = 4;
		}
#endif
		return 0;
	}
}

int unmonitor_bsd(const char *in_dev, int initch, char *in_err, void **in_if, void *in_ext) {
    RadiotapBSD *bsd = *(RadiotapBSD **)in_if;
    if (!bsd->monitor_reset(initch)) {
        strlcpy(in_err, bsd->geterror(), 1024);
        delete bsd;
        return -1;
    } else {
        delete bsd;
        return 1;
    }
}

int chancontrol_bsd(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
    RadiotapBSD bsd(in_dev);
    if (!bsd.chancontrol(in_ch)) {
	strlcpy(in_err, bsd.geterror(), 1024);
	return -1;
    } else {
	return 0;
    }
}
#endif /* HAVE_RADIOTAP */

#endif

