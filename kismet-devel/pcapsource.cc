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
#include <linux/wireless.h>
#endif

#ifdef SYS_OPENBSD
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <dev/ic/if_wi_ieee.h>
#endif

#ifdef SYS_FREEBSD
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_media.h>
#include <net80211/ieee80211_ioctl.h>

// This should be generic but we'll leave it fbsd only right now -drag
#ifdef HAVE_RADIOTAP
#include <net80211/ieee80211_radiotap.h>
#include "tcpdump-extract.h"
#include <stdarg.h>
#endif

#endif

#include "pcapsource.h"
#include "util.h"

#ifdef HAVE_LIBPCAP

// This is such a bad thing to do...
#include <pcap-int.h>

// Pcap global callback structs
pcap_pkthdr callback_header;
u_char callback_data[MAX_PACKET_LEN];

// Open a source
int PcapSource::OpenSource() {
    channel = 0;

    errstr[0] = '\0';

    char *unconst = strdup(interface.c_str());

    pd = pcap_open_live(unconst, MAX_PACKET_LEN, 1, 1000, errstr);

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
    int save_mode = fcntl(pcap_fileno(pd), F_GETFL, 0);
    if (fcntl(pcap_fileno(pd), F_SETFL, save_mode | O_NONBLOCK) < 0) {
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
#if (defined(SYS_FREEBSD) || defined(SYS_OPENBSD))
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
    return pcap_fileno(pd);
}

void PcapSource::Callback(u_char *bp, const struct pcap_pkthdr *header,
                                 const u_char *in_data) {
    memcpy(&callback_header, header, sizeof(pcap_pkthdr));
    memcpy(callback_data, in_data, header->len);
}

int PcapSource::FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
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

    num_packets++;

    // Set the name
    snprintf(packet->sourcename, 32, "%s", name.c_str());
    
    // Set the parameters
    packet->parm = parameters;
    
    return(packet->caplen);
}

int PcapSource::FCSBytes() {
    return 0;
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

    if (packet->carrier == carrier_unknown)
        packet->carrier = IEEE80211Carrier();
    
    return ret;

}

int PcapSource::Prism2KisPack(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    int header_found = 0;
    int callback_offset = 0;

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

        // Subtract the packet FCS since kismet doesn't do anything terribly bright
        // with it right now
        packet->caplen = kismin(p2head->frmlen.data - fcs, (uint32_t) MAX_PACKET_LEN);
        packet->len = packet->caplen;


        // Set our offset for extracting the actual data
        callback_offset = sizeof(wlan_ng_prism2_header);

        // packet->quality = p2head->sq.data;
        packet->signal = p2head->signal.data;
        packet->noise = p2head->noise.data;

        packet->channel = p2head->channel.data;

    }

    if (header_found == 0) {
        snprintf(errstr, 1024, "pcap prism2 convverter saw undersized capture frame");
        packet->len = 0;
        packet->caplen = 0;
        return 0;
    }

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
                    printf("[0x%08x] ", next_present);
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

    /* copy data down over radiotap header */
    packet->caplen -= hdr->it_len;
    packet->len -= hdr->it_len;
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
int PcapSourceFile::FetchDescriptor() {
    return fileno(pd->sf.rfile);
}

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

    num_packets++;

    // Set the name
    snprintf(packet->sourcename, 32, "%s", name.c_str());
    
    // Set the parameters
    packet->parm = parameters;
    
    return(packet->caplen);
}

#ifdef HAVE_LINUX_WIRELESS
// Simple alias to our ifcontrol interface
int PcapSourceWext::FetchChannel() {
    // Use wireless extensions to get the channel
    return Iwconfig_Get_Channel(interface.c_str(), errstr);
}

int PcapSourceWextFCS::FCSBytes() {
    return 4;
}

int PcapSourceWext::FetchSignalLevels(int *in_siglev, int *in_noiselev) {
    int raw_siglev, raw_noiselev, ret;

    if ((ret = Iwconfig_Get_Levels(interface.c_str(), errstr, 
                                   &raw_siglev, &raw_noiselev)) < 0)
        return ret;

    //return Iwconfig_Get_Levels(interface.c_str(), errstr, in_siglev, in_noiselev);

    (*in_siglev) = abs(raw_siglev);
    (*in_noiselev) = abs(raw_noiselev);

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

int PcapSource11GFCS::FCSBytes() {
    return 4;
}

#endif

#ifdef SYS_LINUX
// FCS bytes for wlanng
int PcapSourceWlanng::FCSBytes() {
    return 4;
}

int PcapSourceWlanng::FetchChannel() {
    // Use wireless extensions to get the channel if we can
#ifdef HAVE_LINUX_WIRELESS
    return Iwconfig_Get_Channel(interface.c_str(), errstr);
#else
    return last_channel;
#endif
}

// The wrt54g seems to put a fcs on it
int PcapSourceWrt54g::FCSBytes() {
    return 4;
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
    packet->parm = parameters;
    
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
		snprintf(errstr, 1024, "Channel set ioctl failed: %s",
                 strerror(errno));
		return -1;
	}

    close(skfd);
    return wreq.wi_val[0];                                                  
}
#endif

#ifdef HAVE_RADIOTAP
int PcapSourceRadiotap::FetchChannel() {
#ifdef SYS_FREEBSD
    FreeBSD bsd(interface.c_str());
    int c;
    return bsd.get80211(IEEE80211_IOC_CHANNEL, c, 0, NULL) ? c : -1;
#elif __linux__
	// use wireless extensions - implement this in the future -drag
#else
#error	"No support for your operating system"
#endif
}

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
    return new PcapSourceWrt54g(in_name, in_device);
}
#endif

#ifdef SYS_OPENBSD
KisPacketSource *pcapsource_openbsdprism2_registrant(string in_name, string in_device,
                                                     char *in_err) {
    return new PcapSourceOpenBSDPrism(in_name, in_device);
}
#endif

#ifdef HAVE_RADIOTAP
KisPacketSource *pcapsource_radiotap_registrant(string in_name, string in_device,
                                                     char *in_err) {
    return new PcapSourceRadiotap(in_name, in_device);
}
#endif

// Monitor commands
#ifdef HAVE_LINUX_WIRELESS
// Cisco uses its own config file in /proc to control modes
int monitor_cisco(const char *in_dev, int initch, char *in_err, void **in_if) {
    FILE *cisco_config;
    char cisco_path[128];

    if (Ifconfig_Delta_Flags(in_dev, in_err, IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0)
        return -1;

    // Zero the ssid
    if (Iwconfig_Set_SSID(in_dev, in_err, NULL) < 0)
        return -1;
    
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

// Cisco uses its own config file in /proc to control modes
//
// I was doing this with ioctls but that seems to cause lockups while
// this method doesn't.  I don't think I like these drivers.
int monitor_cisco_wifix(const char *in_dev, int initch, char *in_err, void **in_if) {
    FILE *cisco_config;
    char cisco_path[128];
    vector<string> devbits = StrTokenize(in_dev, ":");

    if (devbits.size() < 2) {
        snprintf(in_err, STATUS_MAX, "Invalid device pair '%s'", in_dev);
        return -1;
    }

    // Bring the device up, zero its ip, and set promisc
    if (Ifconfig_Delta_Flags(devbits[0].c_str(), in_err, 
                             IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0)
        return -1;
    if (Ifconfig_Delta_Flags(devbits[1].c_str(), in_err, 
                             IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0)
        return -1;

    // Zero the ssid
    if (Iwconfig_Set_SSID(devbits[0].c_str(), in_err, NULL) < 0)
        return -1;
    if (Iwconfig_Set_SSID(devbits[1].c_str(), in_err, NULL) < 0)
        return -1;
    
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
int monitor_hostap(const char *in_dev, int initch, char *in_err, void **in_if) {
    int ret;
  
    // Allocate a tracking record for the interface settings and remember our
    // setup
    linux_ifparm *ifparm = (linux_ifparm *) malloc(sizeof(linux_ifparm));
    (*in_if) = ifparm;

    if (Ifconfig_Get_Flags(in_dev, in_err, &ifparm->flags) < 0)
        return -1;

    if (Iwconfig_Get_SSID(in_dev, in_err, ifparm->essid) < 0)
        return -1;

    if ((ifparm->channel = Iwconfig_Get_Channel(in_dev, in_err)) < 0)
        return -1;

    if (Iwconfig_Get_Mode(in_dev, in_err, &ifparm->mode) < 0)
        return -1;
    
    // Try to use the iwpriv command to set monitor mode.  Some versions of
    // hostap require this, some don't, so don't fail on the monitor ioctl
    // if we can't find it, it might get removed in the future.
    if ((ret = Iwconfig_Set_IntPriv(in_dev, "monitor", 3, 0, in_err)) < 0) {
        if (ret != -2)
            return -1;
    }
   
    // Try to set wext monitor mode.  We're good if one of these succeeds...
    if (monitor_wext(in_dev, initch, in_err, in_if) < 0 && ret < 0)
        return -1;

    // If we didn't set wext mode, set the channel manually
    if (chancontrol_wext(in_dev, initch, in_err, NULL) < 0)
        return -1;

    return 0;
}

int unmonitor_hostap(const char *in_dev, int initch, char *in_err, void **in_if) {

    // Restore the IP settings
    linux_ifparm *ifparm = (linux_ifparm *) (*in_if);

    if (Ifconfig_Set_Flags(in_dev, in_err, ifparm->flags) < 0) {
        return -1;
    }

    if (Iwconfig_Set_Channel(in_dev, ifparm->channel, in_err) < 0)
        return -1;

    if (Iwconfig_Set_SSID(in_dev, in_err, ifparm->essid) < 0)
        return -1;
    
    // Ignore errors from both of these, since one might fail with other versions
    // of hostap
    Iwconfig_Set_IntPriv(in_dev, "monitor", 0, 0, in_err);
    Iwconfig_Set_Mode(in_dev, in_err, ifparm->mode);

    free(ifparm);

    return 0;
}

// Orinoco uses iwpriv and iwcontrol settings to control monitor mode
int monitor_orinoco(const char *in_dev, int initch, char *in_err, void **in_if) {
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

    // Bring the device up, zero its ip, and set promisc
    if (Ifconfig_Delta_Flags(in_dev, in_err, IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0)
        return -1;

    // Zero the ssid
    if (Iwconfig_Set_SSID(in_dev, in_err, NULL) < 0) 
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
   
    // Try to set wext monitor mode.  We're good if one of these succeeds...
    if (monitor_wext(in_dev, initch, in_err, in_if) < 0 && ret < 0) {
        snprintf(in_err, 1024, "Could not find 'monitor' private ioctl or use "
                 "the newer style 'mode monitor' command.  This typically means "
                 "that the drivers have not been patched or the "
                 "correct drivers are being loaded. See the troubleshooting "
                 "section of the README for more information.");
        return -1;
    }

    // If we didn't use iwpriv, set the channel directly
    if (chancontrol_wext(in_dev, initch, in_err, NULL) < 0 && ret < 0)
        return -1;
    
    return 0;
}

int unmonitor_orinoco(const char *in_dev, int initch, char *in_err, void **in_if) {
    // Restore the IP settings
    linux_ifparm *ifparm = (linux_ifparm *) (*in_if);

    if (Ifconfig_Set_Flags(in_dev, in_err, ifparm->flags) < 0) {
        return -1;
    }

    // Ignore errors from both of these, since one might fail with other versions
    // of orinoco_cs
    Iwconfig_Set_IntPriv(in_dev, "monitor", 0, ifparm->channel, in_err);
    Iwconfig_Set_Mode(in_dev, in_err, ifparm->mode);

    if (Iwconfig_Set_SSID(in_dev, in_err, ifparm->essid) < 0)
        return -1;
    
    free(ifparm);

    return 0;

}

// Acx100 uses the packhdr iwpriv control to set link state, rest is normal
int monitor_acx100(const char *in_dev, int initch, char *in_err, void **in_if) {
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

    // Set the packhdr iwpriv control to 1
    if (Iwconfig_Set_IntPriv(in_dev, "packhdr", 1, 0, in_err) < 0) {
        return -1;
    }
    
    // The rest is standard wireless extensions
    if (monitor_wext(in_dev, initch, in_err, in_if) < 0)
        return -1;

    return 0;
}

int unmonitor_acx100(const char *in_dev, int initch, char *in_err, void **in_if) {
    if (Iwconfig_Set_IntPriv(in_dev, "packhdr", 0, 0, in_err) < 0) {
        return -1;
    }

    return unmonitor_wext(in_dev, initch, in_err, in_if);
}

// vtar5k iwpriv control to set link state, rest is normal
int monitor_vtar5k(const char *in_dev, int initch, char *in_err, void **in_if) {
    // Set the prism iwpriv control to 1
    if (Iwconfig_Set_IntPriv(in_dev, "prism", 1, 0, in_err) < 0) {
        return -1;
    }
    
    // The rest is standard wireless extensions
    if (monitor_wext(in_dev, initch, in_err, in_if) < 0)
        return -1;

    return 0;
}

// Madwifi stuff uses iwpriv mode
int monitor_madwifi_a(const char *in_dev, int initch, char *in_err, void **in_if) {
    if (Iwconfig_Set_IntPriv(in_dev, "mode", 1, 0, in_err) < 0)
        return -1;

    // The rest is standard wireless extensions
    if (monitor_wext(in_dev, initch, in_err, in_if) < 0)
        return -1;

    return 0;
}

int monitor_madwifi_b(const char *in_dev, int initch, char *in_err, void **in_if) {
    if (Iwconfig_Set_IntPriv(in_dev, "mode", 2, 0, in_err) < 0)
        return -1;

    // The rest is standard wireless extensions
    if (monitor_wext(in_dev, initch, in_err, in_if) < 0)
        return -1;

    return 0;
}

int monitor_madwifi_g(const char *in_dev, int initch, char *in_err, void **in_if) {
    if (Iwconfig_Set_IntPriv(in_dev, "mode", 3, 0, in_err) < 0)
        return -1;

    // The rest is standard wireless extensions
    if (monitor_wext(in_dev, initch, in_err, in_if) < 0)
        return -1;

    return 0;
}

int monitor_madwifi_comb(const char *in_dev, int initch, char *in_err, void **in_if) {
    if (Iwconfig_Set_IntPriv(in_dev, "mode", 0, 0, in_err) < 0)
        return -1;

    // The rest is standard wireless extensions
    if (monitor_wext(in_dev, initch, in_err, in_if) < 0)
        return -1;

    return 0;
}

// Call the standard monitor but ignore error codes since channel
// setting won't work.  This is a temp kluge.
int monitor_prism54g(const char *in_dev, int initch, char *in_err, void **in_if) {
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

    int ret = monitor_wext(in_dev, initch, in_err, in_if);

    if (ret < 0 && ret != -2)
        return ret;
    
    return 0;
}

int unmonitor_prism54g(const char *in_dev, int initch, char *in_err, void **in_if) {
    return unmonitor_wext(in_dev, initch, in_err, in_if);
}

// "standard" wireless extension monitor mode
int monitor_wext(const char *in_dev, int initch, char *in_err, void **in_if) {
    struct iwreq wrq;
    int skfd;

    // Bring the device up, zero its ip, and set promisc
    if (Ifconfig_Delta_Flags(in_dev, in_err, IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0)
        return -1;

    // Zero the ssid
    if (Iwconfig_Set_SSID(in_dev, in_err, NULL) < 0) 
        return -1;

    // Kick it into rfmon mode
    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(in_err, STATUS_MAX, "Failed to create AF_INET DGRAM socket %d:%s", 
                 errno, strerror(errno));
        return -1;
    }

    // Get mode and see if we're already in monitor, don't try to go in
    // if we are (cisco doesn't like rfmon rfmon)
    memset(&wrq, 0, sizeof(struct iwreq));
    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);

    if (ioctl(skfd, SIOCGIWMODE, &wrq) < 0) {
        snprintf(in_err, STATUS_MAX, "Failed to get mode %d:%s", 
                 errno, strerror(errno));
        close(skfd);
        return -1;
    }

    if (wrq.u.mode != LINUX_WLEXT_MONITOR) {
        // Set it
        memset(&wrq, 0, sizeof(struct iwreq));
        strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);
        wrq.u.mode = LINUX_WLEXT_MONITOR;

        if (ioctl(skfd, SIOCSIWMODE, &wrq) < 0) {
            snprintf(in_err, STATUS_MAX, "Failed to set monitor mode: %s.  This usually "
                     "means your drivers either do not support monitor mode, or use a "
                     "different mechanism for getting to it.  Make sure you have a "
                     "version of your drivers that support monitor mode, and consult "
                     "the troubleshooting section of the README.", 
                     strerror(errno));
            close(skfd);
            return -1;
        }
    }
    
    // Set the initial channel - if we ever get a pcapsource that needs a hook
    // back into the class, this will have to be rewritten
    if (chancontrol_wext(in_dev, initch, in_err, NULL) < 0) {
        close(skfd);
        return -2;
    }
    
    close(skfd);
    return 0;
}

int unmonitor_wext(const char *in_dev, int initch, char *in_err, void **in_if) {
    // Restore the IP settings
    linux_ifparm *ifparm = (linux_ifparm *) (*in_if);

    if (Ifconfig_Set_Flags(in_dev, in_err, ifparm->flags) < 0) {
        return -1;
    }

    if (Iwconfig_Set_Mode(in_dev, in_err, ifparm->mode) < 0)
        return -1;

    if (Iwconfig_Set_Channel(in_dev, ifparm->channel, in_err) < 0)
        return -1;

    if (Iwconfig_Set_SSID(in_dev, in_err, ifparm->essid) < 0)
        return -1;
    
    free(ifparm);

    return 0;
}

#endif

#ifdef SYS_LINUX
// wlan-ng modern standard
int monitor_wlanng(const char *in_dev, int initch, char *in_err, void **in_if) {
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
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

    // Turn off WEP
    snprintf(cmdline, 2048, "wlanctl-ng %s dot11req_mibset mibattribute=dot11PrivacyInvoked=false >/dev/null 2>/dev/null", in_dev);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

    // Don't exclude packets
    snprintf(cmdline, 2048, "wlanctl-ng %s dot11req_mibset mibattribute=dot11ExcludeUnencrypted=false >/dev/null 2>/dev/null", in_dev);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

    // Turn on rfmon on the initial channel
    snprintf(cmdline, 2048, "wlanctl-ng %s lnxreq_wlansniff channel=%d enable=true prismheader=true >/dev/null 2>/dev/null", in_dev, initch);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;
    
    return 0;
}

// wlan-ng avs
int monitor_wlanng_avs(const char *in_dev, int initch, char *in_err, void **in_if) {
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
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

    // Turn off WEP
    snprintf(cmdline, 2048, "wlanctl-ng %s dot11req_mibset "
             "mibattribute=dot11PrivacyInvoked=false >/dev/null 2>/dev/null", in_dev);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

    // Don't exclude packets
    snprintf(cmdline, 2048, "wlanctl-ng %s dot11req_mibset "
             "mibattribute=dot11ExcludeUnencrypted=false >/dev/null 2>/dev/null", in_dev);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

    // Turn on rfmon on the initial channel
    snprintf(cmdline, 2048, "wlanctl-ng %s lnxreq_wlansniff channel=%d prismheader=false "
             "wlanheader=true stripfcs=false keepwepflags=false enable=true >/dev/null 2>/dev/null", in_dev, initch);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;
    
    return 0;
}

int monitor_wrt54g(const char *in_dev, int initch, char *in_err, void **in_if) {
    char cmdline[2048];

    snprintf(cmdline, 2048, "/usr/sbin/wl monitor 1");
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

    return 0;
}

#endif

#ifdef SYS_OPENBSD
// This should be done programattically...
int monitor_openbsd_cisco(const char *in_dev, int initch, char *in_err, void **in_if) {
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
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

    snprintf(cmdline, 2048, "ancontrol -i %s -p 1", in_dev);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

    snprintf(cmdline, 2048, "ancontrol -i %s -M 7", in_dev);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;
    
    return 0;
}

int monitor_openbsd_prism2(const char *in_dev, int initch, char *in_err, void **in_if) {
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
        return -1;
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
        return -1;
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
        return -1;
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
    if (in_ch > 0 && in_ch <= 14) {
        if (Iwconfig_Set_IntPriv(in_dev, "mode", 3, 0, in_err) < 0)
            return -1;
    } else {
        if (Iwconfig_Set_IntPriv(in_dev, "mode", 1, 0, in_err) < 0)
            return -1;
    }

    return chancontrol_wext(in_dev, in_ch, in_err, in_ext);
}

int chancontrol_prism54g(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
    // Run the wireless extention stuff and scrap the error codes
    chancontrol_wext(in_dev, in_ch, in_err, in_ext);

    return 0;
}

#endif

#ifdef SYS_LINUX
int chancontrol_wlanng(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
    // I really didn't want to do this...
    char cmdline[2048];

    // Turn on rfmon on the initial channel
    snprintf(cmdline, 2048, "wlanctl-ng %s lnxreq_wlansniff channel=%d enable=true "
             "prismheader=true >/dev/null 2>&1", in_dev, in_ch);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

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

    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

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

#ifdef SYS_FREEBSD
FreeBSD::FreeBSD(const char *name) : ifname(name) {
    s = -1;
}

FreeBSD::~FreeBSD() {
    if (s >= 0)
        close(s);
}

const char *FreeBSD::geterror() const {
	return errstr;
}

void FreeBSD::perror(const char *fmt, ...) {
#if 0
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(errstr, sizeof(errstr), fmt, ap);
	va_end(ap);
	char *cp = strchr(errstr, '\0');
	vsnprintf(cp, sizeof(errstr) - (cp - errstr), ": %s", strerror(errno));
#else
	snprintf(errstr, sizeof(errstr), "%s: %s", fmt, strerror(errno));
#endif
}

void FreeBSD::seterror(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(errstr, sizeof(errstr), fmt, ap);
	va_end(ap);
}

bool FreeBSD::checksocket() {
    if (s < 0) {
        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) {
            perror("Failed to create AF_INET socket");
            return false;
        }
    }
    return true;
}

bool FreeBSD::setmediaopt(int options, int mode) {
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
        perror("%s: cannot get ifmedia", ifname.c_str());
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
        perror("%s: cannot get ifmedia", ifname.c_str());
        return false;
    }
    delete mwords;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname.c_str(), sizeof(ifr.ifr_name));
    ifr.ifr_media = (ifmr.ifm_current &~ IFM_OMASK) | options;
    ifr.ifr_media = (ifr.ifr_media &~ IFM_MMASK) | IFM_MAKEMODE(mode);

    if (ioctl(s, SIOCSIFMEDIA, (caddr_t)&ifr) < 0) {
        perror("%s: cannot set ifmedia", ifname.c_str());
        return false;
    }
    return true;
}

bool FreeBSD::get80211(int type, int& val, int len, u_int8_t *data) {
    struct ieee80211req ireq;

    if (!checksocket())
        return false;
    memset(&ireq, 0, sizeof(ireq));
    strncpy(ireq.i_name, ifname.c_str(), sizeof(ireq.i_name));
    ireq.i_type = type;
    ireq.i_len = len;
    ireq.i_data = data;
    if (ioctl(s, SIOCG80211, &ireq) < 0) {
        perror("%s: SIOCG80211 ioctl failed", ifname.c_str());
        return false;
    }
    val = ireq.i_val;
    return true;
}

bool FreeBSD::set80211(int type, int val, int len, u_int8_t *data) {
    struct ieee80211req ireq;

    if (!checksocket())
	return false;
    memset(&ireq, 0, sizeof(ireq));
    strncpy(ireq.i_name, ifname.c_str(), sizeof(ireq.i_name));
    ireq.i_type = type;
    ireq.i_val = val;
    ireq.i_len = len;
    ireq.i_data = data;
    if (ioctl(s, SIOCS80211, &ireq) < 0) {
	perror("%s: SIOCS80211 ioctl failed", ifname.c_str());
	return false;
    }
    return true;
}

bool FreeBSD::getifflags(int& flags) {
    struct ifreq ifr;

    if (!checksocket())
        return false;

    strncpy(ifr.ifr_name, ifname.c_str(), sizeof (ifr.ifr_name));
    if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
        perror("%s: SIOCGIFFLAGS ioctl failed", ifname.c_str());
        return false;
    }
    flags = (ifr.ifr_flags & 0xffff) | (ifr.ifr_flagshigh << 16);
    return true;
}

bool FreeBSD::setifflags(int value) {
    struct ifreq ifr;
    int flags;

    if (!getifflags(flags))
        return false;

    if (value < 0) {
        value = -value;
        flags &= ~value;
    } else
        flags |= value;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname.c_str(), sizeof (ifr.ifr_name));
    ifr.ifr_flags = flags & 0xffff;
    ifr.ifr_flagshigh = flags >> 16;
    if (ioctl(s, SIOCSIFFLAGS, (caddr_t)&ifr) < 0) {
        perror("%s: SIOCSIFFLAGS ioctl failed", ifname.c_str());
        return false;
    }
    return true;
}

bool FreeBSD::monitor_enable(int initch) {
    /*
     * Enter monitor mode, set the specified channel,
     * enable promiscuous reception, and force the
     * interface up since otherwise bpf won't work.
     */
    if (!setmediaopt(IFM_IEEE80211_MONITOR, IFM_AUTO))
        return false;
    if (!set80211(IEEE80211_IOC_CHANNEL, initch, 0, NULL))
        return false;
    if (!setifflags(IFF_PPROMISC | IFF_UP))
        return false;
    return true;
}

bool FreeBSD::monitor_reset(int initch) {
    (void) setifflags(-IFF_PPROMISC);
    /* NB: reset the current channel before switching modes */
    (void) set80211(IEEE80211_IOC_CHANNEL, initch, 0, NULL);
    /* XXX restore previous options/operating mode */
    (void) setmediaopt(0, IFM_AUTO);
    return true;
}

bool FreeBSD::chancontrol(int in_ch) {
    return set80211(IEEE80211_IOC_CHANNEL, in_ch, 0, NULL);
}

int monitor_freebsd(const char *in_dev, int initch, char *in_err, void **in_if) {
    FreeBSD bsd(in_dev);
    if (!bsd.monitor_enable(initch)) {
        strcpy(in_err, bsd.geterror());
        return -1;
    } else {
        return 0;
    }
}

int unmonitor_freebsd(const char *in_dev, int initch, char *in_err, void **in_if) {
    FreeBSD bsd(in_dev);
    if (!bsd.monitor_reset(initch)) {
	strcpy(in_err, bsd.geterror());
	return -1;
    } else {
	return 0;
    }
}

int chancontrol_freebsd(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
    FreeBSD bsd(in_dev);
    if (!bsd.chancontrol(in_ch)) {
	strcpy(in_err, bsd.geterror());
	return -1;
    } else {
	return 0;
    }
}
#endif /* SYS_FREEBSD */

#endif

