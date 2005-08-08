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

#include "util.h"
#include "packetsourcetracker.h"
#include "packetsource_pcap.h"
#include "tcpdump-extract.h"

#ifdef HAVE_LIBPCAP

// This is such a bad thing to do...
// #include <pcap-int.h>

// Pcap global callback structs, these get filled in by the pcap callback.
// NON-THREAD-SAFE, if we ever use threads.
pcap_pkthdr callback_header;
u_char callback_data[MAX_PACKET_LEN];

int PacketSource_Pcap::OpenSource() {
	char errstr[STATUS_MAX] = "";
	channel = 0;
	char *unconst = strdup(interface.c_str());
	
	pd = pcap_open_live(unconst, MAX_PACKET_LEN, 1, 1000, errstr);

	free(unconst);

	if (strlen(errstr) > 0) {
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	paused = 0;
	errstr[0] = '\0';
	num_packets = 0;

	if (DatalinkType() < 0)
		return -1;

#ifdef HAVE_PCAP_NONBLOCK
	pcap_setnonblock(pd, 1, errstr);
#elif SYS_LINUX
	int save_mode = fcntl(pcap_get_selectable_fd(pd), F_GETFL, 0);
	if (fcntl(pcap_get_selectable_fd(pd), F_SETFL, save_mode | O_NONBLOCK) < 0) {
		snprintf(errstr, STATUS_MAX, "Nonblocking fcntl failed: %s",
				 strerror(errno));
	}
#endif

	if (strlen(errstr) > 0) {
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	return 1;
}

int PacketSource_Pcap::CloseSource() {
	pcap_close(pd);
	return 1;
}

int PacketSource_Pcap::DatalinkType() {
    char errstr[STATUS_MAX] = "";
    datalink_type = pcap_datalink(pd);

    // Blow up if we're not valid 802.11 headers
#if (defined(SYS_FREEBSD) || defined(SYS_OPENBSD))
    if (datalink_type == DLT_EN10MB) {
        snprintf(errstr, STATUS_MAX, "pcap reports link type of EN10MB but we'll "
				 "try to fake it on BSD. This probably will NOT work and probably "
				 "means you're using the WRONG capture source or UNSUPPORTED "
				 "DRIVERS");
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
#if (defined(SYS_FREEBSD) || defined(SYS_NETBSD) && !defined(HAVE_RADIOTAP))
        snprintf(errstr, STATUS_MAX, "Some free- and net- BSD drivers do not report "
				 "rfmon packets correctly.  Kismet may not run correctly.  For "
				 "better support, you should upgrade to a version of BSD with "
				 "radiotap support.");
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
#endif
        datalink_type = KDLT_BSD802_11;
    }
#else
    if (datalink_type == DLT_EN10MB) {
        snprintf(errstr, STATUS_MAX, "pcap reported netlink type 1 (EN10MB) for %s.  "
                 "This probably means you're not in RFMON mode or your drivers are "
                 "reporting a bad value.  Make sure you have the correct drivers "
                 "and that entering monitor mode succeeded.", interface.c_str());
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return -1;
    }
#endif

    // Little hack to give an intelligent error report for radiotap
#ifndef HAVE_RADIOTAP
    if (datalink_type == DLT_IEEE802_11_RADIO) {
        snprintf(errstr, STATUS_MAX, "FATAL: Radiotap link type reported but "
				 "radiotap support was not compiled into Kismet when the configure "
				 "scripts were run.  Make sure that ther radiotap include files "
				 "are detected during configuration");
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return -1;
    }
#endif
    
    if (datalink_type != KDLT_BSD802_11 && datalink_type != DLT_IEEE802_11 &&
        datalink_type != DLT_PRISM_HEADER &&
        datalink_type != DLT_IEEE802_11_RADIO) {
        snprintf(errstr, STATUS_MAX, "Unknown link type %d reported.  Continuing on "
                 "blindly and hoping we get something useful...  This is ALMOST "
				 "CERTIANLY NOT GOING TO WORK RIGHT", datalink_type);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
    }

    return 1;
}

int PacketSource_Pcap::FetchDescriptor() {
	if (pd != NULL)
		return pcap_get_selectable_fd(pd);

	return -1;
}

void PacketSource_Pcap::Pcap_Callback(u_char *bp, const struct pcap_pkthdr *header,
									  const u_char *in_data) {
	// Copy into the globals
	memcpy(&callback_header, header, sizeof(pcap_pkthdr));
	memcpy(callback_data, in_data, kismin(header->len, MAX_PACKET_LEN));
}

int PacketSource_Pcap::Poll() {
	int ret;
	char errstr[STATUS_MAX] = "";

	// Get data from the pcap callbacks
	if ((ret = pcap_dispatch(pd, 1, PacketSource_Pcap::Pcap_Callback, NULL)) < 0) {
		// If we failed to dispatch a packet collection, find out if the interface
		// got downed and give a smarter error message
#ifdef SYS_LINUX
		short flags = 0;
		ret = Ifconfig_Get_Flags(interface.c_str(), errstr, &flags);
		if (ret >= 0 && (flags & IFF_UP) == 0) {
			snprintf(errstr, STATUS_MAX, "Failed to read a packet from %s.  The "
					 "interface is no longer up.  Usually this happens when a DHCP "
					 "client daemon is left running and times out, turning off the "
					 "interface.  See the Kismet README troubleshooting section "
					 "for more information.", interface.c_str());
		} else {
#endif
			snprintf(errstr, STATUS_MAX, "Reading packet from pcap interface %s "
					 "failed, interface is no longer available.", interface.c_str());
#ifdef SYS_LINUX
		}
#endif

		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	if (ret == 0)
		return 0;

	// Genesis a new packet, fill it in with the radio layer info if we have it,
	// and inject it into the system
	kis_packet *newpack = globalreg->packetchain->GeneratePacket();

    if (paused || ManglePacket(newpack) == 0) {
		globalreg->packetchain->DestroyPacket(newpack);
        return 0;
    }

    num_packets++;

	// Set the source (this replaces setting the name and parameters)
	kis_ref_capsource *csrc_ref = new kis_ref_capsource;
	csrc_ref->ref_source = this;
	newpack->insert(_PCM(PACK_COMP_KISCAPSRC), csrc_ref);

	// Inject it into the packetchain
	globalreg->packetchain->ProcessPacket(newpack);

	// Packetchain destroys the packet at the end of processing, so we're done
	// with it here

	return 1;
}

int PacketSource_Pcap::ManglePacket(kis_packet *packet) {
	int ret = 0;

	// Get the timestamp from the pcap callback
	packet->ts = callback_header.ts;

	// Add the link-layer raw data to the packet, for the pristine copy
	kis_datachunk *linkchunk = new kis_datachunk;
	linkchunk->data = new uint8_t[callback_header.caplen];
	linkchunk->length = kismin(callback_header.caplen, (uint32_t) MAX_PACKET_LEN);
	memcpy(linkchunk->data, callback_data, linkchunk->length);
	packet->insert(_PCM(PACK_COMP_LINKFRAME), linkchunk);

	if (datalink_type == DLT_PRISM_HEADER) {
		ret = Prism2KisPack(packet);
#ifdef HAVE_RADIOTAP
	} else if (datalink_type == DLT_IEEE802_11_RADIO) {
		ret = Radiotap2KisPack(packet);
#endif
	}

	// We don't have to do anything else now other than add the signal headers.
	// If the packet only has a LINKFRAME then we can try to use it in place of
	// an 80211FRAME elsewhere in the packet decoders (note to self and others:
	// packet decoders need to process LINKFRAME if no 80211FRAME)
	
	if (ret < 0) {
		return ret;
	}

	// Pull the radio data
	FetchRadioData(packet);

#if 0
	// Build a signalling layer record if we don't have one from the prism
	// headers.  If we can, anyhow.
	kis_layer1_packinfo *radiodata = (kis_layer1_packinfo *) 
		packet->fetch(_PCM(PACK_COMP_RADIODATA));

	if (radiodata == NULL) {
		radiodata = new kis_layer1_packinfo;
		packet->insert(_PCM(PACK_COMP_RADIODATA), radiodata);
	}

	// Fetch the signal levels if we know how and it hasn't been already.
	if (radiodata->signal == 0 && radiodata->noise == 0)
		FetchSignalLevels(&(radiodata->signal), &(radiodata->noise));

	// Fetch the channel if we know how and it hasn't been filled in already
	if (radiodata->channel == 0)
		radiodata->channel = FetchChannel();
#endif

    return ret;
}

int PacketSource_Pcap::Prism2KisPack(kis_packet *packet) {
    int callback_offset = 0;
    char errstr[STATUS_MAX] = "";

	// Make a datachunk for the reformatted frame
	kis_datachunk *eight11chunk = NULL;
	kis_layer1_packinfo *radioheader = NULL;

    // See if we have an AVS wlan header...
    avs_80211_1_header *v1hdr = (avs_80211_1_header *) callback_data;
    if (callback_header.caplen >= sizeof(avs_80211_1_header) &&
        ntohl(v1hdr->version) == 0x80211001 && radioheader == NULL) {

        if (ntohl(v1hdr->length) > callback_header.caplen) {
            snprintf(errstr, STATUS_MAX, "pcap prism2 converter got corrupted "
					 "AVS header length");
            globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
            return 0;
        }

		eight11chunk = new kis_datachunk;
		radioheader = new kis_layer1_packinfo;

        // Subtract the packet FCS since kismet doesn't do anything terribly bright
        // with it right now, also subtract the avs header
		eight11chunk->length = kismin((callback_header.caplen - ntohl(v1hdr->length) -
									  fcsbytes), (uint32_t) MAX_PACKET_LEN);
        callback_offset = ntohl(v1hdr->length);

        // We REALLY need to do something smarter about this and handle the RSSI
        // type instead of just copying
		radioheader->signal = ntohl(v1hdr->ssi_signal);
		radioheader->noise = ntohl(v1hdr->ssi_noise);
		radioheader->channel = ntohl(v1hdr->channel);

        switch (ntohl(v1hdr->phytype)) {
            case 1:
				radioheader->carrier = carrier_80211fhss;
				break;
            case 2:
                radioheader->carrier = carrier_80211dsss;
                break;
            case 4:
            case 5:
                radioheader->carrier = carrier_80211b;
                break;
            case 6:
            case 7:
                radioheader->carrier = carrier_80211g;
                break;
            case 8:
                radioheader->carrier = carrier_80211a;
                break;
            default:
                radioheader->carrier = carrier_unknown;
                break;
        }

        radioheader->encoding = (phy_encoding_type) ntohl(v1hdr->encoding);

        radioheader->datarate = (int) ntohl(v1hdr->datarate);
    }

    // See if we have a prism2 header
    wlan_ng_prism2_header *p2head = (wlan_ng_prism2_header *) callback_data;
    if (callback_header.caplen >= sizeof(wlan_ng_prism2_header) &&
        radioheader == NULL) {

		eight11chunk = new kis_datachunk;
		radioheader = new kis_layer1_packinfo;

        // Subtract the packet FCS since kismet doesn't do anything terribly bright
        // with it right now
        eight11chunk->length = kismin((p2head->frmlen.data - fcsbytes), 
									   (uint32_t) MAX_PACKET_LEN);

        // Set our offset for extracting the actual data
        callback_offset = sizeof(wlan_ng_prism2_header);

        radioheader->signal = p2head->signal.data;
        radioheader->noise = p2head->noise.data;

        radioheader->channel = p2head->channel.data;
    }

    if (radioheader == NULL) {
        snprintf(errstr, STATUS_MAX, "pcap prism2 convverter saw undersized "
				 "capture frame (PRISM80211 linktype, no prism headers)");
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return 0;
    }

	eight11chunk->data = new uint8_t[eight11chunk->length];
    memcpy(eight11chunk->data, callback_data + callback_offset, eight11chunk->length);

	packet->insert(_PCM(PACK_COMP_RADIODATA), radioheader);
	packet->insert(_PCM(PACK_COMP_80211FRAME), eight11chunk);

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

#define BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define BITNO_2(x) (((x) & 2) ? 1 : 0)
#define BIT(n)	(1 << n)

int PacketSource_Pcap::Radiotap2KisPack(kis_packet *packet) {
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
	int fcs_cut = 0; // Is the FCS bit set?
	char errstr[STATUS_MAX];

	kis_datachunk *eight11chunk = NULL;
	kis_layer1_packinfo *radioheader = NULL;

    if (callback_header.caplen < sizeof(*hdr)) {
		snprintf(errstr, STATUS_MAX, "pcap radiotap converter got corrupted "
				 "Radiotap header length");
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return 0;
    }

	// Assign it to the callback data
    hdr = (struct ieee80211_radiotap_header *) callback_data;
    if (callback_header.caplen < hdr->it_len) {
		snprintf(errstr, STATUS_MAX, "pcap radiotap converter got corrupted "
				 "Radiotap header length");
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return 0;
    }

    for (last_presentp = &hdr->it_present;
         (*last_presentp & BIT(IEEE80211_RADIOTAP_EXT)) != 0 &&
         (u_char*)(last_presentp + 1) <= callback_data + hdr->it_len;
         last_presentp++);

    /* are there more bitmap extensions than bytes in header? */
    if ((*last_presentp & BIT(IEEE80211_RADIOTAP_EXT)) != 0) {
		snprintf(errstr, STATUS_MAX, "pcap radiotap converter got corrupted "
				 "Radiotap bitmap length");
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return 0;
    }

	eight11chunk = new kis_datachunk;
	radioheader = new kis_layer1_packinfo;
	
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
                    radioheader->channel = ieee80211_mhz2ieee(u.u16, u2.u16);
                    if (IEEE80211_IS_CHAN_FHSS(u2.u16))
                        radioheader->carrier = carrier_80211dsss;
                    else if (IEEE80211_IS_CHAN_A(u2.u16))
                        radioheader->carrier = carrier_80211a;
                    else if (IEEE80211_IS_CHAN_B(u2.u16))
                        radioheader->carrier = carrier_80211b;
                    else if (IEEE80211_IS_CHAN_PUREG(u2.u16))
                        radioheader->carrier = carrier_80211g;
                    else if (IEEE80211_IS_CHAN_G(u2.u16))
                        radioheader->carrier = carrier_80211g;
                    else if (IEEE80211_IS_CHAN_T(u2.u16))
                        radioheader->carrier = carrier_80211a;/*XXX*/
                    else
                        radioheader->carrier = carrier_unknown;
                    break;
                case IEEE80211_RADIOTAP_RATE:
		    /* strip basic rate bit & convert to kismet units */
                    radioheader->datarate = ((u.u8 &~ 0x80) / 2) * 10;
                    break;
                case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
                    radioheader->signal = u.i8;
                    break;
                case IEEE80211_RADIOTAP_DB_ANTNOISE:
                    radioheader->noise = u.i8;
                    break;
				case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
					radioheader->signal = u.i8;
					break;
				case IEEE80211_RADIOTAP_DBM_ANTNOISE:
					radioheader->noise = u.i8;
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

	if (fcs_cut)
		fcs_cut = fcsbytes;

	eight11chunk->length = callback_header.caplen - hdr->it_len - fcs_cut;
	eight11chunk->data = new uint8_t[eight11chunk->length];
	memcpy(eight11chunk->data, callback_data + hdr->it_len, eight11chunk->length);

	packet->insert(_PCM(PACK_COMP_RADIODATA), radioheader);
	packet->insert(_PCM(PACK_COMP_80211FRAME), eight11chunk);

    return 1;
}
#undef BITNO_32
#undef BITNO_16
#undef BITNO_8
#undef BITNO_4
#undef BITNO_2
#undef BIT

#endif // HAVE_RADIOTAP

int PacketSource_Pcap::FetchChannel() {
	return 0;
}

int PacketSource_Pcapfile::OpenSource() {
	channel = 0;
	char errstr[STATUS_MAX] = "";

	// Open the file offline and bounce out the error
	pd = pcap_open_offline(interface.c_str(), errstr);
	if (strlen(errstr) > 0) {
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	paused = 0;

	num_packets = 0;

	if (DatalinkType() < 0)
		return -1;
	
	return 1;
}

int PacketSource_Pcapfile::Poll() {
	int ret;

	ret = pcap_dispatch(pd, 1, PacketSource_Pcapfile::Pcap_Callback, NULL);

	if (ret < 0) {
		globalreg->messagebus->InjectMessage("Pcap failed to get the next packet",
											 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	} else if (ret == 0) {
		globalreg->messagebus->InjectMessage("Pcap file reached end of capture",
											 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	kis_packet *newpack = globalreg->packetchain->GeneratePacket();

	if (paused || ManglePacket(newpack) < 0) {
		return 0;
	}

	num_packets++;

	kis_ref_capsource *csrc_ref = new kis_ref_capsource;
	csrc_ref->ref_source = this;
	newpack->insert(_PCM(PACK_COMP_KISCAPSRC), csrc_ref);

	globalreg->packetchain->ProcessPacket(newpack);

	return 1;
}

KisPacketSource *packetsource_pcapfile_registrant(REGISTRANT_PARMS) {
	PacketSource_Pcapfile *ret = 
		new PacketSource_Pcapfile(globalreg, in_name, in_device);
	return ret;
}

int unmonitor_pcapfile(MONITOR_PARMS) {
	return 0;
}
#endif

