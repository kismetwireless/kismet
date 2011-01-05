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

#include "gpscore.h"

#ifdef HAVE_LINUX_WIRELESS
// Because some kernels include ethtool which breaks horribly...
// The stock ones don't but others seem to
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

#include <asm/types.h>
#include <linux/if.h>
#include <linux/wireless.h>
#endif

#ifdef SYS_DARWIN
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
extern "C" {
#include <net/bpf.h>
#include <pcap-bpf.h>
}
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

#include "util.h"
#include "endian_magic.h"
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
	last_channel = 0;
	char *unconst = strdup(interface.c_str());

	pd = pcap_open_live(unconst, MAX_PACKET_LEN, 1, 1000, errstr);

	free(unconst);

	if (strlen(errstr) > 0) {
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		return 0;
	}

	error = 0;
	
	paused = 0;
	errstr[0] = '\0';
	num_packets = 0;

	// Anything but windows and linux
    #if defined (SYS_OPENBSD) || defined(SYS_NETBSD) || defined(SYS_FREEBSD) \
		|| defined(SYS_DARWIN)
	// Set the DLT in the order of what we want least, since the last one we
	// set will stick
	pcap_set_datalink(pd, DLT_IEEE802_11);
	pcap_set_datalink(pd, DLT_IEEE802_11_RADIO_AVS);
	pcap_set_datalink(pd, DLT_IEEE802_11_RADIO);
	// Hack to re-enable promisc mode since changing the DLT seems to make it
	// drop it on some bsd pcap implementations
	ioctl(pcap_get_selectable_fd(pd), BIOCPROMISC, NULL);
	// Hack to set the fd to IOIMMEDIATE, to solve problems with select() on bpf
	// devices on BSD
	int v = 1;
	ioctl(pcap_get_selectable_fd(pd), BIOCIMMEDIATE, &v);
	#endif

	if (DatalinkType() < 0) {
		pcap_close(pd);
		return -1;
	}

#ifdef HAVE_PCAP_NONBLOCK
    pcap_setnonblock(pd, 1, errstr);
#elif !defined(SYS_OPENBSD) && defined(HAVE_PCAP_GETSELFD)
    // do something clever  (Thanks to Guy Harris for suggesting this).
    int save_mode = fcntl(pcap_get_selectable_fd(pd), F_GETFL, 0);
    if (fcntl(pcap_get_selectable_fd(pd), F_SETFL, save_mode | O_NONBLOCK) < 0) {
        snprintf(errstr, 1024, "fcntl failed, errno %d (%s)",
                 errno, strerror(errno));
    }
#endif

	if (strlen(errstr) > 0) {
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		pcap_close(pd);
		return 0;
	}

	return 1;
}

int PacketSource_Pcap::CloseSource() {
	if (pd != NULL)
		pcap_close(pd);
	pd = NULL;
	return 1;
}

int PacketSource_Pcap::DatalinkType() {
    char errstr[STATUS_MAX] = "";
    datalink_type = pcap_datalink(pd);

	// Known good pcap generic header types
	if (datalink_type == DLT_PRISM_HEADER ||
		datalink_type == DLT_IEEE802_11_RADIO ||
		datalink_type == DLT_IEEE802_11_RADIO_AVS ||
		datalink_type == DLT_IEEE802_11 ||
		datalink_type == DLT_PPI)
		return 1;

	if (datalink_type == DLT_EN10MB && override_dlt >= 0) {
		_MSG("pcap reported netlink type 1 (EN10MB) for " + interface + ", but "
			 "Kismet will override it with netlink " + IntToString(override_dlt),
			 MSGFLAG_INFO);
		datalink_type = override_dlt;
		return 1;
	}

    // Blow up if we're not valid 802.11 headers
	// Need to not blow up on en10mb?  Override.
    if (datalink_type == DLT_EN10MB) {
        snprintf(errstr, STATUS_MAX, "pcap reported netlink type 1 (EN10MB) for %s.  "
                 "This probably means you're not in RFMON mode or your drivers are "
                 "reporting a bad value.  Make sure you have the correct drivers "
                 "and that entering monitor mode succeeded.", interface.c_str());
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		return 0;
    } else {
        snprintf(errstr, STATUS_MAX, "Unknown link type %d reported.  Continuing on "
                 "blindly and hoping we get something useful...  Unless you have "
				 "loaded plugins for this packet type, Kismet is not going to report "
				 "useful packets.", datalink_type);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
    }

    return 1;
}

int PacketSource_Pcap::FetchDescriptor() {
	if (pd == NULL) {
		return -1;
	}

	if (error) {
		return -1;
	}

#ifdef HAVE_PCAP_GETSELFD
    return pcap_get_selectable_fd(pd);
#else
	return -1;
#endif
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
		int flags = 0;
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

		error = 1;
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		CloseSource();
		return 0;
	}

	if (ret == 0)
		return 0;

	if (paused)
		return 0;

	// Genesis a new packet, fill it in with the radio layer info if we have it,
	// and inject it into the system
	kis_packet *newpack = globalreg->packetchain->GeneratePacket();

	// Get the timestamp from the pcap callback
	newpack->ts.tv_sec = callback_header.ts.tv_sec;
	newpack->ts.tv_usec = callback_header.ts.tv_usec;

	// Add the link-layer raw data to the packet, for the pristine copy
	kis_datachunk *linkchunk = new kis_datachunk;
	linkchunk->dlt = datalink_type;
	linkchunk->source_id = source_id;
	linkchunk->data = 
		new uint8_t[kismin(callback_header.caplen, (uint32_t) MAX_PACKET_LEN)];
	linkchunk->length = kismin(callback_header.caplen, (uint32_t) MAX_PACKET_LEN);
	memcpy(linkchunk->data, callback_data, linkchunk->length);
	newpack->insert(_PCM(PACK_COMP_LINKFRAME), linkchunk);

	// Only decode the DLT if we're asked to
	if (dlt_mangle)
		ManglePacket(newpack, linkchunk);

	num_packets++;

	// Flag the header
	kis_ref_capsource *csrc_ref = new kis_ref_capsource;
	csrc_ref->ref_source = this;
	newpack->insert(_PCM(PACK_COMP_KISCAPSRC), csrc_ref);

	// Inject it into the packetchain
	globalreg->packetchain->ProcessPacket(newpack);

	// Packetchain destroys the packet at the end of processing, so we're done
	// with it here

	return 1;
}

int PacketSource_Pcap::ManglePacket(kis_packet *packet, kis_datachunk *linkchunk) {
	int ret = 0;

	if (linkchunk->dlt == DLT_PRISM_HEADER || 
		linkchunk->dlt == DLT_IEEE802_11_RADIO_AVS) {
		ret = Prism2KisPack(packet, linkchunk);
	} else if (linkchunk->dlt == DLT_IEEE802_11_RADIO) {
		ret = Radiotap2KisPack(packet, linkchunk);
	} else if (linkchunk->dlt == DLT_PPI) {
		ret = PPI2KisPack(packet, linkchunk);
	} else if (linkchunk->dlt == DLT_IEEE802_11) {
		ret = Eight2KisPack(packet, linkchunk);
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

    return ret;
}

int PacketSource_Pcap::Eight2KisPack(kis_packet *packet, kis_datachunk *linkchunk) {
	kis_datachunk *eight11chunk = NULL;

	eight11chunk = new kis_datachunk;

	eight11chunk->dlt = KDLT_IEEE802_11;

	eight11chunk->length = kismin((linkchunk->length - fcsbytes), 
								  (uint32_t) MAX_PACKET_LEN);

	eight11chunk->data = new uint8_t[eight11chunk->length];
    memcpy(eight11chunk->data, linkchunk->data, eight11chunk->length);

	kis_fcs_bytes *fcschunk = NULL;
	if (fcsbytes && linkchunk->length > 4) {
		fcschunk = new kis_fcs_bytes;
		memcpy(fcschunk->fcs, &(linkchunk->data[linkchunk->length - 4]), 4);
		// Valid until proven otherwise
		fcschunk->fcsvalid = 1;

		packet->insert(_PCM(PACK_COMP_FCSBYTES), fcschunk);
	}

	// If we're validating the FCS
	if (validate_fcs && fcschunk != NULL) {
		// Compare it and flag the packet
		uint32_t calc_crc =
			crc32_le_80211(globalreg->crc32_table, eight11chunk->data, 
						   eight11chunk->length);

		if (memcmp(fcschunk->fcsp, &calc_crc, 4)) {
			packet->error = 1;
			fcschunk->fcsvalid = 0;
			//fprintf(stderr, "debug - dot11 to kis, fcs invalid\n");
		} else {
			fcschunk->fcsvalid = 1;
		}
	}

	packet->insert(_PCM(PACK_COMP_80211FRAME), eight11chunk);

	return 1;
}

int PacketSource_Pcap::Prism2KisPack(kis_packet *packet, kis_datachunk *linkchunk) {
    int callback_offset = 0;
    char errstr[STATUS_MAX] = "";

	// Make a datachunk for the reformatted frame
	kis_datachunk *eight11chunk = NULL;
	kis_layer1_packinfo *radioheader = NULL;

    // See if we have an AVS wlan header...
    avs_80211_1_header *v1hdr = (avs_80211_1_header *) linkchunk->data;
    if (linkchunk->length >= sizeof(avs_80211_1_header) &&
        ntohl(v1hdr->version) == 0x80211001) {

        if (ntohl(v1hdr->length) > linkchunk->length ||
			linkchunk->length < (ntohl(v1hdr->length) + fcsbytes)) {
            snprintf(errstr, STATUS_MAX, "pcap prism2 converter got corrupted "
					 "AVS header length");
            globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
            return 0;
        }

		eight11chunk = new kis_datachunk;
		radioheader = new kis_layer1_packinfo;

		eight11chunk->dlt = KDLT_IEEE802_11;

        // Subtract the packet FCS since kismet doesn't do anything terribly bright
        // with it right now, also subtract the avs header.  We have to obey the
		// header length here since avs could change
		eight11chunk->length = kismin((linkchunk->length - ntohl(v1hdr->length) -
									  fcsbytes), (uint32_t) MAX_PACKET_LEN);
        callback_offset = ntohl(v1hdr->length);

        // We REALLY need to do something smarter about this and handle the RSSI
        // type instead of just copying
		radioheader->signal_rssi = ntohl(v1hdr->ssi_signal);
		radioheader->noise_rssi = ntohl(v1hdr->ssi_noise);

		radioheader->freq_mhz = ChanToFreq(ntohl(v1hdr->channel));

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
    wlan_ng_prism2_header *p2head = (wlan_ng_prism2_header *) linkchunk->data;
	if (linkchunk->length >= (sizeof(wlan_ng_prism2_header) + fcsbytes) &&
        radioheader == NULL) {

		eight11chunk = new kis_datachunk;
		radioheader = new kis_layer1_packinfo;

		eight11chunk->dlt = KDLT_IEEE802_11;

#if 0
        // Subtract the packet FCS since kismet doesn't do anything terribly bright
        // with it right now
		if (p2head->frmlen.data < fcsbytes) {
			snprintf(errstr, STATUS_MAX, "pcap prism2 converter got corrupted "
					 "wlanng-header frame length");
			globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
			return 0;
		}
#endif
		
		// We don't pay attention to the length provided by prism2hdr, since
		// some drivers get it wrong
		eight11chunk->length = kismin((linkchunk->length - 
									   sizeof(wlan_ng_prism2_header) - fcsbytes),
									  (uint32_t) MAX_PACKET_LEN);

#if 0
        eight11chunk->length = kismin((p2head->frmlen.data - fcsbytes), 
									   (uint32_t) MAX_PACKET_LEN);
#endif

        // Set our offset for extracting the actual data
        callback_offset = sizeof(wlan_ng_prism2_header);

        radioheader->signal_rssi = p2head->signal.data;
        radioheader->noise_rssi = p2head->noise.data;

        radioheader->freq_mhz = ChanToFreq(p2head->channel.data);
    }

    if (radioheader == NULL) {
        snprintf(errstr, STATUS_MAX, "pcap prism2 converter saw strange "
				 "capture frame (PRISM80211 linktype, unable to determine "
				 "prism headers)");
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return 0;
    }

	eight11chunk->data = new uint8_t[eight11chunk->length];
    memcpy(eight11chunk->data, linkchunk->data + callback_offset, eight11chunk->length);

	packet->insert(_PCM(PACK_COMP_RADIODATA), radioheader);
	packet->insert(_PCM(PACK_COMP_80211FRAME), eight11chunk);

	kis_fcs_bytes *fcschunk = NULL;
	if (fcsbytes && linkchunk->length > 4) {
		fcschunk = new kis_fcs_bytes;
		memcpy(fcschunk->fcs, &(linkchunk->data[linkchunk->length - 4]), 4);
		// Valid until proven otherwise
		fcschunk->fcsvalid = 1;

		packet->insert(_PCM(PACK_COMP_FCSBYTES), fcschunk);
	}

	// If we're validating the FCS
	if (validate_fcs && fcschunk != NULL) {
		// Compare it and flag the packet
		uint32_t calc_crc =
			crc32_le_80211(globalreg->crc32_table, eight11chunk->data, 
						   eight11chunk->length);

		if (memcmp(fcschunk->fcsp, &calc_crc, 4)) {
			packet->error = 1;
			fcschunk->fcsvalid = 0;
		} else {
			fcschunk->fcsvalid = 1;
		}
	}

    return 1;
}

/*
 * Convert MHz frequency to IEEE channel number.
 */
#if 0
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
#endif

/*
 * Useful combinations of channel characteristics.
 */
#define	IEEE80211_CHAN_FHSS \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_GFSK)
#define	IEEE80211_CHAN_A \
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_BPLUS \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK | IEEE80211_CHAN_TURBO)
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
#define	IEEE80211_IS_CHAN_BPLUS(_flags) \
	((_flags & IEEE80211_CHAN_BPLUS) == IEEE80211_CHAN_BPLUS)
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

int PacketSource_Pcap::Radiotap2KisPack(kis_packet *packet, kis_datachunk *linkchunk) {
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

    if (linkchunk->length < sizeof(*hdr)) {
		snprintf(errstr, STATUS_MAX, "pcap radiotap converter got corrupted "
				 "Radiotap header length");
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return 0;
    }

	// Assign it to the callback data
    hdr = (struct ieee80211_radiotap_header *) linkchunk->data;
    if (linkchunk->length < EXTRACT_LE_16BITS(&hdr->it_len)) {
		snprintf(errstr, STATUS_MAX, "pcap radiotap converter got corrupted "
				 "Radiotap header length");
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return 0;
    }

	// null-statement for-loop
    for (last_presentp = &hdr->it_present;
         (EXTRACT_LE_32BITS(last_presentp) & BIT(IEEE80211_RADIOTAP_EXT)) != 0 &&
         (u_char *) (last_presentp + 1) <= linkchunk->data + 
		 EXTRACT_LE_16BITS(&(hdr->it_len)); last_presentp++);

    /* are there more bitmap extensions than bytes in header? */
    if ((EXTRACT_LE_32BITS(last_presentp) & BIT(IEEE80211_RADIOTAP_EXT)) != 0) {
		snprintf(errstr, STATUS_MAX, "pcap radiotap converter got corrupted "
				 "Radiotap bitmap length");
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return 0;
    }

	eight11chunk = new kis_datachunk;
	radioheader = new kis_layer1_packinfo;

	eight11chunk->dlt = KDLT_IEEE802_11;
	
    iter = (u_char*)(last_presentp + 1);

    for (bit0 = 0, presentp = &hdr->it_present; presentp <= last_presentp;
         presentp++, bit0 += 32) {
        for (present = EXTRACT_LE_32BITS(presentp); present; present = next_present) {
            /* clear the least significant bit that is set */
            next_present = present & (present - 1);

            /* extract the least significant bit that is set */
            bit = (enum ieee80211_radiotap_type)
                (bit0 + BITNO_32(present ^ next_present));

            switch (bit) {
                case IEEE80211_RADIOTAP_FLAGS:
                case IEEE80211_RADIOTAP_RATE:
				/*
                case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
                case IEEE80211_RADIOTAP_DB_ANTNOISE:
				*/
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
#if defined(SYS_OPENBSD)
                case IEEE80211_RADIOTAP_RSSI:
                    u.u8 = EXTRACT_LE_8BITS(iter);
                    iter += sizeof(u.u8);
                    u2.u8 = EXTRACT_LE_8BITS(iter);
                    iter += sizeof(u2.u8);
                    break;
#endif
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
                    // radioheader->channel = ieee80211_mhz2ieee(u.u16, u2.u16);
                    radioheader->freq_mhz = u.u16;
                    if (IEEE80211_IS_CHAN_FHSS(u2.u16))
                        radioheader->carrier = carrier_80211fhss;
                    else if (IEEE80211_IS_CHAN_A(u2.u16))
                        radioheader->carrier = carrier_80211a;
                    else if (IEEE80211_IS_CHAN_BPLUS(u2.u16))
                        radioheader->carrier = carrier_80211bplus;
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
                    if ((u2.u16 & IEEE80211_CHAN_CCK) == IEEE80211_CHAN_CCK)
                        radioheader->encoding = encoding_cck;
                    else if ((u2.u16 & IEEE80211_CHAN_OFDM) == IEEE80211_CHAN_OFDM)
                        radioheader->encoding = encoding_ofdm;
                    else if ((u2.u16 & IEEE80211_CHAN_DYN) == IEEE80211_CHAN_DYN)
                        radioheader->encoding = encoding_dynamiccck;
                    else if ((u2.u16 & IEEE80211_CHAN_GFSK) == IEEE80211_CHAN_GFSK)
                        radioheader->encoding = encoding_gfsk;
                    else
                        radioheader->encoding = encoding_unknown;
                    break;
                case IEEE80211_RADIOTAP_RATE:
					/* strip basic rate bit & convert to kismet units */
                    radioheader->datarate = ((u.u8 &~ 0x80) / 2) * 10;
                    break;
				/* ignore DB values, they're not helpful
                case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
                    radioheader->signal_dbm = u.i8;
                    break;
                case IEEE80211_RADIOTAP_DB_ANTNOISE:
                    radioheader->noise_dbm = u.i8;
                    break;
				*/
				case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
					radioheader->signal_dbm = u.i8;
					break;
				case IEEE80211_RADIOTAP_DBM_ANTNOISE:
					radioheader->noise_dbm = u.i8;
					break;
                case IEEE80211_RADIOTAP_FLAGS:
                    if (u.u8 & IEEE80211_RADIOTAP_F_FCS) {
						fcs_cut = 4;
					}
                    break;
#if defined(SYS_OPENBSD)
                case IEEE80211_RADIOTAP_RSSI:
                    /* Convert to Kismet units...  No reason to use RSSI units
					 * here since we know the conversion factor */
                    radioheader->signal_dbm = int((float(u.u8) / float(u2.u8) * 255));
                    break;
#endif
                default:
                    break;
            }
        }
    }

	if (EXTRACT_LE_16BITS(&(hdr->it_len)) + fcs_cut > (int) linkchunk->length) {
		/*
		_MSG("Pcap Radiotap converter got corrupted Radiotap frame, not "
			 "long enough for radiotap header plus indicated FCS", MSGFLAG_ERROR);
		*/
		delete eight11chunk;
		delete radioheader;
        return 0;
	}

	eight11chunk->length = linkchunk->length - 
		EXTRACT_LE_16BITS(&(hdr->it_len)) - fcs_cut;
	eight11chunk->data = new uint8_t[eight11chunk->length];
	memcpy(eight11chunk->data, linkchunk->data + 
		   EXTRACT_LE_16BITS(&(hdr->it_len)), eight11chunk->length);

	packet->insert(_PCM(PACK_COMP_RADIODATA), radioheader);
	packet->insert(_PCM(PACK_COMP_80211FRAME), eight11chunk);

	kis_fcs_bytes *fcschunk = NULL;
	if (fcs_cut && linkchunk->length > 4) {
		fcschunk = new kis_fcs_bytes;
		memcpy(fcschunk->fcs, &(linkchunk->data[linkchunk->length - 4]), 4);
		// Valid until proven otherwise
		fcschunk->fcsvalid = 1;

		packet->insert(_PCM(PACK_COMP_FCSBYTES), fcschunk);
	}

	// If we're validating the FCS
	if (validate_fcs && fcschunk != NULL) {
		// Compare it and flag the packet
		uint32_t calc_crc =
			crc32_le_80211(globalreg->crc32_table, eight11chunk->data, 
						   eight11chunk->length);

		if (memcmp(fcschunk->fcsp, &calc_crc, 4)) {
			packet->error = 1;
			fcschunk->fcsvalid = 0;
			// fprintf(stderr, "debug - rtap to kis, fcs invalid\n");
		} else {
			fcschunk->fcsvalid = 1;
		}

	}

    return 1;
}
#undef BITNO_32
#undef BITNO_16
#undef BITNO_8
#undef BITNO_4
#undef BITNO_2
#undef BIT

int PacketSource_Pcap::PPI2KisPack(kis_packet *packet, kis_datachunk *linkchunk) {
	ppi_packet_header *ppi_ph;
	ppi_field_header *ppi_fh;
	unsigned int ppi_fh_offt = sizeof(ppi_packet_header);
	unsigned int tuint, ph_len;
	int applyfcs = 0, fcsknownbad = 0;

	// Make a datachunk for the reformatted frame
	kis_datachunk *eight11chunk = NULL;
	kis_layer1_packinfo *radioheader = NULL;
	kis_gps_packinfo *gpsinfo = NULL;

	if (linkchunk->length < sizeof(ppi_packet_header)) {
		_MSG("pcap PPI converter got runt PPI frame", MSGFLAG_ERROR);
		return 0;
	}

	ppi_ph = (ppi_packet_header *) linkchunk->data;
	ph_len = kis_letoh16(ppi_ph->pph_len);
	if (ph_len > linkchunk->length) {
		_MSG("pcap PPI converter got invalid/runt PPI frame header", MSGFLAG_ERROR);
		return 0;
	}

	// Fix broken kismet dumps where kismet logged the wrong size (always
	// size 24) - if we're size 24, we have a PPI 11n common header, and
	// we can fit it all, then we adjust the header size up
	if (ph_len == 24 && linkchunk->length > 32) {
		ppi_fh = (ppi_field_header *) &(linkchunk->data[ppi_fh_offt]);
		if (kis_letoh16(ppi_fh->pfh_datatype) == PPI_FIELD_11COMMON) 
			ph_len = 32;
	}

	// Ignore the DLT and treat it all as 802.11... for now
	while (ppi_fh_offt < linkchunk->length &&
		   ppi_fh_offt < ph_len) {
		ppi_fh = (ppi_field_header *) &(linkchunk->data[ppi_fh_offt]);
		unsigned int fh_len = kis_letoh16(ppi_fh->pfh_datalen);
		unsigned int fh_type = kis_letoh16(ppi_fh->pfh_datatype);

		if (fh_len > linkchunk->length || fh_len > ph_len) {
			_MSG("pcap PPI converter got corrupt/invalid PPI field length",
				 MSGFLAG_ERROR);
			return 0;
		}

		ppi_fh_offt += fh_len + sizeof(ppi_field_header);

		if (fh_type == PPI_FIELD_11COMMON) {
			// printf("debug - 80211 common\n");
			ppi_80211_common *ppic = (ppi_80211_common *) ppi_fh;

			// Common flags
			tuint = kis_letoh16(ppic->flags);
			if ((tuint & PPI_80211_FLAG_INVALFCS) ||
				(tuint & PPI_80211_FLAG_PHYERROR)) {
				// Junk packets that are FCS or phy compromised
				return 0;
			}

			if (tuint & PPI_80211_FLAG_FCS) {
				applyfcs = 1;
			}

			if ((tuint & PPI_80211_FLAG_FCS) && (tuint & PPI_80211_FLAG_INVALFCS)) {
				applyfcs = 1;
				fcsknownbad = 1;
			}

			if (radioheader == NULL)
				radioheader = new kis_layer1_packinfo;

			// Channel flags
			tuint = kis_letoh16(ppic->chan_flags);
			if (tuint & PPI_80211_CHFLAG_CCK) 
				radioheader->encoding = encoding_cck;
			if (tuint & PPI_80211_CHFLAG_OFDM) 
				radioheader->encoding = encoding_ofdm;
			if (tuint & PPI_80211_CHFLAG_DYNAMICCCK) 
				radioheader->encoding = encoding_dynamiccck;
			if (tuint & PPI_80211_CHFLAG_GFSK) 
				radioheader->encoding = encoding_gfsk;
			if (tuint & PPI_80211_CHFLAG_TURBO)
				radioheader->carrier = carrier_80211bplus;
			if ((tuint & PPI_80211_CHFLAG_OFDM) &&
				(tuint & PPI_80211_CHFLAG_2GHZ))
				radioheader->carrier = carrier_80211g;
			if (tuint & PPI_80211_CHFLAG_5GHZ)
				radioheader->carrier = carrier_80211a;

			radioheader->signal_dbm = ppic->signal_dbm;
			radioheader->noise_dbm = ppic->noise_dbm;

			radioheader->datarate = kis_letoh16(ppic->rate) * 5;

			radioheader->freq_mhz = kis_letoh16(ppic->freq_mhz);
		} else if (fh_type == PPI_FIELD_11NMAC) {
			ppi_11n_mac *ppin = (ppi_11n_mac *) ppi_fh;

			if (radioheader == NULL)
				radioheader = new kis_layer1_packinfo;

			// Decode greenfield notation
			tuint = kis_letoh16(ppin->flags);
			if (tuint & PPI_11NMAC_HT2040)
				radioheader->carrier = carrier_80211n20;
			else
				radioheader->carrier = carrier_80211n40;

		} else if (fh_type == PPI_FIELD_11NMACPHY) {
			ppi_11n_macphy *ppinp = (ppi_11n_macphy *) ppi_fh;

			if (radioheader == NULL)
				radioheader = new kis_layer1_packinfo;

			// Decode greenfield notation
			tuint = kis_letoh16(ppinp->flags);
			if (tuint & PPI_11NMAC_HT2040)
				radioheader->carrier = carrier_80211n20;
			else
				radioheader->carrier = carrier_80211n40;
		} else if (fh_type == PPI_FIELD_GPS) {
			ppi_gps_hdr *ppigps = (ppi_gps_hdr *) ppi_fh;

			if (ppigps->version == 0) {
				unsigned int data_offt = 0;
				uint32_t fields_present = kis_letoh32(ppigps->fields_present);
				uint16_t gps_len = kis_letoh16(ppigps->gps_len) - sizeof(ppi_gps_hdr);

				union block {
					uint8_t u8;
					uint16_t u16;
					uint32_t u32;
					uint64_t u64;
				} *u;

				// printf("debug - gps present, %u len %d %d %d %d\n", fields_present, gps_len, fields_present & PPI_GPS_FLAG_LAT, fields_present & PPI_GPS_FLAG_LON, fields_present & PPI_GPS_FLAG_ALT);

				if ((fields_present & PPI_GPS_FLAG_LAT) &&
					(fields_present & PPI_GPS_FLAG_LON) &&
					gps_len - data_offt >= 8) {

					if (gpsinfo == NULL)
						gpsinfo = new kis_gps_packinfo;

					u = (block *) &(ppigps->field_data[data_offt]);
					gpsinfo->lat = fixed3_7_to_double(kis_letoh32(u->u32));
					data_offt += 4;

					u = (block *) &(ppigps->field_data[data_offt]);
					gpsinfo->lon = fixed3_7_to_double(kis_letoh32(u->u32));
					data_offt += 4;

					gpsinfo->gps_fix = 2;
					gpsinfo->alt = 0;
				}

                //Speed is stored as a velocity in VECTOR tags..
                /*
				if ((fields_present & PPI_GPS_FLAG_SPD) &&
					gps_len - data_offt >= 4) {

					u = (block *) &(ppigps->field_data[data_offt]);
					gpsinfo->spd = fixed3_7_to_double(kis_letoh32(u->u32));
					data_offt += 4;
				}
                */

				if ((fields_present & PPI_GPS_FLAG_ALT) && gps_len - data_offt >= 4) {
					gpsinfo->gps_fix = 3;

					u = (block *) &(ppigps->field_data[data_offt]);
					gpsinfo->alt = fixed6_4_to_double(kis_letoh32(u->u32));
					data_offt += 4;
				}

				packet->insert(_PCM(PACK_COMP_GPS), gpsinfo);
			}
		}
	}

	if (applyfcs)
		applyfcs = 4;

	eight11chunk = new kis_datachunk;

	eight11chunk->dlt = KDLT_IEEE802_11;

	// Subtract the packet FCS since kismet doesn't do anything terribly bright
	// with it right now, also subtract the avs header.  We have to obey the
	// header length here since avs could change
	eight11chunk->length = kismin((linkchunk->length - ph_len - applyfcs), 
								  (uint32_t) MAX_PACKET_LEN);

	eight11chunk->data = new uint8_t[eight11chunk->length];
    memcpy(eight11chunk->data, linkchunk->data + ph_len, eight11chunk->length);

	if (radioheader != NULL)
		packet->insert(_PCM(PACK_COMP_RADIODATA), radioheader);
	packet->insert(_PCM(PACK_COMP_80211FRAME), eight11chunk);

	kis_fcs_bytes *fcschunk = NULL;
	if (applyfcs && linkchunk->length > 4) {
		fcschunk = new kis_fcs_bytes;
		memcpy(fcschunk->fcs, &(linkchunk->data[linkchunk->length - 4]), 4);
	
		// Listen to the PPI file for known bad, regardless if we have validate
		// turned on or not
		if (fcsknownbad)
			fcschunk->fcsvalid = 0;
		else
			fcschunk->fcsvalid = 1;

		packet->insert(_PCM(PACK_COMP_FCSBYTES), fcschunk);
	}

	// If we're validating the FCS
	if (validate_fcs && fcschunk != NULL) {
		// Compare it and flag the packet
		uint32_t calc_crc =
			crc32_le_80211(globalreg->crc32_table, eight11chunk->data, 
						   eight11chunk->length);

		if (memcmp(fcschunk->fcsp, &calc_crc, 4)) {
			packet->error = 1;
			fcschunk->fcsvalid = 0;
			fprintf(stderr, "debug - rtap to kis, fcs invalid\n");
		} else {
			fcschunk->fcsvalid = 1;
		}
	}

    return 1;
}

int PacketSource_Pcap::FetchHardwareChannel() {
	return 0;
}

int PacketSource_Pcapfile::AutotypeProbe(string in_device) {
	// Autodetect as a pcapfile if it's a regular file in the fs
	
	struct stat sbuf;

	if (stat(in_device.c_str(), &sbuf) < 0)
		return 0;

	if (S_ISREG(sbuf.st_mode)) {
		type = "pcapfile";
		return 1;
	}

	return 0;
}

int PacketSource_Pcapfile::RegisterSources(Packetsourcetracker *tracker) {
	// Register the pcapfile source based off ourselves, nonroot, no channels
	tracker->RegisterPacketProto("pcapfile", this, "n/a", 0);
	return 1;
}

int PacketSource_Pcapfile::OpenSource() {
	last_channel = 0;
	char errstr[STATUS_MAX] = "";

	// Open the file offline and bounce out the error
	pd = pcap_open_offline(interface.c_str(), errstr);
	if (strlen(errstr) > 0) {
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		return 0;
	}

	paused = 0;

	num_packets = 0;

	if (DatalinkType() < 0)
		return -1;

	genericparms.weak_dissect = 1;
	
	return 1;
}

int PacketSource_Pcapfile::Poll() {
	int ret;

	ret = pcap_dispatch(pd, 1, PacketSource_Pcapfile::Pcap_Callback, NULL);

	if (ret < 0) {
		globalreg->messagebus->InjectMessage("Pcap failed to get the next packet",
											 MSGFLAG_ERROR);
		return 0;
	} else if (ret == 0) {
		globalreg->messagebus->InjectMessage("Pcap file reached end of capture",
											 MSGFLAG_ERROR);
		CloseSource();
		return 0;
	}

	if (paused)
		return 0;

	kis_packet *newpack = globalreg->packetchain->GeneratePacket();

	// Get the timestamp from the pcap callback
	newpack->ts.tv_sec = callback_header.ts.tv_sec;
	newpack->ts.tv_usec = callback_header.ts.tv_usec;

	// Add the link-layer raw data to the packet, for the pristine copy
	kis_datachunk *linkchunk = new kis_datachunk;
	linkchunk->dlt = datalink_type;
	linkchunk->source_id = source_id;
	linkchunk->data = 
		new uint8_t[kismin(callback_header.caplen, (uint32_t) MAX_PACKET_LEN)];
	linkchunk->length = kismin(callback_header.caplen, (uint32_t) MAX_PACKET_LEN);
	memcpy(linkchunk->data, callback_data, linkchunk->length);
	newpack->insert(_PCM(PACK_COMP_LINKFRAME), linkchunk);

	// Only decode the DLT if we're asked to
	if (dlt_mangle && ManglePacket(newpack, linkchunk) < 0)
		return 0;

	num_packets++;

	// Flag the header
	kis_ref_capsource *csrc_ref = new kis_ref_capsource;
	csrc_ref->ref_source = this;
	newpack->insert(_PCM(PACK_COMP_KISCAPSRC), csrc_ref);

	globalreg->packetchain->ProcessPacket(newpack);

	return 1;
}

#endif

