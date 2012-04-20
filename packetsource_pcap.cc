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

#include "kis_dlt.h"
#include "kis_dlt_ppi.h"
#include "kis_dlt_prism2.h"
#include "kis_dlt_radiotap.h"

#include "phy_80211.h"
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

	if (strlen(errstr) > 0 || pd == NULL) {
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		return 0;
	}

	error = 0;
	
	paused = 0;
	errstr[0] = '\0';
	num_packets = 0;

#if 0
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
#endif

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

		if (pd != NULL)
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

	if (pd == NULL)
		return -1;

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

	linkchunk->set_data(callback_data, kismin(callback_header.caplen, 
											  (uint32_t) MAX_PACKET_LEN), true);
#if 0
	linkchunk->data = 
		new uint8_t[kismin(callback_header.caplen, (uint32_t) MAX_PACKET_LEN)];
	linkchunk->length = kismin(callback_header.caplen, (uint32_t) MAX_PACKET_LEN);
	memcpy(linkchunk->data, callback_data, linkchunk->length);
#endif

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

	if (linkchunk->dlt == DLT_IEEE802_11) {
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
	eight11chunk->set_data(linkchunk->data, kismin(linkchunk->length - fcsbytes,
												   (uint32_t) MAX_PACKET_LEN), false);

#if 0
	eight11chunk->length = kismin((linkchunk->length - fcsbytes), 
								  (uint32_t) MAX_PACKET_LEN);

	eight11chunk->data = new uint8_t[eight11chunk->length];
    memcpy(eight11chunk->data, linkchunk->data, eight11chunk->length);
#endif

	kis_packet_checksum *fcschunk = NULL;
	if (fcsbytes && linkchunk->length > 4) {
		fcschunk = new kis_packet_checksum;

		// memcpy(fcschunk->fcs, &(linkchunk->data[linkchunk->length - 4]), 4);

		fcschunk->set_data(&(linkchunk->data[linkchunk->length - 4]), 4);

		// Valid until proven otherwise
		fcschunk->checksum_valid = 1;

		packet->insert(_PCM(PACK_COMP_CHECKSUM), fcschunk);
	}


	// If we're validating the FCS
	if (validate_fcs && fcschunk != NULL) {
		// Compare it and flag the packet
		uint32_t calc_crc =
			crc32_le_80211(globalreg->crc32_table, eight11chunk->data, 
						   eight11chunk->length);

		if (memcmp(fcschunk->checksum_ptr, &calc_crc, 4)) {
			packet->error = 1;
			fcschunk->checksum_valid = 0;
			//fprintf(stderr, "debug - dot11 to kis, fcs invalid\n");
		} else {
			fcschunk->checksum_valid = 1;
		}
	}

	packet->insert(_PCM(PACK_COMP_DECAP), eight11chunk);

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

