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
		ret = Radiotap2KisPack(packet, data, moddata);
#endif
	}

	// We don't have to do anything else now other than add the signal headers.
	// If the packet only has a LINKFRAME then we can try to use it in place of
	// an 80211FRAME elsewhere in the packet decoders (note to self and others:
	// packet decoders need to process LINKFRAME if no 80211FRAME)
	
	if (ret < 0)
		return ret;

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

	if (paused || ManglePacket(newpack) == 0) {
		return 0;
	}

	num_packets++;

	kis_ref_capsource *csrc_ref = new kis_ref_capsource;
	csrc_ref->ref_source = this;
	newpack->insert(_PCM(PACK_COMP_KISCAPSRC), csrc_ref);

	globalreg->packetchain->ProcessPacket(newpack);

	return 1;
}

#endif

