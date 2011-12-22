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

/* DLT handler framework */

#include "config.h"

#include "globalregistry.h"
#include "util.h"
#include "endian_magic.h"
#include "messagebus.h"
#include "packet.h"
#include "packetchain.h"
#include "packetsource.h"
#include "gpscore.h"

#include "kis_dlt_prism2.h"

#define WLAN_DEVNAMELEN_MAX	16

// Prism 802.11 headers from wlan-ng tacked on to the beginning of a
// pcap packet... Snagged from the wlan-ng source
typedef struct {
	uint32_t did;
	uint16_t status;
	uint16_t len;
	uint32_t data;
} __attribute__((__packed__)) p80211item_uint32_t;

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
} __attribute__((__packed__)) wlan_ng_prism2_header;

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

Kis_DLT_Prism2::Kis_DLT_Prism2(GlobalRegistry *in_globalreg) :
	Kis_DLT_Handler(in_globalreg) {

	dlt_name = "Prism2";
	dlt = DLT_PRISM_HEADER;

	globalreg->InsertGlobal("DLT_PRISM2", this);

	_MSG("Registering support for DLT_Prism2 packet header decoding", MSGFLAG_INFO);
}

Kis_DLT_Prism2::~Kis_DLT_Prism2() {
	globalreg->InsertGlobal("DLT_Prism2", NULL);
}

int Kis_DLT_Prism2::HandlePacket(kis_packet *in_pack) {
	kis_datachunk *decapchunk = 
		(kis_datachunk *) in_pack->fetch(pack_comp_decap);

	if (decapchunk != NULL) {
		// printf("debug - dltPrism2 frame already decapped\n");
		return 1;
	}

	kis_datachunk *linkchunk = 
		(kis_datachunk *) in_pack->fetch(pack_comp_linkframe);

	if (linkchunk == NULL) {
		// printf("debug - dltPrism2 no link\n");
		return 1;
	}

	if (linkchunk->dlt != dlt) {
		return 1;
	}

	kis_ref_capsource *capsrc =
		(kis_ref_capsource *) in_pack->fetch(pack_comp_capsrc);

	if (capsrc == NULL) {
		// printf("debug - no capsrc?\n");
		return 1;
	}

    int callback_offset = 0;
    char errstr[STATUS_MAX] = "";

	// Make a datachunk for the reformatted frame
	kis_layer1_packinfo *radioheader = NULL;

	int fcsbytes = capsrc->ref_source->FetchFCSBytes();

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

		decapchunk = new kis_datachunk;
		radioheader = new kis_layer1_packinfo;

		decapchunk->dlt = KDLT_IEEE802_11;

        // Subtract the packet FCS since kismet doesn't do anything terribly bright
        // with it right now, also subtract the avs header.  We have to obey the
		// header length here since avs could change
		decapchunk->length = kismin((linkchunk->length - ntohl(v1hdr->length) -
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

		decapchunk = new kis_datachunk;
		radioheader = new kis_layer1_packinfo;

		decapchunk->dlt = KDLT_IEEE802_11;

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
		decapchunk->length = kismin((linkchunk->length - 
									   sizeof(wlan_ng_prism2_header) - fcsbytes),
									  (uint32_t) MAX_PACKET_LEN);

#if 0
        decapchunk->length = kismin((p2head->frmlen.data - fcsbytes), 
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

	decapchunk->data = new uint8_t[decapchunk->length];
    memcpy(decapchunk->data, linkchunk->data + callback_offset, decapchunk->length);

	in_pack->insert(pack_comp_radiodata, radioheader);
	in_pack->insert(pack_comp_decap, decapchunk);

	kis_packet_checksum *fcschunk = NULL;
	if (fcsbytes && linkchunk->length > 4) {
		fcschunk = new kis_packet_checksum;

		fcschunk->set_data(&(linkchunk->data[linkchunk->length - 4]), 4);
		// Valid until proven otherwise
		fcschunk->checksum_valid = 1;

		in_pack->insert(pack_comp_checksum, fcschunk);
	}

	// If we're validating the FCS
	if (capsrc->ref_source->FetchValidateCRC() && fcschunk != NULL) {
		// Compare it and flag the packet
		uint32_t calc_crc =
			crc32_le_80211(globalreg->crc32_table, decapchunk->data, 
						   decapchunk->length);

		if (memcmp(fcschunk->checksum_ptr, &calc_crc, 4)) {
			in_pack->error = 1;
			fcschunk->checksum_valid = 0;
			// fprintf(stderr, "debug - rtap to kis, fcs invalid\n");
		} else {
			fcschunk->checksum_valid = 1;
		}
	}


	return 1;
}


