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

#include "kis_dlt_ppi.h"
#include "kis_ppi.h"

#include "gpscore.h"

Kis_DLT_PPI::Kis_DLT_PPI(GlobalRegistry *in_globalreg) :
	Kis_DLT_Handler(in_globalreg) {

	dlt_name = "PPI";
	dlt = DLT_PPI;

	globalreg->InsertGlobal("DLT_PPI", this);

	_MSG("Registering support for DLT_PPI packet header decoding", MSGFLAG_INFO);
}

Kis_DLT_PPI::~Kis_DLT_PPI() {
	globalreg->InsertGlobal("DLT_PPI", NULL);
}

int Kis_DLT_PPI::HandlePacket(kis_packet *in_pack) {
	kis_datachunk *decapchunk = 
		(kis_datachunk *) in_pack->fetch(pack_comp_decap);

	if (decapchunk != NULL) {
		// printf("debug - dltppi frame already decapped\n");
		return 1;
	}

	kis_datachunk *linkchunk = 
		(kis_datachunk *) in_pack->fetch(pack_comp_linkframe);

	if (linkchunk == NULL) {
		// printf("debug - dltppi no link\n");
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

	ppi_packet_header *ppi_ph;
	ppi_field_header *ppi_fh;
	unsigned int ppi_fh_offt = sizeof(ppi_packet_header);
	unsigned int tuint, ph_len;
	unsigned int ppi_dlt = -1;
	int applyfcs = 0, fcsknownbad = 0;

	// Make a datachunk for the reformatted frame
	kis_layer1_packinfo *radioheader = NULL;
	kis_gps_packinfo *gpsinfo = NULL;

	if (linkchunk->length < sizeof(ppi_packet_header)) {
		_MSG("pcap PPI converter got runt PPI frame", MSGFLAG_ERROR);
		return 0;
	}

	ppi_ph = (ppi_packet_header *) linkchunk->data;
	ph_len = kis_letoh16(ppi_ph->pph_len);
	ppi_dlt = kis_letoh32(ppi_ph->pph_dlt);
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

				in_pack->insert(pack_comp_gps, gpsinfo);
			}
		}
	}

	if (applyfcs)
		applyfcs = 4;

	decapchunk = new kis_datachunk;

	decapchunk->dlt = ppi_dlt;

	// Alias the decapsulated data
	decapchunk->set_data(linkchunk->data + ph_len, 
						 kismin((linkchunk->length - ph_len - applyfcs), 
								(uint32_t) MAX_PACKET_LEN),
						 false);

	if (radioheader != NULL)
		in_pack->insert(pack_comp_radiodata, radioheader);
	in_pack->insert(pack_comp_decap, decapchunk);

	kis_packet_checksum *fcschunk = NULL;
	if (applyfcs && linkchunk->length > 4) {
		fcschunk = new kis_packet_checksum;

		fcschunk->set_data(&(linkchunk->data[linkchunk->length - 4]), 4);
	
		// Listen to the PPI file for known bad, regardless if we have validate
		// turned on or not
		if (fcsknownbad)
			fcschunk->checksum_valid = 0;
		else
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
		} else {
			fcschunk->checksum_valid = 1;
		}
	}


	return 1;
}


