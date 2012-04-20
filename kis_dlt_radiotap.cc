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

#if defined(SYS_OPENBSD) || defined(SYS_NETBSD)
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_radiotap.h>
#endif // Open/Net

#ifdef SYS_FREEBSD
#include <net80211/ieee80211_radiotap.h>
#endif // FreeBSD

// Include the linux system radiotap headers
#ifdef HAVE_LINUX_SYS_RADIOTAP
#include <net/ieee80211_radiotap.h>
#endif

// If we couldn't make any sense of system rt headers (OSX perhaps, or
// win32, or an older linux) then pull in the local radiotap copy
#ifdef HAVE_LOCAL_RADIOTAP
#include "local_ieee80211_radiotap.h"
#endif

#include "kis_dlt_radiotap.h"

#include "tcpdump-extract.h"

// Extension to radiotap header not yet included in all BSD's
#ifndef IEEE80211_RADIOTAP_F_FCS
#define IEEE80211_RADIOTAP_F_FCS        0x10    /* frame includes FCS */
#endif

Kis_DLT_Radiotap::Kis_DLT_Radiotap(GlobalRegistry *in_globalreg) :
	Kis_DLT_Handler(in_globalreg) {

	dlt_name = "Radiotap";
	dlt = DLT_IEEE802_11_RADIO;

	globalreg->InsertGlobal("DLT_RADIOTAP", this);

	_MSG("Registering support for DLT_RADIOTAP packet header decoding", MSGFLAG_INFO);
}

Kis_DLT_Radiotap::~Kis_DLT_Radiotap() {
	globalreg->InsertGlobal("DLT_RADIOTAP", NULL);
}

#define ALIGN_OFFSET(offset, width) \
	    ( (((offset) + ((width) - 1)) & (~((width) - 1))) - offset )

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
int Kis_DLT_Radiotap::HandlePacket(kis_packet *in_pack) {
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

	u2.u64 = 0;

	struct ieee80211_radiotap_header *hdr;
	u_int32_t present, next_present;
	u_int32_t *presentp, *last_presentp;
	enum ieee80211_radiotap_type bit;
	int bit0;
	const u_char *iter;
	const u_char *iter_start;
	unsigned int iter_align;
	int fcs_cut = 0; // Is the FCS bit set?
	char errstr[STATUS_MAX];

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

	decapchunk = new kis_datachunk;
	radioheader = new kis_layer1_packinfo;

	decapchunk->dlt = KDLT_IEEE802_11;
	
    iter_start = iter = (u_char*)(last_presentp + 1);

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
					iter_align = ALIGN_OFFSET((unsigned int) (iter - iter_start), 2);
					iter += iter_align;

                    u.u16 = EXTRACT_LE_16BITS(iter);
                    iter += sizeof(u.u16);
                    u2.u16 = EXTRACT_LE_16BITS(iter);
                    iter += sizeof(u2.u16);
                    break;
                case IEEE80211_RADIOTAP_FHSS:
                case IEEE80211_RADIOTAP_LOCK_QUALITY:
                case IEEE80211_RADIOTAP_TX_ATTENUATION:
                case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
					iter_align = ALIGN_OFFSET((unsigned int) (iter - iter_start), 2);
					iter += iter_align;

                    u.u16 = EXTRACT_LE_16BITS(iter);
                    iter += sizeof(u.u16);
                    break;
                case IEEE80211_RADIOTAP_TSFT:
					iter_align = ALIGN_OFFSET((unsigned int) (iter - iter_start), 8);
					iter += iter_align;

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

			// static int pnum = 0;
            switch (bit) {
                case IEEE80211_RADIOTAP_CHANNEL:
                    // radioheader->channel = ieee80211_mhz2ieee(u.u16, u2.u16);
                    radioheader->freq_mhz = u.u16;
					// printf("debug - %d freq %u\n", pnum++, radioheader->freq_mhz);
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
		delete decapchunk;
		delete radioheader;
        return 0;
	}

#if 0
	decapchunk->length = linkchunk->length - 
		EXTRACT_LE_16BITS(&(hdr->it_len)) - fcs_cut;
	decapchunk->data = new uint8_t[decapchunk->length];
	memcpy(decapchunk->data, linkchunk->data + 
		   EXTRACT_LE_16BITS(&(hdr->it_len)), decapchunk->length);
#endif
	decapchunk->set_data(linkchunk->data + EXTRACT_LE_16BITS(&(hdr->it_len)),
						 (linkchunk->length - EXTRACT_LE_16BITS(&(hdr->it_len)) - 
						  fcs_cut), false);

	in_pack->insert(pack_comp_radiodata, radioheader);
	in_pack->insert(pack_comp_decap, decapchunk);

	kis_packet_checksum *fcschunk = NULL;
	if (fcs_cut && linkchunk->length > 4) {
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
#undef BITNO_32
#undef BITNO_16
#undef BITNO_8
#undef BITNO_4
#undef BITNO_2
#undef BIT


