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

#ifndef __PPI_H__
#define __PPI_H__

#include "config.h"

/* PPI flexible-header packet format */

#ifndef DLT_PPI
#define DLT_PPI						192 /* cace PPI */
#endif

// CACE PPI headers
typedef struct {
	uint8_t pph_version;
	uint8_t pph_flags;
	uint16_t pph_len;
	uint32_t pph_dlt;
} __attribute__((packed)) ppi_packet_header;

#define PPI_PH_FLAG_ALIGNED		2

typedef struct {
	uint16_t pfh_datatype;
	uint16_t pfh_datalen;
} __attribute__((packed)) ppi_field_header;

#define PPI_FIELD_11COMMON		2
#define PPI_FIELD_11NMAC		3
#define PPI_FIELD_11NMACPHY		4
#define PPI_FIELD_SPECMAP		5
#define PPI_FIELD_PROCINFO		6
#define PPI_FIELD_CAPINFO		7
#define PPI_FIELD_GPS			30002

typedef struct {
	uint16_t pfh_datatype;
	uint16_t pfh_datalen;
	uint64_t tsf_timer;
	uint16_t flags;
	uint16_t rate;
	uint16_t freq_mhz;
	uint16_t chan_flags;
	uint8_t fhss_hopset;
	uint8_t fhss_pattern;
	int8_t signal_dbm;
	int8_t noise_dbm;
} __attribute__((packed)) ppi_80211_common;

typedef struct {
	uint16_t pfh_datatype;
	uint16_t pfh_datalen;
	uint8_t version;
	uint8_t magic;
	uint16_t gps_len;
	uint32_t fields_present;
	uint8_t field_data[0];
} __attribute__((packed)) ppi_gps_hdr;

#define PPI_GPS_MAGIC				0xCF

#define PPI_GPS_FLAG_LON			2
#define PPI_GPS_FLAG_LAT			4
#define PPI_GPS_FLAG_ALT			8
#define PPI_GPS_FLAG_ALT_G			16
#define PPI_GPS_FLAG_GPSTIME		32
#define PPI_GPS_FLAG_FRACTIME		64
#define PPI_GPS_FLAG_EPH	        128
#define PPI_GPS_FLAG_EPV	        256
#define PPI_GPS_FLAG_EPT	        512
#define PPI_GPS_FLAG_APPID	        536870912
#define PPI_GPS_FLAG_DATA	        1073741824


#define PPI_80211_FLAG_FCS			1
#define PPI_80211_FLAG_TSFMS		2
#define PPI_80211_FLAG_INVALFCS		4
#define PPI_80211_FLAG_PHYERROR		8

#define PPI_80211_CHFLAG_TURBO 		16
#define PPI_80211_CHFLAG_CCK		32
#define PPI_80211_CHFLAG_OFDM		64
#define PPI_80211_CHFLAG_2GHZ		128
#define PPI_80211_CHFLAG_5GHZ		256
#define PPI_80211_CHFLAG_PASSIVE	512
#define PPI_80211_CHFLAG_DYNAMICCCK	1024
#define PPI_80211_CHFLAG_GFSK		2048

typedef struct {
	uint16_t pfh_datatype;
	uint16_t pfh_datalen;
	uint32_t flags;
	uint32_t a_mpdu_id;
	uint8_t num_delimiters;
	uint8_t reserved[3];
} __attribute__((packed)) ppi_11n_mac;

#define PPI_11NMAC_GREENFIELD		1
#define PPI_11NMAC_HT2040			2
#define PPI_11NMAC_RX_SGI			4
#define PPI_11NMAC_DUPERX			8
#define PPI_11NMAC_AGGREGATE		16
#define PPI_11NMAC_MOREAGGREGATE	32
#define PPI_11NMAC_AGGCRC			64

typedef struct {
	uint16_t pfh_datatype;
	uint16_t pfh_datalen;
	uint32_t flags;
	uint32_t a_mpdu_id;
	uint8_t num_delimiters;
	uint8_t mcs;
	uint8_t num_streams;
	uint8_t combined_rssi;
	uint8_t ant0_ctl_rssi;
	uint8_t ant1_ctl_rssi;
	uint8_t ant2_ctl_rssi;
	uint8_t ant3_ctl_rssi;
	uint8_t ant0_ext_rssi;
	uint8_t ant1_ext_rssi;
	uint8_t ant2_ext_rssi;
	uint8_t ant3_ext_rssi;
	uint16_t extension_freq_mhz;
	uint16_t extension_flags;
	int8_t ant0_signal_dbm;
	int8_t ant0_noise_dbm;
	int8_t ant1_signal_dbm;
	int8_t ant1_noise_dbm;
	int8_t ant2_signal_dbm;
	int8_t ant2_noise_dbm;
	int8_t ant3_signal_dbm;
	int8_t ant3_noise_dbm;
	uint32_t evm0;
	uint32_t evm1;
	uint32_t evm2;
	uint32_t evm3;
} __attribute__((packed)) ppi_11n_macphy;

#endif

