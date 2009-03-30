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

#ifdef HAVE_LIBPCAP

#include <errno.h>

#include "endian_magic.h"
#include "dumpfile_pcap.h"
#include "packetsource_pcap.h"
#include "spectool_netclient.h"

int dumpfilepcap_chain_hook(CHAINCALL_PARMS) {
	Dumpfile_Pcap *auxptr = (Dumpfile_Pcap *) auxdata;
	return auxptr->chain_handler(in_pack);
}

Dumpfile_Pcap::Dumpfile_Pcap() {
	fprintf(stderr, "FATAL OOPS: Dumpfile_Pcap called with no globalreg\n");
	exit(1);
}

Dumpfile_Pcap::Dumpfile_Pcap(GlobalRegistry *in_globalreg) : Dumpfile(in_globalreg) {
	char errstr[STATUS_MAX] = "";
	globalreg = in_globalreg;

	dumpfile = NULL;
	dumper = NULL;

	type = "pcapdump";

	int dlt = DLT_IEEE802_11;

	if (globalreg->sourcetracker == NULL) {
		fprintf(stderr, "FATAL OOPS:  Sourcetracker missing before Dumpfile_Pcap\n");
		exit(1);
	}

	// Process a resume request
	dumpformat = dump_unknown;

	// continue processing if we're not resuming
	if (globalreg->kismet_config->FetchOpt("pcapdumpformat") == "ppi") {
#ifndef HAVE_PPI
		_MSG("Cannot log in PPI format, the libpcap available when Kismet was "
			 "compiled did not support PPI, defaulting to 802.11 format.",
			 MSGFLAG_ERROR);
		dlt = DLT_IEEE802_11;
#else
		_MSG("Pcap log in PPI format", MSGFLAG_INFO);
		dumpformat = dump_ppi;
		dlt = DLT_PPI;
#endif
	} else if (globalreg->kismet_config->FetchOpt("pcapdumpformat") == "80211") {
		_MSG("Pcap log in 80211 format", MSGFLAG_INFO);
		dumpformat = dump_80211;
		dlt = DLT_IEEE802_11;
	} else {
		_MSG("Pcap log defaulting to 80211 format", MSGFLAG_INFO);
		dumpformat = dump_80211;
		dlt = DLT_IEEE802_11;
	}

	// Find the file name
	if ((fname = ProcessConfigOpt("pcapdump")) == "" || 
		globalreg->fatal_condition) {
		return;
	}

	dumpfile = pcap_open_dead(dlt, MAX_PACKET_LEN);
	if (dumpfile == NULL) {
		snprintf(errstr, STATUS_MAX, "Failed to open pcap dump file '%s': %s",
				 fname.c_str(), strerror(errno));
		_MSG(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	dumper = pcap_dump_open(dumpfile, fname.c_str());
	if (dumper == NULL) {
		snprintf(errstr, STATUS_MAX, "Failed to open pcap dump file '%s': %s",
				 fname.c_str(), strerror(errno));
		_MSG(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	_MSG("Opened pcapdump log file '" + fname + "'", MSGFLAG_INFO);

	if (globalreg->kismet_config->FetchOpt("beaconlog") == "true") {
		_MSG("Pcap log saving all beacon frames", MSGFLAG_INFO);
		beaconlog = 1;
	} else {
		_MSG("Pcap log saving only first and different beacon frames",
			 MSGFLAG_INFO);
		beaconlog = 0;
	} 

	if (globalreg->kismet_config->FetchOpt("phylog") == "true") {
		_MSG("Pcap log saving PHY frame types", MSGFLAG_INFO);
		phylog = 1;
	} else {
		_MSG("Pcap log file not saving PHY frame types", MSGFLAG_INFO);
		phylog = 0;
	}

	if (globalreg->kismet_config->FetchOpt("corruptlog") == "true") {
		_MSG("Pcap log saving corrupt frames", MSGFLAG_INFO);
		corruptlog = 1;
	} else {
		_MSG("Pcap log not saving corrupt frames", MSGFLAG_INFO);
		corruptlog = 0;
	}

	globalreg->packetchain->RegisterHandler(&dumpfilepcap_chain_hook, this,
											CHAINPOS_LOGGING, -100);

	globalreg->RegisterDumpFile(this);
}

Dumpfile_Pcap::~Dumpfile_Pcap() {
	int opened = 0;

	globalreg->packetchain->RemoveHandler(&dumpfilepcap_chain_hook, 
										  CHAINPOS_LOGGING);

	// Close files
	if (dumper != NULL) {
		Flush();
		pcap_dump_flush(dumper);
		pcap_dump_close(dumper);
		opened = 1;
	}

	if (dumpfile != NULL) {
		pcap_close(dumpfile);
	}

	dumper = NULL;
	dumpfile = NULL;

	if (opened) 
		_MSG("Closed pcapdump log file '" + fname + "'", MSGFLAG_INFO);
}

int Dumpfile_Pcap::Flush() {
	if (dumper == NULL || dumpfile == NULL)
		return 0;

	pcap_dump_flush(dumper);

	return 1;
}

int Dumpfile_Pcap::chain_handler(kis_packet *in_pack) {
	// Grab the mangled frame if we have it, then try to grab up the list of
	// data types and die if we can't get anything
	kis_ieee80211_packinfo *packinfo =
		(kis_ieee80211_packinfo *) in_pack->fetch(_PCM(PACK_COMP_80211));

	kis_datachunk *chunk = 
		(kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_MANGLEFRAME));

	kis_layer1_packinfo *radioinfo =
		(kis_layer1_packinfo *) in_pack->fetch(_PCM(PACK_COMP_RADIODATA));

	kis_spectrum_data *specdata =
		(kis_spectrum_data *) in_pack->fetch(_PCM(PACK_COMP_SPECTRUM));

	kis_gps_packinfo *gpsdata =
		(kis_gps_packinfo *) in_pack->fetch(_PCM(PACK_COMP_GPS));

	if (chunk == NULL) {
		if ((chunk = 
			 (kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_80211FRAME))) == NULL) {

			chunk = 
				(kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_LINKFRAME));
		}
	}

	if (chunk != NULL && (chunk->length < 0 || chunk->length > MAX_PACKET_LEN)) {
		_MSG("Weird frame in pcap logger with the wrong size...", MSGFLAG_ERROR);
		return 0;
	}

	if (packinfo != NULL) {
		if (phylog == 0 && packinfo->type == packet_phy)
			return 0;

		if (corruptlog == 0 && packinfo->corrupt)
			return 0;

		if (beaconlog == 0 && packinfo->type == packet_management &&
			packinfo->subtype == packet_sub_beacon) {
			macmap<uint32_t>::iterator bcmi =
				bssid_csum_map.find(packinfo->bssid_mac);

			if (bcmi != bssid_csum_map.end() &&
				*(bcmi->second) == packinfo->ssid_csum) {
				return 0;
			}

			bssid_csum_map.insert(packinfo->bssid_mac, packinfo->ssid_csum);
		}
	}

	unsigned int dump_len = 0;
	if (chunk != NULL)
		dump_len += chunk->length;

	u_char *dump_data = NULL;

	// Assemble the full packet
	if (dumpformat == dump_ppi) {
		ppi_packet_header *ppi_ph;
		unsigned int ppi_len = sizeof(ppi_packet_header);
		unsigned int ppi_pos = sizeof(ppi_packet_header);

		if (radioinfo != NULL) 
			ppi_len += sizeof(ppi_80211_common);
		if (specdata != NULL)
			ppi_len += sizeof(ppi_spectrum) + specdata->rssi_vec.size();
#if 0
		if (gpsdata != NULL && gpsdata->gps_fix >= 2)
			ppi_len += sizeof(ppi_gps);
#endif

		dump_len += ppi_len;

		dump_data = new u_char[dump_len];

		ppi_ph = (ppi_packet_header *) dump_data;

		ppi_ph->pph_version = 0;
		ppi_ph->pph_flags = 0;
		ppi_ph->pph_len = kis_htole16(ppi_len);

		// Hardcode 80211 DLT for now
		ppi_ph->pph_dlt = kis_htole32(105);

		if (specdata != NULL) {
			ppi_spectrum *ppi_spec;
			ppi_spec = (ppi_spectrum *) &(dump_data[ppi_pos]);
			ppi_pos += sizeof(ppi_spectrum) + specdata->rssi_vec.size();

			ppi_spec->pfh_datatype = kis_htole16(PPI_FIELD_SPECMAP);
			ppi_spec->pfh_datalen = kis_htole16(sizeof(ppi_spectrum) -
												sizeof(ppi_field_header) +
												specdata->rssi_vec.size());

			ppi_spec->start_khz = kis_htole32(specdata->start_khz);
			ppi_spec->res_hz = kis_htole32(specdata->res_hz);
			ppi_spec->amp_offset_mdbm = kis_htole32(abs(specdata->amp_offset_mdbm));
			ppi_spec->amp_res_mdbm = kis_htole32(specdata->amp_res_mdbm);
			ppi_spec->rssi_max = kis_htole16(specdata->rssi_max);
			ppi_spec->num_samples = kis_htole16(specdata->rssi_vec.size());
			for (unsigned int s = 0; s < specdata->rssi_vec.size(); s++) 
				ppi_spec->data[s] = specdata->rssi_vec[s];
		}

		if (radioinfo != NULL) {
			ppi_80211_common *ppi_common;
			ppi_common = (ppi_80211_common *) &(dump_data[ppi_pos]);
			ppi_pos += sizeof(ppi_80211_common);

			ppi_common->pfh_datatype = kis_htole16(PPI_FIELD_11COMMON);
			ppi_common->pfh_datalen = kis_htole16(sizeof(ppi_80211_common) -
												  sizeof(ppi_field_header));

			if (packinfo != NULL) 
				ppi_common->tsf_timer = kis_htole64(packinfo->timestamp);
			else
				ppi_common->tsf_timer = 0;

			// Assemble the flags in host mode then convert them all at once
			ppi_common->flags = 0;
			if (packinfo != NULL && packinfo->corrupt)
				ppi_common->flags |= PPI_80211_FLAG_PHYERROR;
			ppi_common->flags = kis_htole16(ppi_common->flags);

			ppi_common->rate = kis_htole16(radioinfo->datarate / 5);
			ppi_common->freq_mhz = kis_htole16(radioinfo->freq_mhz);

			// Assemble the channel flags then endian swap them
			ppi_common->chan_flags = 0;
			if (radioinfo->encoding == encoding_cck)
				ppi_common->chan_flags |= PPI_80211_CHFLAG_CCK;
			if (radioinfo->encoding == encoding_ofdm)
				ppi_common->chan_flags |= PPI_80211_CHFLAG_OFDM;
			if (radioinfo->encoding == encoding_dynamiccck)
				ppi_common->chan_flags |= PPI_80211_CHFLAG_DYNAMICCCK;
			if (radioinfo->encoding == encoding_gfsk)
				ppi_common->chan_flags |= PPI_80211_CHFLAG_GFSK;
			if (radioinfo->carrier == carrier_80211bplus)
				ppi_common->chan_flags |= PPI_80211_CHFLAG_TURBO;
			if (radioinfo->carrier == carrier_80211g)
				ppi_common->chan_flags |= (PPI_80211_CHFLAG_OFDM |
										   PPI_80211_CHFLAG_2GHZ);
			if (radioinfo->carrier == carrier_80211a)
				ppi_common->chan_flags |= PPI_80211_CHFLAG_5GHZ;
			ppi_common->chan_flags = kis_htole16(ppi_common->chan_flags);

			ppi_common->fhss_hopset = 0;
			ppi_common->fhss_pattern = 0;

			ppi_common->signal_dbm = radioinfo->signal_dbm;
			ppi_common->noise_dbm = radioinfo->noise_dbm;
		}

#if 0
		if (gpsdata != NULL && gpsdata->gps_fix >= 2) {
			ppi_gps *ppigps;
			ppigps = (ppi_gps *) &(dump_data[ppi_pos]);
			ppi_pos += sizeof(ppi_gps);

			ppigps->pfh_datatype = kis_htole16(PPI_FIELD_GPS);
			ppigps->pfh_datalen = kis_htole16(sizeof(ppi_gps) -
											  sizeof(ppi_field_header));

			ppigps->versio = 0;
			ppigps->pad = 0;
			// ??
			ppigps->gps_len = ppigps->pfh_datalen;

			ppigps->fields_present = PPI_GPS_FLAG_LAT | PPI_GPS_FLAG_LON;
		}
#endif

	}

	if (dump_data == NULL)
		dump_data = new u_char[dump_len];

	// copy the packet content in, offset if necessary
	if (chunk != NULL)
		memcpy(&(dump_data[dump_len - chunk->length]), chunk->data, chunk->length);

	// Fake a header
	struct pcap_pkthdr wh;
	wh.ts.tv_sec = in_pack->ts.tv_sec;
	wh.ts.tv_usec = in_pack->ts.tv_usec;
	wh.caplen = wh.len = dump_len;

	// Dump it
	pcap_dump((u_char *) dumper, &wh, dump_data);

	delete[] dump_data;

	// fprintf(stderr, "%d %d\n", wh.caplen, dumped_frames);

	dumped_frames++;

	return 1;
}

#endif /* have_libpcap */

