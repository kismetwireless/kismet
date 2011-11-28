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

#include <errno.h>

#include "globalregistry.h"
#include "alertracker.h"
#include "dumpfile_nettxt.h"
#include "packetsource.h"
#include "packetsourcetracker.h"
#include "netracker.h"

Dumpfile_Nettxt::Dumpfile_Nettxt() {
	fprintf(stderr, "FATAL OOPS: Dumpfile_Nettxt called with no globalreg\n");
	exit(1);
}

Dumpfile_Nettxt::Dumpfile_Nettxt(GlobalRegistry *in_globalreg) : 
	Dumpfile(in_globalreg) {
	globalreg = in_globalreg;

	txtfile = NULL;

	type = "nettxt";
	logclass = "text";

	if (globalreg->netracker == NULL) {
		_MSG("Deprecated netracker core disabled, disabling nettxt logfile.", 
			 MSGFLAG_INFO);
		// fprintf(stderr, "FATAL OOPS:  Netracker missing before Dumpfile_Nettxt\n");
		// exit(1);
		return;
	}

	if (globalreg->kismet_config == NULL) {
		fprintf(stderr, "FATAL OOPS:  Config file missing before Dumpfile_Nettxt\n");
		exit(1);
	}

	if (globalreg->alertracker == NULL) {
		fprintf(stderr, "FATAL OOPS:  Alertacker missing before dumpfile_nettxt\n");
		exit(1);
	}

	// Find the file name
	if ((fname = ProcessConfigOpt()) == "" ||
		globalreg->fatal_condition) {
		return;
	}

	if ((txtfile = fopen(fname.c_str(), "w")) == NULL) {
		_MSG("Failed to open nettxt log file '" + fname + "': " + strerror(errno),
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	globalreg->RegisterDumpFile(this);

	_MSG("Opened nettxt log file '" + fname + "'", MSGFLAG_INFO);

}

Dumpfile_Nettxt::~Dumpfile_Nettxt() {
	// Close files
	if (txtfile != NULL) {
		Flush();
	}

	txtfile = NULL;

	if (export_filter != NULL)
		delete export_filter;
}

int Dumpfile_Nettxt::Flush() {
	if (txtfile != NULL)
		fclose(txtfile);

	string tempname = fname + ".temp";
	if ((txtfile = fopen(tempname.c_str(), "w")) == NULL) {
		_MSG("Failed to open temporary nettxt file for writing: " +
			 string(strerror(errno)), MSGFLAG_ERROR);
		return -1;
	}
	
	fprintf(txtfile, "Kismet (http://www.kismetwireless.net)\n"
			"%.24s - Kismet %s.%s.%s\n"
			"-----------------\n\n",
			ctime(&(globalreg->start_time)),
			globalreg->version_major.c_str(),
			globalreg->version_minor.c_str(),
			globalreg->version_tiny.c_str());

	// Get the tracked network and client->ap maps
	const map<mac_addr, Netracker::tracked_network *> tracknet =
		globalreg->netracker->FetchTrackedNets();

	// Get the alerts
	const vector<kis_alert_info *> *alerts =
		globalreg->alertracker->FetchBacklog();

	map<mac_addr, Netracker::tracked_network *>::const_iterator x;
	map<mac_addr, Netracker::tracked_client *>::const_iterator y;

	int netnum = 0;

	// Dump all the networks
	for (x = tracknet.begin(); x != tracknet.end(); ++x) {
		netnum++;

		if (export_filter->RunFilter(x->second->bssid, mac_addr(0), mac_addr(0)))
			continue;

		Netracker::tracked_network *net = x->second;

		if (net->type == network_remove)
			continue;

		string ntype;
		switch (net->type) {
			case network_ap:
				ntype = "infrastructure";
				break;
			case network_adhoc:
				ntype = "ad-hoc";
				break;
			case network_probe:
				ntype = "probe";
				break;
			case network_data:
				ntype = "data";
				break;
			case network_turbocell:
				ntype = "turbocell";
				break;
			default:
				ntype = "unknown";
				break;
		}

		fprintf(txtfile, "Network %d: BSSID %s\n", netnum, 
				net->bssid.Mac2String().c_str());
		fprintf(txtfile, " Manuf      : %s\n", net->manuf.c_str());
		fprintf(txtfile, " First      : %.24s\n", ctime(&(net->first_time)));
		fprintf(txtfile, " Last       : %.24s\n", ctime(&(net->last_time)));
		fprintf(txtfile, " Type       : %s\n", ntype.c_str());
		fprintf(txtfile, " BSSID      : %s\n", net->bssid.Mac2String().c_str());

		int ssidnum = 1;
		for (map<uint32_t, Netracker::adv_ssid_data *>::iterator m =
			 net->ssid_map.begin(); m != net->ssid_map.end(); ++m) {
			string typestr;
			if (m->second->type == ssid_beacon)
				typestr = "Beacon";
			else if (m->second->type == ssid_proberesp)
				typestr = "Probe Response";
			else if (m->second->type == ssid_probereq)
				typestr = "Probe Request";
			else if (m->second->type == ssid_file)
				typestr = "Cached SSID";

			fprintf(txtfile, "   SSID %d\n", ssidnum);
			fprintf(txtfile, "    Type       : %s\n", typestr.c_str());
			fprintf(txtfile, "    SSID       : \"%s\" %s\n", m->second->ssid.c_str(),
					m->second->ssid_cloaked ? "(Cloaked)" : "");
			if (m->second->beacon_info.length() > 0)
				fprintf(txtfile, "    Info       : %s\n", 
						m->second->beacon_info.c_str());
			fprintf(txtfile, "    First      : %.24s\n", 
					ctime(&(m->second->first_time)));
			fprintf(txtfile, "    Last       : %.24s\n", 
					ctime(&(m->second->last_time)));
			fprintf(txtfile, "    Max Rate   : %2.1f\n", m->second->maxrate);
			if (m->second->beaconrate != 0) 
				fprintf(txtfile, "    Beacon     : %d\n", m->second->beaconrate);
			fprintf(txtfile, "    Packets    : %d\n", m->second->packets);

			if (m->second->dot11d_vec.size() > 0) {
				fprintf(txtfile, "    Country    : %s\n", 
						m->second->dot11d_country.c_str());
				for (unsigned int z = 0; z < m->second->dot11d_vec.size(); z++) {
					fprintf(txtfile, "     Chan Range: %u-%u %u dBm\n", 
							m->second->dot11d_vec[z].startchan,
							m->second->dot11d_vec[z].startchan + 
							m->second->dot11d_vec[z].numchan - 1,
							m->second->dot11d_vec[z].txpower);
				}
			}

			if (m->second->cryptset == 0)
				fprintf(txtfile, "    Encryption : None\n");
			if (m->second->cryptset == crypt_wep)
				fprintf(txtfile, "    Encryption : WEP\n");
			if (m->second->cryptset & crypt_layer3)
				fprintf(txtfile, "    Encryption : Layer3\n");
			if (m->second->cryptset & crypt_wpa_migmode)
				fprintf(txtfile, "    Encryption : WPA Migration Mode\n");
			if (m->second->cryptset & crypt_wep40)
				fprintf(txtfile, "    Encryption : WEP40\n");
			if (m->second->cryptset & crypt_wep104)
				fprintf(txtfile, "    Encryption : WEP104\n");
			/*
			if (m->second->cryptset & crypt_wpa)
				fprintf(txtfile, "    Encryption : WPA\n");
			*/
			if (m->second->cryptset & crypt_psk)
				fprintf(txtfile, "    Encryption : WPA+PSK\n");
			if (m->second->cryptset & crypt_tkip)
				fprintf(txtfile, "    Encryption : WPA+TKIP\n");
			if (m->second->cryptset & crypt_aes_ocb)
				fprintf(txtfile, "    Encryption : WPA+AES-OCB\n");
			if (m->second->cryptset & crypt_aes_ccm)
				fprintf(txtfile, "    Encryption : WPA+AES-CCM\n");
			if (m->second->cryptset & crypt_leap)
				fprintf(txtfile, "    Encryption : WPA+LEAP\n");
			if (m->second->cryptset & crypt_ttls)
				fprintf(txtfile, "    Encryption : WPA+TTLS\n");
			if (m->second->cryptset & crypt_tls)
				fprintf(txtfile, "    Encryption : WPA+TLS\n");
			if (m->second->cryptset & crypt_peap)
				fprintf(txtfile, "    Encryption : WPA+PEAP\n");
			if (m->second->cryptset & crypt_isakmp)
				fprintf(txtfile, "    Encryption : ISAKMP\n");
			if (m->second->cryptset & crypt_pptp)
				fprintf(txtfile, "    Encryption : PPTP\n");
			if (m->second->cryptset & crypt_fortress)
				fprintf(txtfile, "    Encryption : Fortress\n");
			if (m->second->cryptset & crypt_keyguard)
				fprintf(txtfile, "    Encryption : Keyguard\n");

			ssidnum++;
		}

		fprintf(txtfile, " Channel    : %d\n", net->channel);
		for (map<unsigned int, unsigned int>::const_iterator fmi = net->freq_mhz_map.begin(); fmi != net->freq_mhz_map.end(); ++fmi) {
			float perc = ((float) fmi->second / 
						  (float) (net->llc_packets + net->data_packets)) * 100;
			fprintf(txtfile, " Frequency  : %d - %d packets, %.02f%%\n",
					fmi->first, fmi->second, perc);
		}
		fprintf(txtfile, " Max Seen   : %d\n", net->snrdata.maxseenrate * 100);

		if (net->snrdata.carrierset & (1 << (int) carrier_80211b))
			fprintf(txtfile, " Carrier    : IEEE 802.11b\n");
		if (net->snrdata.carrierset & (1 << (int) carrier_80211bplus))
			fprintf(txtfile, " Carrier    : IEEE 802.11b+\n");
		if (net->snrdata.carrierset & (1 << (int) carrier_80211a))
			fprintf(txtfile, " Carrier    : IEEE 802.11a\n");
		if (net->snrdata.carrierset & (1 << (int) carrier_80211g))
			fprintf(txtfile, " Carrier    : IEEE 802.11g\n");
		if (net->snrdata.carrierset & (1 << (int) carrier_80211fhss))
			fprintf(txtfile, " Carrier    : IEEE 802.11 FHSS\n");
		if (net->snrdata.carrierset & (1 << (int) carrier_80211dsss))
			fprintf(txtfile, " Carrier    : IEEE 802.11 DSSS\n");
		if (net->snrdata.carrierset & (1 << (int) carrier_80211n20))
			fprintf(txtfile, " Carrier    : IEEE 802.11n 20MHz\n");
		if (net->snrdata.carrierset & (1 << (int) carrier_80211n40))
			fprintf(txtfile, " Carrier    : IEEE 802.11n 40MHz\n");

		if (net->snrdata.encodingset & (1 << (int) encoding_cck))
			fprintf(txtfile, " Encoding   : CCK\n");
		if (net->snrdata.encodingset & (1 << (int) encoding_pbcc))
			fprintf(txtfile, " Encoding   : PBCC\n");
		if (net->snrdata.encodingset & (1 << (int) encoding_ofdm))
			fprintf(txtfile, " Encoding   : OFDM\n");
		if (net->snrdata.encodingset & (1 << (int) encoding_dynamiccck))
			fprintf(txtfile, " Encoding   : Dynamic CCK-OFDM\n");
		if (net->snrdata.encodingset & (1 << (int) encoding_gfsk))
			fprintf(txtfile, " Encoding   : GFSK\n");


		fprintf(txtfile, " LLC        : %d\n", net->llc_packets);
		fprintf(txtfile, " Data       : %d\n", net->data_packets);
		fprintf(txtfile, " Crypt      : %d\n", net->crypt_packets);
		fprintf(txtfile, " Fragments  : %d\n", net->fragments);
		fprintf(txtfile, " Retries    : %d\n", net->retries);
		fprintf(txtfile, " Total      : %d\n", net->llc_packets + net->data_packets);
		fprintf(txtfile, " Datasize   : %llu\n", 
				(long long unsigned int) net->datasize);

		if (net->gpsdata.gps_valid) {
			fprintf(txtfile, " Min Pos    : Lat %f Lon %f Alt %f Spd %f\n", 
					net->gpsdata.min_lat, net->gpsdata.min_lon,
					net->gpsdata.min_alt, net->gpsdata.min_spd);
			fprintf(txtfile, " Max Pos    : Lat %f Lon %f Alt %f Spd %f\n", 
					net->gpsdata.max_lat, net->gpsdata.max_lon,
					net->gpsdata.max_alt, net->gpsdata.max_spd);
			fprintf(txtfile, " Peak Pos   : Lat %f Lon %f Alt %f\n", 
					net->snrdata.peak_lat, net->snrdata.peak_lon,
					net->snrdata.peak_alt);
			fprintf(txtfile, " Avg Pos    : AvgLat %f AvgLon %f AvgAlt %f\n",
					net->gpsdata.aggregate_lat, net->gpsdata.aggregate_lon, 
					net->gpsdata.aggregate_alt);
		}

		if (net->guess_ipdata.ip_type > ipdata_factoryguess && 
			net->guess_ipdata.ip_type < ipdata_group) {
			string iptype;
			switch (net->guess_ipdata.ip_type) {
				case ipdata_udptcp:
					iptype = "UDP/TCP";
					break;
				case ipdata_arp:
					iptype = "ARP";
					break;
				case ipdata_dhcp:
					iptype = "DHCP";
					break;
				default:
					iptype = "Unknown";
					break;
			}

			fprintf(txtfile, " IP Type    : %s\n", iptype.c_str());
			fprintf(txtfile, " IP Block   : %s\n", 
					inet_ntoa(net->guess_ipdata.ip_addr_block));
			fprintf(txtfile, " IP Netmask : %s\n", 
					inet_ntoa(net->guess_ipdata.ip_netmask));
			fprintf(txtfile, " IP Gateway : %s\n", 
					inet_ntoa(net->guess_ipdata.ip_gateway));
		}

		fprintf(txtfile, " Last BSSTS : %llu\n", 
				(long long unsigned int) net->bss_timestamp);

		for (map<uuid, Netracker::source_data *>::iterator sdi = net->source_map.begin();
			 sdi != net->source_map.end(); ++sdi) {
			KisPacketSource *kps = 
			globalreg->sourcetracker->FindKisPacketSourceUUID(sdi->second->source_uuid);

			if (kps == NULL) {
				fprintf(txtfile, "    Seen By : (Deleted Source) %s %d packets\n",
						kps->FetchUUID().UUID2String().c_str(), 
						sdi->second->num_packets);
			} else {
				fprintf(txtfile, "    Seen By : %s (%s) %s %d packets\n",
						kps->FetchName().c_str(), kps->FetchInterface().c_str(), 
						kps->FetchUUID().UUID2String().c_str(), 
						sdi->second->num_packets);
			}
			fprintf(txtfile, "              %.24s\n",
					ctime((const time_t *) &(sdi->second->last_seen)));

		}

		if (net->cdp_dev_id.length() > 0)
			fprintf(txtfile, " CDP Device : \"%s\"\n", net->cdp_dev_id.c_str());
		if (net->cdp_port_id.length() > 0)
			fprintf(txtfile, " CDP Port   : \"%s\"\n", net->cdp_port_id.c_str());

		for (map<string, string>::const_iterator ai = net->arb_tag_map.begin();
			 ai != net->arb_tag_map.end(); ++ai)  {
			if (ai->first == "" || ai->second == "")
				continue;

			if (ai->first.length() <= 11)
				fprintf(txtfile, "%11.11s : \"%s\"\n", ai->first.c_str(), 
						ai->second.c_str());
			else
				fprintf(txtfile, "%s : \"%s\"\n", ai->first.c_str(), 
						ai->second.c_str());
		}

		// Sloppy iteration but it doesn't happen often and alert backlogs shouldn't
		// be that huge
		for (unsigned int an = 0; an < alerts->size(); an++) {
			if ((*alerts)[an]->bssid != net->bssid)
				continue;

			kis_alert_info *ali = (*alerts)[an];

			fprintf(txtfile, " Alert      : %.24s %s %s\n",
					ctime((const time_t *) &(ali->tm.tv_sec)),
					ali->header.c_str(),
					ali->text.c_str());
		}

		int clinum = 0;

		// Get the client range pairs and print them out
		for (y = net->client_map.begin(); y != net->client_map.end(); ++y) {
			Netracker::tracked_client *cli = y->second;

			clinum++;

			if (cli->type == client_remove)
				continue;

			string ctype;
			switch (cli->type) {
				case client_fromds:
					ctype = "From Distribution";
					break;
				case client_tods:
					ctype = "To Distribution";
					break;
				case client_interds:
					ctype = "Inter-Distribution";
					break;
				case client_established:
					ctype = "Established";
					break;
				case client_adhoc:
					ctype = "Ad-hoc";
					break;
				default:
					ctype = "Unknown";
					break;
			}

			fprintf(txtfile, " Client %d: MAC %s\n", clinum, 
					cli->mac.Mac2String().c_str());
			fprintf(txtfile, "  Manuf      : %s\n", cli->manuf.c_str());
			fprintf(txtfile, "  First      : %.24s\n", ctime(&(cli->first_time)));
			fprintf(txtfile, "  Last       : %.24s\n", ctime(&(cli->last_time)));
			fprintf(txtfile, "  Type       : %s\n", ctype.c_str());
			fprintf(txtfile, "  MAC        : %s\n", cli->mac.Mac2String().c_str());

			int ssidnum = 1;
			for (map<uint32_t, Netracker::adv_ssid_data *>::iterator m =
				 cli->ssid_map.begin(); m != cli->ssid_map.end(); ++m) {
				string typestr;
				if (m->second->type == ssid_beacon)
					typestr = "Beacon";
				else if (m->second->type == ssid_proberesp)
					typestr = "Probe Response";
				else if (m->second->type == ssid_probereq)
					typestr = "Probe Request";

				fprintf(txtfile, "   SSID %d\n", ssidnum);
				fprintf(txtfile, "    Type       : %s\n", typestr.c_str());
				if (m->second->ssid_cloaked)
					fprintf(txtfile, "    SSID       : <cloaked>\n");
				else
					fprintf(txtfile, "    SSID       : %s\n", 
							m->second->ssid.c_str());
				if (m->second->beacon_info.length() > 0)
					fprintf(txtfile, "    Info       : %s\n", 
							m->second->beacon_info.c_str());
				fprintf(txtfile, "    First      : %.24s\n", 
						ctime(&(m->second->first_time)));
				fprintf(txtfile, "    Last       : %.24s\n", 
						ctime(&(m->second->last_time)));
				fprintf(txtfile, "    Max Rate   : %2.1f\n", m->second->maxrate);
				if (m->second->beaconrate != 0) 
					fprintf(txtfile, "    Beacon     : %d\n", m->second->beaconrate);
				fprintf(txtfile, "    Packets    : %d\n", m->second->packets);

				if (m->second->dot11d_vec.size() > 0) {
					fprintf(txtfile, "    Country    : %s\n", 
							m->second->dot11d_country.c_str());
					for (unsigned int z = 0; z < m->second->dot11d_vec.size(); z++) {
						fprintf(txtfile, "     Chan Range: %u-%u %u dBm\n", 
								m->second->dot11d_vec[z].startchan,
								m->second->dot11d_vec[z].numchan,
								m->second->dot11d_vec[z].txpower);
					}
				}

				if (m->second->cryptset == 0)
					fprintf(txtfile, "    Encryption : None\n");
				if (m->second->cryptset & crypt_wep)
					fprintf(txtfile, "    Encryption : WEP\n");
				if (m->second->cryptset & crypt_layer3)
					fprintf(txtfile, "    Encryption : Layer3\n");
				if (m->second->cryptset & crypt_wep40)
					fprintf(txtfile, "    Encryption : WEP40\n");
				if (m->second->cryptset & crypt_wep104)
					fprintf(txtfile, "    Encryption : WEP104\n");
				if (m->second->cryptset & crypt_tkip)
					fprintf(txtfile, "    Encryption : TKIP\n");
				if (m->second->cryptset & crypt_wpa)
					fprintf(txtfile, "    Encryption : WPA\n");
				if (m->second->cryptset & crypt_psk)
					fprintf(txtfile, "    Encryption : PSK\n");
				if (m->second->cryptset & crypt_aes_ocb)
					fprintf(txtfile, "    Encryption : AES-OCB\n");
				if (m->second->cryptset & crypt_aes_ccm)
					fprintf(txtfile, "    Encryption : AES-CCM\n");
				if (m->second->cryptset & crypt_leap)
					fprintf(txtfile, "    Encryption : LEAP\n");
				if (m->second->cryptset & crypt_ttls)
					fprintf(txtfile, "    Encryption : TTLS\n");
				if (m->second->cryptset & crypt_tls)
					fprintf(txtfile, "    Encryption : TLS\n");
				if (m->second->cryptset & crypt_peap)
					fprintf(txtfile, "    Encryption : PEAP\n");
				if (m->second->cryptset & crypt_isakmp)
					fprintf(txtfile, "    Encryption : ISAKMP\n");
				if (m->second->cryptset & crypt_pptp)
					fprintf(txtfile, "    Encryption : PPTP\n");
				if (m->second->cryptset & crypt_fortress)
					fprintf(txtfile, "    Encryption : Fortress\n");
				if (m->second->cryptset & crypt_keyguard)
					fprintf(txtfile, "    Encryption : Keyguard\n");

				ssidnum++;
			}

			fprintf(txtfile, "  Channel    : %d\n", cli->channel);
		for (map<unsigned int, unsigned int>::const_iterator fmi = cli->freq_mhz_map.begin(); fmi != cli->freq_mhz_map.end(); ++fmi) {
			float perc = ((float) fmi->second / 
						  (float) (cli->llc_packets + cli->data_packets)) * 100;
			fprintf(txtfile, "  Frequency  : %d - %d packets, %.02f%%\n",
					fmi->first, fmi->second, perc);
		}
			fprintf(txtfile, "  Max Seen   : %d\n", cli->snrdata.maxseenrate * 100);

			if (cli->snrdata.carrierset & (1 << (int) carrier_80211b))
				fprintf(txtfile, "  Carrier    : IEEE 802.11b\n");
			if (cli->snrdata.carrierset & (1 << (int) carrier_80211bplus))
				fprintf(txtfile, "  Carrier    : IEEE 802.11b+\n");
			if (cli->snrdata.carrierset & (1 << (int) carrier_80211a))
				fprintf(txtfile, "  Carrier    : IEEE 802.11a\n");
			if (cli->snrdata.carrierset & (1 << (int) carrier_80211g))
				fprintf(txtfile, "  Carrier    : IEEE 802.11g\n");
			if (cli->snrdata.carrierset & (1 << (int) carrier_80211fhss))
				fprintf(txtfile, "  Carrier    : IEEE 802.11 FHSS\n");
			if (cli->snrdata.carrierset & (1 << (int) carrier_80211dsss))
				fprintf(txtfile, "  Carrier    : IEEE 802.11 DSSS\n");

			if (cli->snrdata.encodingset & (1 << (int) encoding_cck))
				fprintf(txtfile, "  Encoding   : CCK\n");
			if (cli->snrdata.encodingset & (1 << (int) encoding_pbcc))
				fprintf(txtfile, "  Encoding   : PBCC\n");
			if (cli->snrdata.encodingset & (1 << (int) encoding_ofdm))
				fprintf(txtfile, "  Encoding   : OFDM\n");

			fprintf(txtfile, "  LLC        : %d\n", cli->llc_packets);
			fprintf(txtfile, "  Data       : %d\n", cli->data_packets);
			fprintf(txtfile, "  Crypt      : %d\n", cli->crypt_packets);
			fprintf(txtfile, "  Fragments  : %d\n", cli->fragments);
			fprintf(txtfile, "  Retries    : %d\n", cli->retries);
			fprintf(txtfile, "  Total      : %d\n", 
					cli->llc_packets + cli->data_packets);
			fprintf(txtfile, "  Datasize   : %llu\n", 
					(long long unsigned int) cli->datasize);

			if (cli->gpsdata.gps_valid) {
				fprintf(txtfile, "  Min Pos    : Lat %f Lon %f Alt %f Spd %f\n", 
						cli->gpsdata.min_lat, cli->gpsdata.min_lon,
						cli->gpsdata.min_alt, cli->gpsdata.min_spd);
				fprintf(txtfile, "  Max Pos    : Lat %f Lon %f Alt %f Spd %f\n", 
						cli->gpsdata.max_lat, cli->gpsdata.max_lon,
						cli->gpsdata.max_alt, cli->gpsdata.max_spd);
				fprintf(txtfile, "  Peak Pos   : Lat %f Lon %f Alt %f\n", 
						cli->snrdata.peak_lat, cli->snrdata.peak_lon,
						cli->snrdata.peak_alt);
				fprintf(txtfile, "  Avg Pos    : AvgLat %f AvgLon %f AvgAlt %f\n",
						cli->gpsdata.aggregate_lat, cli->gpsdata.aggregate_lon, 
						cli->gpsdata.aggregate_alt);
			}

			if (cli->guess_ipdata.ip_type > ipdata_factoryguess && 
				cli->guess_ipdata.ip_type < ipdata_group) {
				string iptype;
				switch (cli->guess_ipdata.ip_type) {
					case ipdata_udptcp:
						iptype = "UDP/TCP";
						break;
					case ipdata_arp:
						iptype = "ARP";
						break;
					case ipdata_dhcp:
						iptype = "DHCP";
						break;
					default:
						iptype = "Unknown";
						break;
				}

				fprintf(txtfile, "  IP Type    : %s\n", iptype.c_str());
				fprintf(txtfile, "  IP Block   : %s\n", 
						inet_ntoa(cli->guess_ipdata.ip_addr_block));
				fprintf(txtfile, "  IP Netmask : %s\n", 
						inet_ntoa(cli->guess_ipdata.ip_netmask));
				fprintf(txtfile, "  IP Gateway : %s\n", 
						inet_ntoa(cli->guess_ipdata.ip_gateway));
			}

			for (map<uuid, Netracker::source_data *>::iterator sdi = 
				 cli->source_map.begin(); sdi != cli->source_map.end(); ++sdi) {
				KisPacketSource *kps = globalreg->sourcetracker->FindKisPacketSourceUUID(sdi->second->source_uuid);

				if (kps == NULL) {
					fprintf(txtfile, "     Seen By : (Deleted Source) %s %d packets\n",
							kps->FetchUUID().UUID2String().c_str(), 
							sdi->second->num_packets);
				} else {
					fprintf(txtfile, "     Seen By : %s (%s) %s %d packets\n",
							kps->FetchName().c_str(), kps->FetchInterface().c_str(), 
							kps->FetchUUID().UUID2String().c_str(), 
							sdi->second->num_packets);
				}
				fprintf(txtfile, "               %.24s\n",
						ctime((const time_t *) &(sdi->second->last_seen)));
			}

			if (cli->cdp_dev_id.length() > 0)
				fprintf(txtfile, "  CDP Device : \"%s\"\n", 
						cli->cdp_dev_id.c_str());
			if (cli->cdp_port_id.length() > 0)
				fprintf(txtfile, "  CDP Port   : \"%s\"\n", 
						cli->cdp_port_id.c_str());
			if (cli->dhcp_host.length() > 0)
				fprintf(txtfile, "   DHCP Host : \"%s\"\n", 
						cli->dhcp_host.c_str());
			if (cli->dhcp_vendor.length() > 0)
				fprintf(txtfile, "     DHCP OS : \"%s\"\n", 
						cli->dhcp_vendor.c_str());

			for (map<string, string>::const_iterator ai = cli->arb_tag_map.begin();
				 ai != cli->arb_tag_map.end(); ++ai)  {
				if (ai->first == "" || ai->second == "")
					continue;

				if (ai->first.length() <= 12)
					fprintf(txtfile, "%12.12s : \"%s\"\n", ai->first.c_str(), 
							ai->second.c_str());
				else
					fprintf(txtfile, "%s : \"%s\"\n", ai->first.c_str(), 
							ai->second.c_str());
			}
		}

	}

	fflush(txtfile);

	fclose(txtfile);

	txtfile = NULL;

	if (rename(tempname.c_str(), fname.c_str()) < 0) {
		_MSG("Failed to rename nettxt temp file " + tempname + " to " + fname + ":" +
			 string(strerror(errno)), MSGFLAG_ERROR);
		return -1;
	}

	dumped_frames = netnum;

	return 1;
}


