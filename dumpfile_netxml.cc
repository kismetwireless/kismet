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
#include "gpsdclient.h"
#include "dumpfile_netxml.h"
#include "packetsource.h"
#include "packetsourcetracker.h"

Dumpfile_Netxml::Dumpfile_Netxml() {
	fprintf(stderr, "FATAL OOPS: Dumpfile_Netxml called with no globalreg\n");
	exit(1);
}

Dumpfile_Netxml::Dumpfile_Netxml(GlobalRegistry *in_globalreg) : 
	Dumpfile(in_globalreg) {
	globalreg = in_globalreg;

	xmlfile = NULL;

	type = "netxml";
	logclass = "xml";

	if (globalreg->netracker == NULL) {
		// fprintf(stderr, "FATAL OOPS:  Netracker missing before Dumpfile_Netxml\n");
		// exit(1);
		_MSG("Deprecated nettracker core disabled, disabling netxml logfile.", 
			 MSGFLAG_INFO);
		return;
	}

	if (globalreg->kismet_config == NULL) {
		fprintf(stderr, "FATAL OOPS:  Config file missing before Dumpfile_Netxml\n");
		exit(1);
	}

	// Find the file name
	if ((fname = ProcessConfigOpt()) == "" ||
		globalreg->fatal_condition) {
		return;
	}

	if ((xmlfile = fopen(fname.c_str(), "w")) == NULL) {
		_MSG("Failed to open netxml log file '" + fname + "': " + strerror(errno),
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	globalreg->RegisterDumpFile(this);

	_MSG("Opened netxml log file '" + fname + "'", MSGFLAG_INFO);

}

Dumpfile_Netxml::~Dumpfile_Netxml() {
	// Close files
	if (xmlfile != NULL) {
		Flush();
	}

	xmlfile = NULL;

	if (export_filter != NULL)
		delete export_filter;
}

int Dumpfile_Netxml::Flush() {
	if (xmlfile != NULL)
		fclose(xmlfile);

	string tempname = fname + ".temp";
	if ((xmlfile = fopen(tempname.c_str(), "w")) == NULL) {
		_MSG("Failed to open temporary netxml file for writing: " +
			 string(strerror(errno)), MSGFLAG_ERROR);
		return -1;
	}

    // Write the XML headers
    fprintf(xmlfile, "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n"
			"<!DOCTYPE detection-run SYSTEM \"http://kismetwireless.net/"
			"kismet-3.1.0.dtd\">\n\n");

    fprintf(xmlfile, "<detection-run kismet-version=\"%s.%s.%s\" "
			"start-time=\"%.24s\">\n\n",
			globalreg->version_major.c_str(),
			globalreg->version_minor.c_str(),
			globalreg->version_tiny.c_str(),
            ctime(&(globalreg->start_time)));

	// Get the source info
	const vector<pst_packetsource *> *sources =
		globalreg->sourcetracker->FetchSourceVec();

	for (unsigned int s = 0; s < sources->size(); s++) {
		if ((*sources)[s]->strong_source == NULL)
			continue;

		fprintf(xmlfile, "<card-source uuid=\"%s\">\n",
				(*sources)[s]->strong_source->FetchUUID().UUID2String().c_str());

		fprintf(xmlfile, " <card-source>%s</card-source>\n",
				SanitizeXML((*sources)[s]->sourceline).c_str());

		fprintf(xmlfile, " <card-name>%s</card-name>\n",
				SanitizeXML((*sources)[s]->strong_source->FetchName()).c_str());
		fprintf(xmlfile, " <card-interface>%s</card-interface>\n",
				SanitizeXML((*sources)[s]->strong_source->FetchInterface()).c_str());
		fprintf(xmlfile, " <card-type>%s</card-type>\n",
				SanitizeXML((*sources)[s]->strong_source->FetchType()).c_str());
		fprintf(xmlfile, " <card-packets>%d</card-packets>\n",
				(*sources)[s]->strong_source->FetchNumPackets());

		fprintf(xmlfile, " <card-hop>%s</card-hop>\n",
				((*sources)[s]->channel_dwell || (*sources)[s]->channel_hop) ? 
						"true" : "false");

		if ((*sources)[s]->channel_ptr != NULL) {
			string channels;

			for (unsigned int c = 0; c < (*sources)[s]->channel_ptr->channel_vec.size();
				 c++) {

				if ((*sources)[s]->channel_ptr->channel_vec[c].range == 0) {
					channels += IntToString((*sources)[s]->channel_ptr->channel_vec[c].u.chan_t.channel);
					if ((*sources)[s]->channel_ptr->channel_vec[c].u.chan_t.dwell > 1)
						channels += string(":") +
							IntToString((*sources)[s]->channel_ptr->channel_vec[c].u.chan_t.dwell);
				} else {
					channels += string("range-") + IntToString((*sources)[s]->channel_ptr->channel_vec[c].u.range_t.start) + string("-") + IntToString((*sources)[s]->channel_ptr->channel_vec[c].u.range_t.end) + string("-") + IntToString((*sources)[s]->channel_ptr->channel_vec[c].u.range_t.width) + string("-") + IntToString((*sources)[s]->channel_ptr->channel_vec[c].u.range_t.iter);
				}

				if (c != (*sources)[s]->channel_ptr->channel_vec.size() - 1)
					channels += ",";
			}

			fprintf(xmlfile, " <card-channels>%s</card-channels>\n",
					channels.c_str());
		}

		fprintf(xmlfile, "</card-source>\n");
	}

	// Get the tracked network and client->ap maps
	const map<mac_addr, Netracker::tracked_network *> tracknet =
		globalreg->netracker->FetchTrackedNets();

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

		fprintf(xmlfile, "  <wireless-network number=\"%d\" type=\"%s\" "
				"first-time=\"%.24s\" ",
				netnum, ntype.c_str(), ctime(&(net->first_time)));
		fprintf(xmlfile, "last-time=\"%.24s\">\n",
				ctime(&(net->last_time)));

		for (map<uint32_t, Netracker::adv_ssid_data *>::iterator m =
			 net->ssid_map.begin(); m != net->ssid_map.end(); ++m) {
			string adtype;

			if (m->second->type == ssid_beacon)
				adtype = "Beacon";
			else if (m->second->type == ssid_proberesp)
				adtype = "Probe Response";
			else if (m->second->type == ssid_file)
				adtype = "Cached SSID";

			fprintf(xmlfile, "    <SSID first-time=\"%.24s\" ",
					ctime(&(m->second->first_time)));
			fprintf(xmlfile, "last-time=\"%.24s\">\n"
					"        <type>%s</type>\n"
					"        <max-rate>%f</max-rate>\n"
					"        <packets>%d</packets>\n",
					ctime(&(m->second->last_time)),
					adtype.c_str(),
					m->second->maxrate,
					m->second->packets);

			if (m->second->beaconrate != 0)
				fprintf(xmlfile, "        <beaconrate>%d</beaconrate>\n",
						m->second->beaconrate);

			if (m->second->cryptset == 0)
				fprintf(xmlfile, "        <encryption>None</encryption>\n");
			if (m->second->cryptset == crypt_wep)
				fprintf(xmlfile, "        <encryption>WEP</encryption>\n");
			if (m->second->cryptset & crypt_layer3)
				fprintf(xmlfile, "        <encryption>Layer3</encryption>\n");
			if (m->second->cryptset & crypt_wpa_migmode)
				fprintf(xmlfile, "        <encryption>WPA Migration Mode</encryption>\n");
			if (m->second->cryptset & crypt_wep40)
				fprintf(xmlfile, "        <encryption>WEP40</encryption>\n");
			if (m->second->cryptset & crypt_wep104)
				fprintf(xmlfile, "        <encryption>WEP104</encryption>\n");
			/*
			if (m->second->cryptset & crypt_wpa)
				fprintf(xmlfile, "        <encryption>WPA</encryption>\n");
			*/
			if (m->second->cryptset & crypt_tkip)
				fprintf(xmlfile, "        <encryption>WPA+TKIP</encryption>\n");
			if (m->second->cryptset & crypt_psk)
				fprintf(xmlfile, "        <encryption>WPA+PSK</encryption>\n");
			if (m->second->cryptset & crypt_aes_ocb)
				fprintf(xmlfile, "        <encryption>WPA+AES-OCB</encryption>\n");
			if (m->second->cryptset & crypt_aes_ccm)
				fprintf(xmlfile, "        <encryption>WPA+AES-CCM</encryption>\n");
			if (m->second->cryptset & crypt_leap)
				fprintf(xmlfile, "        <encryption>WPA+LEAP</encryption>\n");
			if (m->second->cryptset & crypt_ttls)
				fprintf(xmlfile, "        <encryption>WPA+TTLS</encryption>\n");
			if (m->second->cryptset & crypt_tls)
				fprintf(xmlfile, "        <encryption>WPA+TLS</encryption>\n");
			if (m->second->cryptset & crypt_peap)
				fprintf(xmlfile, "        <encryption>WPA+PEAP</encryption>\n");
			if (m->second->cryptset & crypt_isakmp)
				fprintf(xmlfile, "        <encryption>ISAKMP</encryption>\n");
			if (m->second->cryptset & crypt_pptp)
				fprintf(xmlfile, "        <encryption>PPTP</encryption>\n");
			if (m->second->cryptset & crypt_fortress)
				fprintf(xmlfile, "        <encryption>Fortress</encryption>\n");
			if (m->second->cryptset & crypt_keyguard)
				fprintf(xmlfile, "        <encryption>Keyguard</encryption>\n");

			if (m->second->dot11d_vec.size() > 0) {
				fprintf(xmlfile, "        <dot11d country=\"%s\">\n",
						SanitizeXML(m->second->dot11d_country).c_str());
				for (unsigned int z = 0; z < m->second->dot11d_vec.size(); z++) {
					fprintf(xmlfile, "          <dot11d-range start=\"%u\" end=\"%u\" "
							"max-power=\"%u\"/>\n",
							m->second->dot11d_vec[z].startchan,
							m->second->dot11d_vec[z].startchan + 
							m->second->dot11d_vec[z].numchan - 1,
							m->second->dot11d_vec[z].txpower);
				}
				fprintf(xmlfile, "        </dot11d>\n");
			}

			fprintf(xmlfile, "        <essid cloaked=\"%s\">%s</essid>\n",
					m->second->ssid_cloaked ? "true" : "false", 
					SanitizeXML(m->second->ssid).c_str());
			if (m->second->beacon_info.length() > 0)
				fprintf(xmlfile, "        <info>%s</info>\n",
						SanitizeXML(m->second->beacon_info).c_str());

			fprintf(xmlfile, "    </SSID>\n");
		}

		fprintf(xmlfile, "    <BSSID>%s</BSSID>\n", net->bssid.Mac2String().c_str());

		fprintf(xmlfile, "    <manuf>%s</manuf>\n", SanitizeXML(net->manuf).c_str());

		fprintf(xmlfile, "    <channel>%d</channel>\n", net->channel);
		for (map<unsigned int, unsigned int>::const_iterator fmi = net->freq_mhz_map.begin(); fmi != net->freq_mhz_map.end(); ++fmi) {
			fprintf(xmlfile, "    <freqmhz>%u %u</freqmhz>\n", fmi->first, fmi->second);
		}
		fprintf(xmlfile, "    <maxseenrate>%ld</maxseenrate>\n",
				(long) net->snrdata.maxseenrate * 100);

		if (net->snrdata.carrierset & (1 << (int) carrier_80211b))
			fprintf(xmlfile, "    <carrier>IEEE 802.11b</carrier>\n");
		if (net->snrdata.carrierset & (1 << (int) carrier_80211bplus))
			fprintf(xmlfile, "    <carrier>IEEE 802.11b+</carrier>\n");
		if (net->snrdata.carrierset & (1 << (int) carrier_80211a))
			fprintf(xmlfile, "    <carrier>IEEE 802.11a</carrier>\n");
		if (net->snrdata.carrierset & (1 << (int) carrier_80211g))
			fprintf(xmlfile, "    <carrier>IEEE 802.11g</carrier>\n");
		if (net->snrdata.carrierset & (1 << (int) carrier_80211fhss))
			fprintf(xmlfile, "    <carrier>IEEE 802.11 FHSS</carrier>\n");
		if (net->snrdata.carrierset & (1 << (int) carrier_80211dsss))
			fprintf(xmlfile, "    <carrier>IEEE 802.11 DSSS</carrier>\n");
		if (net->snrdata.carrierset & (1 << (int) carrier_80211n20))
			fprintf(xmlfile, "    <carrier>IEEE 802.11n 20MHz</carrier>\n");
		if (net->snrdata.carrierset & (1 << (int) carrier_80211n40))
			fprintf(xmlfile, "    <carrier>IEEE 802.11n 40MHz</carrier>\n");

		if (net->snrdata.encodingset & (1 << (int) encoding_cck))
			fprintf(xmlfile, "    <encoding>CCK</encoding>\n");
		if (net->snrdata.encodingset & (1 << (int) encoding_pbcc))
			fprintf(xmlfile, "    <encoding>PBCC</encoding>\n");
		if (net->snrdata.encodingset & (1 << (int) encoding_ofdm))
			fprintf(xmlfile, "    <encoding>OFDM</encoding>\n");
		if (net->snrdata.encodingset & (1 << (int) encoding_dynamiccck))
			fprintf(xmlfile, "    <encoding>Dynamic CCK-OFDM</encoding>\n");
		if (net->snrdata.encodingset & (1 << (int) encoding_gfsk))
			fprintf(xmlfile, "    <encoding>GFSK</encoding>\n");

		fprintf(xmlfile, "     <packets>\n");
		fprintf(xmlfile, "       <LLC>%d</LLC>\n", net->llc_packets);
		fprintf(xmlfile, "       <data>%d</data>\n", net->data_packets);
		fprintf(xmlfile, "       <crypt>%d</crypt>\n", net->crypt_packets);
		// TODO - DupeIV stuff?
		fprintf(xmlfile, "       <total>%d</total>\n", 
				net->llc_packets + net->data_packets);
		fprintf(xmlfile, "       <fragments>%d</fragments>\n", net->fragments);
		fprintf(xmlfile, "       <retries>%d</retries>\n", net->retries);
		fprintf(xmlfile, "     </packets>\n");

		fprintf(xmlfile, "     <datasize>%llu</datasize>\n", 
				(long long unsigned int) net->datasize);

		if (net->snrdata.last_signal_rssi != 0 ||
			net->snrdata.last_signal_dbm != 0) {
			fprintf(xmlfile, "    <snr-info>\n");
			fprintf(xmlfile, "      <last_signal_dbm>%d</last_signal_dbm>\n",
					net->snrdata.last_signal_dbm);
			fprintf(xmlfile, "      <last_noise_dbm>%d</last_noise_dbm>\n",
					net->snrdata.last_noise_dbm);
			fprintf(xmlfile, "      <last_signal_rssi>%d</last_signal_rssi>\n",
					net->snrdata.last_signal_rssi);
			fprintf(xmlfile, "      <last_noise_rssi>%d</last_noise_rssi>\n",
					net->snrdata.last_noise_rssi);

			fprintf(xmlfile, "      <min_signal_dbm>%d</min_signal_dbm>\n",
					net->snrdata.min_signal_dbm);
			fprintf(xmlfile, "      <min_noise_dbm>%d</min_noise_dbm>\n",
					net->snrdata.min_noise_dbm);
			fprintf(xmlfile, "      <min_signal_rssi>%d</min_signal_rssi>\n",
					net->snrdata.min_signal_rssi);
			fprintf(xmlfile, "      <min_noise_rssi>%d</min_noise_rssi>\n",
					net->snrdata.min_noise_rssi);

			fprintf(xmlfile, "      <max_signal_dbm>%d</max_signal_dbm>\n",
					net->snrdata.max_signal_dbm);
			fprintf(xmlfile, "      <max_noise_dbm>%d</max_noise_dbm>\n",
					net->snrdata.max_noise_dbm);
			fprintf(xmlfile, "      <max_signal_rssi>%d</max_signal_rssi>\n",
					net->snrdata.max_signal_rssi);
			fprintf(xmlfile, "      <max_noise_rssi>%d</max_noise_rssi>\n",
					net->snrdata.max_noise_rssi);

			fprintf(xmlfile, "    </snr-info>\n");
		}

		if (net->gpsdata.gps_valid) {
			fprintf(xmlfile, "    <gps-info>\n");
			fprintf(xmlfile, "      <min-lat>%f</min-lat>\n", net->gpsdata.min_lat);
			fprintf(xmlfile, "      <min-lon>%f</min-lon>\n", net->gpsdata.min_lon);
			fprintf(xmlfile, "      <min-alt>%f</min-alt>\n", net->gpsdata.min_alt);
			fprintf(xmlfile, "      <min-spd>%f</min-spd>\n", net->gpsdata.min_spd);
			fprintf(xmlfile, "      <max-lat>%f</max-lat>\n", net->gpsdata.max_lat);
			fprintf(xmlfile, "      <max-lon>%f</max-lon>\n", net->gpsdata.max_lon);
			fprintf(xmlfile, "      <max-alt>%f</max-alt>\n", net->gpsdata.max_alt);
			fprintf(xmlfile, "      <max-spd>%f</max-spd>\n", net->gpsdata.max_spd);
			fprintf(xmlfile, "      <peak-lat>%f</peak-lat>\n", 
					net->snrdata.peak_lat);
			fprintf(xmlfile, "      <peak-lon>%f</peak-lon>\n", 
					net->snrdata.peak_lon);
			fprintf(xmlfile, "      <peak-alt>%f</peak-alt>\n", 
					net->snrdata.peak_alt);
			fprintf(xmlfile, "      <avg-lat>%f</avg-lat>\n", 
					net->gpsdata.aggregate_lat);
			fprintf(xmlfile, "      <avg-lon>%f</avg-lon>\n", 
					net->gpsdata.aggregate_lon);
			fprintf(xmlfile, "      <avg-alt>%f</avg-alt>\n", 
					net->gpsdata.aggregate_alt);
			fprintf(xmlfile, "    </gps-info>\n");
		}

		for (map<string, string>::const_iterator ai = net->arb_tag_map.begin();
			 ai != net->arb_tag_map.end(); ++ai) {
			if (ai->first == "" || ai->second == "")
				continue;

			fprintf(xmlfile, "<tag name=\"%s\">%s</tag>\n", 
					SanitizeXML(ai->first).c_str(), SanitizeXML(ai->second).c_str());
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

			fprintf(xmlfile, "    <ip-address type=\"%s\">\n", iptype.c_str());
			fprintf(xmlfile, "      <ip-block>%s</ip-block>\n", 
					inet_ntoa(net->guess_ipdata.ip_addr_block));
			fprintf(xmlfile, "      <ip-netmask>%s</ip-netmask>\n",
					inet_ntoa(net->guess_ipdata.ip_netmask));
			fprintf(xmlfile, "      <ip-gateway>%s</ip-gateway>\n",
					inet_ntoa(net->guess_ipdata.ip_gateway));
			fprintf(xmlfile, "    </ip-address>\n");
		}

		fprintf(xmlfile, "    <bsstimestamp>%llu</bsstimestamp>\n", 
				(long long unsigned int) net->bss_timestamp);
		fprintf(xmlfile, "    <cdp-device>%s</cdp-device>\n",
				SanitizeXML(net->cdp_dev_id).c_str());
		fprintf(xmlfile, "    <cdp-portid>%s</cdp-portid>\n",
				SanitizeXML(net->cdp_port_id).c_str());

		for (map<uuid, Netracker::source_data *>::iterator sdi = 
			 net->source_map.begin(); sdi != net->source_map.end(); ++sdi) {
			KisPacketSource *kps = globalreg->sourcetracker->FindKisPacketSourceUUID(sdi->second->source_uuid);

			fprintf(xmlfile, "    <seen-card>\n");
			fprintf(xmlfile, "     <seen-uuid>%s</seen-uuid>\n",
					kps->FetchUUID().UUID2String().c_str());
			fprintf(xmlfile, "     <seen-time>%.24s</seen-time>\n",
					ctime((const time_t *) &(sdi->second->last_seen)));
			fprintf(xmlfile, "     <seen-packets>%d</seen-packets>\n",
					sdi->second->num_packets);
			fprintf(xmlfile, "    </seen-card>\n");
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
					ctype = "fromds";
					break;
				case client_tods:
					ctype = "tods";
					break;
				case client_interds:
					ctype = "interds";
					break;
				case client_established:
					ctype = "established";
					break;
				case client_adhoc:
					ctype = "ad-hoc";
					break;
				default:
					ctype = "unknown";
					break;
			}

			fprintf(xmlfile, "    <wireless-client number=\"%d\" type=\"%s\" "
					"first-time=\"%.24s\" ",
					clinum, ctype.c_str(),
					ctime(&(cli->first_time)));
			fprintf(xmlfile, "last-time=\"%.24s\">\n",
					ctime(&(cli->last_time)));

			fprintf(xmlfile, "      <client-mac>%s</client-mac>\n", 
					cli->mac.Mac2String().c_str());

			fprintf(xmlfile, "      <client-manuf>%s</client-manuf>\n", 
					SanitizeXML(cli->manuf).c_str());

			for (map<uint32_t, Netracker::adv_ssid_data *>::iterator m =
				 cli->ssid_map.begin(); m != cli->ssid_map.end(); ++m) {
				string adtype;

				if (m->second->type == ssid_beacon)
					adtype = "Beacon";
				else if (m->second->type == ssid_proberesp)
					adtype = "Probe Response";
				else if (m->second->type == ssid_probereq)
					adtype = "Probe Request";

				fprintf(xmlfile, "        <SSID first-time=\"%.24s\" ",
						ctime(&(m->second->first_time)));
				fprintf(xmlfile, "last-time=\"%.24s\">\n"
						"            <type>%s</type>\n"
						"            <max-rate>%f</max-rate>\n"
						"            <packets>%d</packets>\n",
						ctime(&(m->second->last_time)),
						adtype.c_str(),
						m->second->maxrate,
						m->second->packets);

				if (m->second->beaconrate != 0)
					fprintf(xmlfile, "            <beaconrate>%d</beaconrate>\n",
							m->second->beaconrate);

				if (m->second->dot11d_vec.size() > 0) {
					fprintf(xmlfile, "            <dot11d country=\"%s\">\n",
							SanitizeXML(m->second->dot11d_country).c_str());
					for (unsigned int z = 0; z < m->second->dot11d_vec.size(); z++) {
						fprintf(xmlfile, "              <dot11d-range start=\"%u\" "
								"end=\"%u\" max-power=\"%u\"/>\n",
								m->second->dot11d_vec[z].startchan,
								m->second->dot11d_vec[z].numchan,
								m->second->dot11d_vec[z].txpower);
					}
					fprintf(xmlfile, "        </dot11d>\n");
				}

				if (m->second->cryptset == 0)
					fprintf(xmlfile, "            <encryption>None</encryption>\n");
				if (m->second->cryptset & crypt_wep)
					fprintf(xmlfile, "            <encryption>WEP</encryption>\n");
				if (m->second->cryptset & crypt_layer3)
					fprintf(xmlfile, "            <encryption>Layer3</encryption>\n");
				if (m->second->cryptset & crypt_wep40)
					fprintf(xmlfile, "            <encryption>WEP40</encryption>\n");
				if (m->second->cryptset & crypt_wep104)
					fprintf(xmlfile, "            <encryption>WEP104</encryption>\n");
				if (m->second->cryptset & crypt_tkip)
					fprintf(xmlfile, "            <encryption>TKIP</encryption>\n");
				if (m->second->cryptset & crypt_wpa)
					fprintf(xmlfile, "            <encryption>WPA</encryption>\n");
				if (m->second->cryptset & crypt_psk)
					fprintf(xmlfile, "            <encryption>PSK</encryption>\n");
				if (m->second->cryptset & crypt_aes_ocb)
					fprintf(xmlfile, 
							"            <encryption>AES-OCB</encryption>\n");
				if (m->second->cryptset & crypt_aes_ccm)
					fprintf(xmlfile, 
							"            <encryption>AES-CCM</encryption>\n");
				if (m->second->cryptset & crypt_leap)
					fprintf(xmlfile, "            <encryption>LEAP</encryption>\n");
				if (m->second->cryptset & crypt_ttls)
					fprintf(xmlfile, "            <encryption>TTLS</encryption>\n");
				if (m->second->cryptset & crypt_tls)
					fprintf(xmlfile, "            <encryption>TLS</encryption>\n");
				if (m->second->cryptset & crypt_peap)
					fprintf(xmlfile, "            <encryption>PEAP</encryption>\n");
				if (m->second->cryptset & crypt_isakmp)
					fprintf(xmlfile, "            <encryption>ISAKMP</encryption>\n");
				if (m->second->cryptset & crypt_pptp)
					fprintf(xmlfile, "            <encryption>PPTP</encryption>\n");
				if (m->second->cryptset & crypt_fortress)
					fprintf(xmlfile, "            <encryption>Fortress</encryption>\n");
				if (m->second->cryptset & crypt_keyguard)
					fprintf(xmlfile, "            <encryption>Keyguard</encryption>\n");

				if (m->second->ssid_cloaked == 0)
					fprintf(xmlfile, "            <ssid>%s</ssid>\n",
							SanitizeXML(m->second->ssid).c_str());
				if (m->second->beacon_info.length() > 0)
					fprintf(xmlfile, "        <info>%s</info>\n",
							SanitizeXML(m->second->beacon_info).c_str());

				fprintf(xmlfile, "        </SSID>\n");
			}

			fprintf(xmlfile, "      <channel>%d</channel>\n", cli->channel);
			for (map<unsigned int, unsigned int>::const_iterator fmi = cli->freq_mhz_map.begin(); fmi != cli->freq_mhz_map.end(); ++fmi) {
				fprintf(xmlfile, "      <freqmhz>%u %u</freqmhz>\n", fmi->first, fmi->second);
			}
			fprintf(xmlfile, "      <maxseenrate>%ld</maxseenrate>\n",
					(long) cli->snrdata.maxseenrate * 100);

			if (cli->snrdata.carrierset & (1 << (int) carrier_80211b))
				fprintf(xmlfile, "      <carrier>IEEE 802.11b"
						"</carrier>\n");
			if (cli->snrdata.carrierset & (1 << (int) carrier_80211bplus))
				fprintf(xmlfile, "      <carrier>IEEE 802.11b+"
						"</carrier>\n");
			if (cli->snrdata.carrierset & (1 << (int) carrier_80211a))
				fprintf(xmlfile, "      <carrier>IEEE 802.11a"
						"</carrier>\n");
			if (cli->snrdata.carrierset & (1 << (int) carrier_80211g))
				fprintf(xmlfile, "      <carrier>IEEE 802.11g"
						"</carrier>\n");
			if (cli->snrdata.carrierset & (1 << (int) carrier_80211fhss))
				fprintf(xmlfile, "      <carrier>IEEE 802.11 FHSS"
						"</carrier>\n");
			if (cli->snrdata.carrierset & (1 << (int) carrier_80211dsss))
				fprintf(xmlfile, "      <carrier>IEEE 802.11 DSSS"
						"</carrier>\n");

			if (cli->snrdata.encodingset & (1 << (int) encoding_cck))
				fprintf(xmlfile, "      <encoding>CCK</encoding>\n");
			if (cli->snrdata.encodingset & (1 << (int) encoding_pbcc))
				fprintf(xmlfile, "      <encoding>PBCC</encoding>\n");
			if (cli->snrdata.encodingset & (1 << (int) encoding_ofdm))
				fprintf(xmlfile, "      <encoding>OFDM</encoding>\n");

			fprintf(xmlfile, "       <packets>\n");
			fprintf(xmlfile, "         <LLC>%d</LLC>\n", 
					cli->llc_packets);
			fprintf(xmlfile, "         <data>%d</data>\n", 
					cli->data_packets);
			fprintf(xmlfile, "         <crypt>%d</crypt>\n", 
					cli->crypt_packets);
			// TODO - DupeIV stuff?
			fprintf(xmlfile, "         <total>%d</total>\n", 
					cli->llc_packets + cli->data_packets);
			fprintf(xmlfile, "         <fragments>%d</fragments>\n", 
					cli->fragments);
			fprintf(xmlfile, "         <retries>%d</retries>\n", 
					cli->retries);
			fprintf(xmlfile, "       </packets>\n");

			fprintf(xmlfile, "       <datasize>%llu</datasize>\n", 
					(long long unsigned int) cli->datasize);

			if (cli->snrdata.last_signal_rssi != 0 ||
				cli->snrdata.last_signal_dbm != 0) {
				fprintf(xmlfile, "      <snr-info>\n");
				fprintf(xmlfile, "        <last_signal_dbm>%d</last_signal_dbm>\n",
						cli->snrdata.last_signal_dbm);
				fprintf(xmlfile, "        <last_noise_dbm>%d</last_noise_dbm>\n",
						cli->snrdata.last_noise_dbm);
				fprintf(xmlfile, "        <last_signal_rssi>%d</last_signal_rssi>\n",
						cli->snrdata.last_signal_rssi);
				fprintf(xmlfile, "        <last_noise_rssi>%d</last_noise_rssi>\n",
						cli->snrdata.last_noise_rssi);

				fprintf(xmlfile, "        <min_signal_dbm>%d</min_signal_dbm>\n",
						cli->snrdata.min_signal_dbm);
				fprintf(xmlfile, "        <min_noise_dbm>%d</min_noise_dbm>\n",
						cli->snrdata.min_noise_dbm);
				fprintf(xmlfile, "        <min_signal_rssi>%d</min_signal_rssi>\n",
						cli->snrdata.min_signal_rssi);
				fprintf(xmlfile, "        <min_noise_rssi>%d</min_noise_rssi>\n",
						cli->snrdata.min_noise_rssi);

				fprintf(xmlfile, "        <max_signal_dbm>%d</max_signal_dbm>\n",
						cli->snrdata.max_signal_dbm);
				fprintf(xmlfile, "        <max_noise_dbm>%d</max_noise_dbm>\n",
						cli->snrdata.max_noise_dbm);
				fprintf(xmlfile, "        <max_signal_rssi>%d</max_signal_rssi>\n",
						cli->snrdata.max_signal_rssi);
				fprintf(xmlfile, "        <max_noise_rssi>%d</max_noise_rssi>\n",
						cli->snrdata.max_noise_rssi);

				fprintf(xmlfile, "      </snr-info>\n");
			}

			if (cli->gpsdata.gps_valid) {
				fprintf(xmlfile, "      <gps-info>\n");
				fprintf(xmlfile, "        <min-lat>%f</min-lat>\n", 
						cli->gpsdata.min_lat);
				fprintf(xmlfile, "        <min-lon>%f</min-lon>\n", 
						cli->gpsdata.min_lon);
				fprintf(xmlfile, "        <min-alt>%f</min-alt>\n", 
						cli->gpsdata.min_alt);
				fprintf(xmlfile, "        <min-spd>%f</min-spd>\n", 
						cli->gpsdata.min_spd);
				fprintf(xmlfile, "        <max-lat>%f</max-lat>\n", 
						cli->gpsdata.max_lat);
				fprintf(xmlfile, "        <max-lon>%f</max-lon>\n", 
						cli->gpsdata.max_lon);
				fprintf(xmlfile, "        <max-alt>%f</max-alt>\n", 
						cli->gpsdata.max_alt);
				fprintf(xmlfile, "        <max-spd>%f</max-spd>\n", 
						cli->gpsdata.max_spd);
				fprintf(xmlfile, "        <peak-lat>%f</peak-lat>\n", 
						cli->snrdata.peak_lat);
				fprintf(xmlfile, "        <peak-lon>%f</peak-lon>\n", 
						cli->snrdata.peak_lon);
				fprintf(xmlfile, "        <peak-alt>%f</peak-alt>\n", 
						cli->snrdata.peak_alt);
				fprintf(xmlfile, "        <avg-lat>%f</avg-lat>\n", 
						cli->gpsdata.aggregate_lat);
				fprintf(xmlfile, "        <avg-lon>%f</avg-lon>\n", 
						cli->gpsdata.aggregate_lon);
				fprintf(xmlfile, "        <avg-alt>%f</avg-alt>\n", 
						cli->gpsdata.aggregate_alt);
				fprintf(xmlfile, "      </gps-info>\n");
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

				fprintf(xmlfile, "      <ip-address type=\"%s\">\n", 
						iptype.c_str());
				fprintf(xmlfile, "        <ip-block>%s</ip-block>\n", 
						inet_ntoa(cli->guess_ipdata.ip_addr_block));
				fprintf(xmlfile, "        <ip-netmask>%s</ip-netmask>\n",
						inet_ntoa(cli->guess_ipdata.ip_netmask));
				fprintf(xmlfile, "        <ip-gateway>%s</ip-gateway>\n",
						inet_ntoa(cli->guess_ipdata.ip_gateway));
				fprintf(xmlfile, "      </ip-address>\n");
			}

			if (cli->cdp_dev_id.length() > 0)
				fprintf(xmlfile, "      <cdp-device>%s</cdp-device>\n",
						SanitizeXML(cli->cdp_dev_id).c_str());
			if (cli->cdp_port_id.length() > 0)
				fprintf(xmlfile, "      <cdp-portid>%s</cdp-portid>\n",
						SanitizeXML(cli->cdp_port_id).c_str());

			if (cli->dhcp_host.length() > 0)
				fprintf(xmlfile, "      <dhcp-hostname>%s</dhcp-hostname>\n",
						SanitizeXML(cli->dhcp_host).c_str());
			if (cli->dhcp_vendor.length() > 0)
				fprintf(xmlfile, "      <dhcp-vendor>%s</dhcp-vendor>\n",
						SanitizeXML(cli->dhcp_vendor).c_str());

			for (map<uuid, Netracker::source_data *>::iterator sdi = 
				 cli->source_map.begin(); sdi != cli->source_map.end(); ++sdi) {
				KisPacketSource *kps = globalreg->sourcetracker->FindKisPacketSourceUUID(sdi->second->source_uuid);

				fprintf(xmlfile, "      <seen-card>\n");
				fprintf(xmlfile, "       <seen-uuid>%s</seen-uuid>\n",
						kps->FetchUUID().UUID2String().c_str());
				fprintf(xmlfile, "       <seen-time>%.24s</seen-time>\n",
						ctime((const time_t *) &(sdi->second->last_seen)));
				fprintf(xmlfile, "       <seen-packets>%d</seen-packets>\n",
						sdi->second->num_packets);
				fprintf(xmlfile, "      </seen-card>\n");
			}

			for (map<string, string>::const_iterator ai = cli->arb_tag_map.begin();
				 ai != cli->arb_tag_map.end(); ++ai) {
				if (ai->first == "" || ai->second == "")
					continue;

				fprintf(xmlfile, "      <tag name=\"%s\">%s</tag>\n", 
						SanitizeXML(ai->first).c_str(), SanitizeXML(ai->second).c_str());
			}

			fprintf(xmlfile, "    </wireless-client>\n");

		}
			fprintf(xmlfile, "  </wireless-network>\n");

	}

	fprintf(xmlfile, "</detection-run>\n");

	fflush(xmlfile);

	fclose(xmlfile);

	xmlfile = NULL;

	if (rename(tempname.c_str(), fname.c_str()) < 0) {
		_MSG("Failed to rename netxml temp file " + tempname + " to " + fname + ":" +
			 string(strerror(errno)), MSGFLAG_ERROR);
		return -1;
	}

	dumped_frames = netnum;

	return 1;
}


