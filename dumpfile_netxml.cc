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

Dumpfile_Netxml::Dumpfile_Netxml() {
	fprintf(stderr, "FATAL OOPS: Dumpfile_Netxml called with no globalreg\n");
	exit(1);
}

Dumpfile_Netxml::Dumpfile_Netxml(GlobalRegistry *in_globalreg) : 
	Dumpfile(in_globalreg) {
	globalreg = in_globalreg;

	xmlfile = NULL;

	type = "netxml";

	if (globalreg->netracker == NULL) {
		fprintf(stderr, "FATAL OOPS:  Netracker missing before Dumpfile_Netxml\n");
		exit(1);
	}

	if (globalreg->kismet_config == NULL) {
		fprintf(stderr, "FATAL OOPS:  Config file missing before Dumpfile_Netxml\n");
		exit(1);
	}

	int ret = 0;

	if ((ret = ProcessRuntimeResume("netxml")) == -1) {
		if (globalreg->fatal_condition)
			return;

		// Find the file name
		if ((fname = ProcessConfigOpt("netxml")) == "" || 
			globalreg->fatal_condition) {
			return;
		}
	} else if (ret == 1) {
		_MSG("Resuming netxml log file '" + fname + "'", MSGFLAG_INFO);
	} else {
		_MSG("Netxml log file not enabled in runstate", MSGFLAG_INFO);
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
		fclose(xmlfile);
		_MSG("Closed netxml log file '" + fname + "'", MSGFLAG_INFO);
	}

	xmlfile = NULL;

	if (export_filter != NULL)
		delete export_filter;
}

int Dumpfile_Netxml::Flush() {
	if (xmlfile == NULL)
		return 0;

	rewind(xmlfile);

    // Write the XML headers
    fprintf(xmlfile, "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n"
			"<!DOCTYPE detection-run SYSTEM \"http://kismetwireless.net/"
			"kismet-3.1.0.dtd\">\n\n");

    fprintf(xmlfile, "<detection-run kismet-version=\"%s.%s.%s\" "
			"start-time=\"%.24s\">\n\n",
			VERSION_MAJOR, VERSION_MINOR, VERSION_TINY,
            ctime(&(globalreg->start_time)));

	// Get the tracket network and client->ap maps
	const map<mac_addr, Netracker::tracked_network *> tracknet =
		globalreg->netracker->FetchTrackedNets();
	const multimap<mac_addr, Netracker::tracked_client *> trackcli =
		globalreg->netracker->FetchAssocClients();

	map<mac_addr, Netracker::tracked_network *>::const_iterator x;
	multimap<mac_addr, Netracker::tracked_client *>::const_iterator y;

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

		fprintf(xmlfile, "  <wireless-network number=\"%d\" type=\"%s\" wep=\"%s\" "
				"cloaked=\"%s\" first-time=\"%.24s\" last-time=\"%.24s\">\n",
				netnum, ntype.c_str(), net->cryptset ? "true" : "false",
				net->ssid_cloaked ? "true" : "false",
				ctime(&(net->first_time)), ctime(&(net->last_time)));

		if (net->ssid.length() > 0) {
			for (map<uint32_t, string>::iterator m = net->beacon_ssid_map.begin();
				 m != net->beacon_ssid_map.end(); ++m) {
				if (m->second.length() > 0) {
					fprintf(xmlfile, "    <SSID>%s</SSID>\n",
							SanitizeXML(m->second).c_str());
				}
			}
			fprintf(xmlfile, "    <Last-SSID>%s</Last-SSID>\n", 
					SanitizeXML(net->ssid).c_str());
		}

		fprintf(xmlfile, "    <BSSID>%s</BSSID>\n", net->bssid.Mac2String().c_str());
		
		if (net->beacon_info.length() > 0) {
			fprintf(xmlfile, "    <info>%s</info>\n", 
					SanitizeXML(net->beacon_info).c_str());
		}

		fprintf(xmlfile, "    <channel>%d</channel>\n", net->channel);
		fprintf(xmlfile, "    <maxrate>%2.1f</maxrate>\n", net->maxrate);
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

		if (net->snrdata.encodingset & (1 << (int) encoding_cck))
			fprintf(xmlfile, "    <encoding>CCK</encoding>\n");
		if (net->snrdata.encodingset & (1 << (int) encoding_pbcc))
			fprintf(xmlfile, "    <encoding>PBCC</encoding>\n");
		if (net->snrdata.encodingset & (1 << (int) encoding_ofdm))
			fprintf(xmlfile, "    <encoding>OFDM</encoding>\n");

		if (net->cryptset == 0)
			fprintf(xmlfile, "    <encryption>None</encryption>\n");
		if (net->cryptset & crypt_wep)
			fprintf(xmlfile, "    <encryption>WEP</encryption>\n");
		if (net->cryptset & crypt_layer3)
			fprintf(xmlfile, "    <encryption>Layer3</encryption>\n");
		if (net->cryptset & crypt_wep40)
			fprintf(xmlfile, "    <encryption>WEP40</encryption>\n");
		if (net->cryptset & crypt_wep104)
			fprintf(xmlfile, "    <encryption>WEP104</encryption>\n");
		if (net->cryptset & crypt_tkip)
			fprintf(xmlfile, "    <encryption>TKIP</encryption>\n");
		if (net->cryptset & crypt_wpa)
			fprintf(xmlfile, "    <encryption>WPA</encryption>\n");
		if (net->cryptset & crypt_psk)
			fprintf(xmlfile, "    <encryption>PSK</encryption>\n");
		if (net->cryptset & crypt_aes_ocb)
			fprintf(xmlfile, "    <encryption>AES-OCB</encryption>\n");
		if (net->cryptset & crypt_aes_ccm)
			fprintf(xmlfile, "    <encryption>AES-CCM</encryption>\n");
		if (net->cryptset & crypt_leap)
			fprintf(xmlfile, "    <encryption>LEAP</encryption>\n");
		if (net->cryptset & crypt_ttls)
			fprintf(xmlfile, "    <encryption>TTLS</encryption>\n");
		if (net->cryptset & crypt_tls)
			fprintf(xmlfile, "    <encryption>TLS</encryption>\n");
		if (net->cryptset & crypt_peap)
			fprintf(xmlfile, "    <encryption>PEAP</encryption>\n");
		if (net->cryptset & crypt_isakmp)
			fprintf(xmlfile, "    <encryption>ISAKMP</encryption>\n");
		if (net->cryptset & crypt_pptp)
			fprintf(xmlfile, "    <encryption>PPTP</encryption>\n");

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
			fprintf(xmlfile, "      <agg-lat>%Lf</agg-lat>\n", 
					net->gpsdata.aggregate_lat);
			fprintf(xmlfile, "      <agg-lon>%Lf</agg-lon>\n", 
					net->gpsdata.aggregate_lon);
			fprintf(xmlfile, "      <agg-alt>%Lf</agg-alt>\n", 
					net->gpsdata.aggregate_alt);
			fprintf(xmlfile, "      <agg-points>%llu</agg-points>\n", 
					(long long unsigned int) net->gpsdata.aggregate_points);
			fprintf(xmlfile, "    </gps-info>\n");
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
		fprintf(xmlfile, "    <datasize>%llu</datasize>\n", 
				(long long unsigned int) net->datasize);
		fprintf(xmlfile, "    <cdp-device>%s</cdp-device>\n",
				SanitizeXML(net->cdp_dev_id).c_str());
		fprintf(xmlfile, "    <cdp-portid>%s</cdp-portid>\n",
				SanitizeXML(net->cdp_port_id).c_str());

		int clinum = 0;

		// Get the client range pairs and print them out
		pair<multimap<mac_addr, Netracker::tracked_client *>::const_iterator, 
			multimap<mac_addr, Netracker::tracked_client *>::const_iterator> apclis = 
			trackcli.equal_range(net->bssid);
		for (y = apclis.first; y != apclis.second; ++y) {
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
					"wep=\"%s\" first-time=\"%.24s\" last-time=\"%.24s\">\n",
					clinum, ctype.c_str(), cli->cryptset ? "true" : "false",
					ctime(&(cli->first_time)), ctime(&(cli->last_time)));

			fprintf(xmlfile, "      <client-mac>%s</client-mac>\n", 
					cli->mac.Mac2String().c_str());

			fprintf(xmlfile, "      <client-channel>%d</client-channel>\n", 
					cli->channel);
			fprintf(xmlfile, "      <client-maxrate>%2.1f</client-maxrate>\n", 
					cli->maxrate);
			fprintf(xmlfile, "      <client-maxseenrate>%ld</client-maxseenrate>\n",
					(long) cli->snrdata.maxseenrate * 100);

			if (cli->snrdata.carrierset & (1 << (int) carrier_80211b))
				fprintf(xmlfile, "      <client-carrier>IEEE 802.11b"
						"</client-carrier>\n");
			if (cli->snrdata.carrierset & (1 << (int) carrier_80211bplus))
				fprintf(xmlfile, "      <client-carrier>IEEE 802.11b+"
						"</client-carrier>\n");
			if (cli->snrdata.carrierset & (1 << (int) carrier_80211a))
				fprintf(xmlfile, "      <client-carrier>IEEE 802.11a"
						"</client-carrier>\n");
			if (cli->snrdata.carrierset & (1 << (int) carrier_80211g))
				fprintf(xmlfile, "      <client-carrier>IEEE 802.11g"
						"</client-carrier>\n");
			if (cli->snrdata.carrierset & (1 << (int) carrier_80211fhss))
				fprintf(xmlfile, "      <client-carrier>IEEE 802.11 FHSS"
						"</client-carrier>\n");
			if (cli->snrdata.carrierset & (1 << (int) carrier_80211dsss))
				fprintf(xmlfile, "      <client-carrier>IEEE 802.11 DSSS"
						"</client-carrier>\n");

			if (cli->snrdata.encodingset & (1 << (int) encoding_cck))
				fprintf(xmlfile, "      <client-encoding>CCK</client-encoding>\n");
			if (cli->snrdata.encodingset & (1 << (int) encoding_pbcc))
				fprintf(xmlfile, "      <client-encoding>PBCC</client-encoding>\n");
			if (cli->snrdata.encodingset & (1 << (int) encoding_ofdm))
				fprintf(xmlfile, "      <client-encoding>OFDM</client-encoding>\n");

			if (cli->cryptset == 0)
				fprintf(xmlfile, "      <client-encryption>None"
						"</client-encryption>\n");
			if (cli->cryptset & crypt_wep)
				fprintf(xmlfile, "      <client-encryption>WEP"
						"</client-encryption>\n");
			if (cli->cryptset & crypt_layer3)
				fprintf(xmlfile, "      <client-encryption>Layer3"
						"</client-encryption>\n");
			if (cli->cryptset & crypt_wep40)
				fprintf(xmlfile, "      <client-encryption>WEP40"
						"</client-encryption>\n");
			if (cli->cryptset & crypt_wep104)
				fprintf(xmlfile, "      <client-encryption>WEP104"
						"</client-encryption>\n");
			if (cli->cryptset & crypt_tkip)
				fprintf(xmlfile, "      <client-encryption>TKIP"
						"</client-encryption>\n");
			if (cli->cryptset & crypt_wpa)
				fprintf(xmlfile, "      <client-encryption>WPA"
						"</client-encryption>\n");
			if (cli->cryptset & crypt_psk)
				fprintf(xmlfile, "      <client-encryption>PSK"
						"</client-encryption>\n");
			if (cli->cryptset & crypt_aes_ocb)
				fprintf(xmlfile, "      <client-encryption>AES-OCB"
						"</client-encryption>\n");
			if (cli->cryptset & crypt_aes_ccm)
				fprintf(xmlfile, "      <client-encryption>AES-CCM"
						"</client-encryption>\n");
			if (cli->cryptset & crypt_leap)
				fprintf(xmlfile, "      <client-encryption>LEAP"
						"</client-encryption>\n");
			if (cli->cryptset & crypt_ttls)
				fprintf(xmlfile, "      <client-encryption>TTLS"
						"</client-encryption>\n");
			if (cli->cryptset & crypt_tls)
				fprintf(xmlfile, "      <client-encryption>TLS"
						"</client-encryption>\n");
			if (cli->cryptset & crypt_peap)
				fprintf(xmlfile, "      <client-encryption>PEAP"
						"</client-encryption>\n");
			if (cli->cryptset & crypt_isakmp)
				fprintf(xmlfile, "      <client-encryption>ISAKMP"
						"</client-encryption>\n");
			if (cli->cryptset & crypt_pptp)
				fprintf(xmlfile, "      <client-encryption>PPTP"
						"</client-encryption>\n");

			fprintf(xmlfile, "       <client-packets>\n");
			fprintf(xmlfile, "         <client-LLC>%d</client-LLC>\n", 
					cli->llc_packets);
			fprintf(xmlfile, "         <client-data>%d</client-data>\n", 
					cli->data_packets);
			fprintf(xmlfile, "         <client-crypt>%d</client-crypt>\n", 
					cli->crypt_packets);
			// TODO - DupeIV stuff?
			fprintf(xmlfile, "         <client-total>%d</client-total>\n", 
					cli->llc_packets + cli->data_packets);
			fprintf(xmlfile, "         <client-fragments>%d</client-fragments>\n", 
					cli->fragments);
			fprintf(xmlfile, "         <client-retries>%d</client-retries>\n", 
					cli->retries);
			fprintf(xmlfile, "       </client-packets>\n");

			fprintf(xmlfile, "       <client-datasize>%ld</client-datasize>\n", 
					(long int) cli->datasize);

			if (cli->gpsdata.gps_valid) {
				fprintf(xmlfile, "      <client-gps-info>\n");
				fprintf(xmlfile, "        <client-min-lat>%f</client-min-lat>\n", 
						cli->gpsdata.min_lat);
				fprintf(xmlfile, "        <client-min-lon>%f</client-min-lon>\n", 
						cli->gpsdata.min_lon);
				fprintf(xmlfile, "        <client-min-alt>%f</client-min-alt>\n", 
						cli->gpsdata.min_alt);
				fprintf(xmlfile, "        <client-min-spd>%f</client-min-spd>\n", 
						cli->gpsdata.min_spd);
				fprintf(xmlfile, "        <client-max-lat>%f</client-max-lat>\n", 
						cli->gpsdata.max_lat);
				fprintf(xmlfile, "        <client-max-lon>%f</client-max-lon>\n", 
						cli->gpsdata.max_lon);
				fprintf(xmlfile, "        <client-max-alt>%f</client-max-alt>\n", 
						cli->gpsdata.max_alt);
				fprintf(xmlfile, "        <client-max-spd>%f</client-max-spd>\n", 
						cli->gpsdata.max_spd);
				fprintf(xmlfile, "        <client-peak-lat>%f</client-peak-lat>\n", 
						cli->snrdata.peak_lat);
				fprintf(xmlfile, "        <client-peak-lon>%f</client-peak-lon>\n", 
						cli->snrdata.peak_lon);
				fprintf(xmlfile, "        <client-peak-alt>%f</client-peak-alt>\n", 
						cli->snrdata.peak_alt);
				fprintf(xmlfile, "        <client-agg-lat>%lld</client-agg-lat>\n", 
						(long long int) cli->gpsdata.aggregate_lat);
				fprintf(xmlfile, "        <client-agg-lon>%lld</client-agg-lon>\n", 
						(long long int) cli->gpsdata.aggregate_lon);
				fprintf(xmlfile, "        <client-agg-alt>%lld</client-agg-alt>\n", 
						(long long int) cli->gpsdata.aggregate_alt);
				fprintf(xmlfile, "        <client-agg-points>%lld"
						"</client-agg-points>\n", cli->gpsdata.aggregate_points);
				fprintf(xmlfile, "      </client-gps-info>\n");
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

				fprintf(xmlfile, "      <client-ip-address type=\"%s\">\n", 
						iptype.c_str());
				fprintf(xmlfile, "        <client-ip-block>%s"
						"</client-ip-block>\n", 
						inet_ntoa(cli->guess_ipdata.ip_addr_block));
				fprintf(xmlfile, "        <client-ip-netmask>%s"
						"</client-ip-netmask>\n",
						inet_ntoa(cli->guess_ipdata.ip_netmask));
				fprintf(xmlfile, "        <client-ip-gateway>%s"
						"</client-ip-gateway>\n",
						inet_ntoa(cli->guess_ipdata.ip_gateway));
				fprintf(xmlfile, "      </client-ip-address>\n");
			}

			fprintf(xmlfile, "      <cdp-device>%s</cdp-device>\n",
					SanitizeXML(cli->cdp_dev_id).c_str());
			fprintf(xmlfile, "      <cdp-portid>%s</cdp-portid>\n",
					SanitizeXML(cli->cdp_port_id).c_str());
			fprintf(xmlfile, "    </wireless-client>\n");

		}
			fprintf(xmlfile, "  </wireless-network>\n");

	}

	fprintf(xmlfile, "</detection-run>\n");

	fflush(xmlfile);

	return 1;
}


