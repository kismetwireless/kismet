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

#include "globalregistry.h"
#include "devicetracker.h"
#include "kis_panel_network.h"
#include "kis_client_devicetracker.h"
#include "kis_client_phy80211.h"

void CPD11_DOT11SSID(CLIPROTO_CB_PARMS) {
	((Client_Phy80211 *) auxptr)->Proto_DOT11SSID(globalreg, proto_string, 
												  proto_parsed, srccli, 
												  auxptr);
}

void CPD11_DOT11DEVICE(CLIPROTO_CB_PARMS) {
	((Client_Phy80211 *) auxptr)->Proto_DOT11DEVICE(globalreg, proto_string, 
													proto_parsed, srccli, 
													auxptr);
}

void CPD11_DOT11CLIENT(CLIPROTO_CB_PARMS) {
	((Client_Phy80211 *) auxptr)->Proto_DOT11CLIENT(globalreg, proto_string, 
													proto_parsed, srccli, 
													auxptr);
}

Client_Phy80211::Client_Phy80211(GlobalRegistry *in_globalreg, 
								 Client_Devicetracker *in_tracker,
								 int in_phyid) : Client_Phy_Handler(in_globalreg, 
													in_tracker, in_phyid) {
	phyname = "IEEE802.11";

	const char *CPD11_ssid_fields[] = {
		"bssidmac", "checksum", "type", "ssid", "beaconinfo",
		"cryptset", "cloaked", "firsttime", "lasttime",
		"beaconrate", "beacons", "channel", "dot11d",
		NULL
	};

	const char *CPD11_dot11device_fields[] = {
		"mac", "typeset", "txcrypt", "rxcrypt", "decrypted",
		"disconnects", "cdpdev", "cdpport",
		"fragments", "retries", "lastssid", 
		"lastssidcsum", "txdatasize", "rxdatasize", 
		"lastbssid", "dhcphost", "dhcpvendor",
		"eapid",
		NULL
	};

	const char *CPD11_dot11client_fields[] = {
		"mac", "bssidmac", "firsttime", "lasttime", 
		"decrypted", "txcrypt", "rxcrypt",
		"lastssid", "lastssidcsum", "cdpdev",
		"cdpport", "dhcphost", "dhcpvendor",
		"txdatasize", "rxdatasize", "manuf", 
		"eapid",
		NULL
	};

	devcomp_ref_common = devicetracker->RegisterDeviceComponent("COMMON");
	devcomp_ref_dot11 = devicetracker->RegisterDeviceComponent("DOT11_DEVICE");

	proto_dot11ssid_fields_num = TokenNullJoin(&proto_dot11ssid_fields, 
											   CPD11_ssid_fields);
	proto_dot11device_fields_num = TokenNullJoin(&proto_dot11device_fields,
												 CPD11_dot11device_fields);
	proto_dot11client_fields_num = TokenNullJoin(&proto_dot11client_fields,
												 CPD11_dot11client_fields);
}

void Client_Phy80211::NetClientConfigure(KisNetClient *in_cli, int in_recon) {
	if (in_cli->RegisterProtoHandler("DOT11DEVICE", proto_dot11device_fields,
									 CPD11_DOT11DEVICE, this) < 0) {
		_MSG("Could not register *DOT11DEVICE sentence; is this an old version of "
			 "Kismet you're trying to connect to?  Connection will be terminated.",
			 MSGFLAG_ERROR);
		in_cli->KillConnection();
		return;
	}

	if (in_cli->RegisterProtoHandler("DOT11SSID", proto_dot11ssid_fields,
									 CPD11_DOT11SSID, this) < 0) {
		_MSG("Could not register *DOT11SSID sentence; is this an old version of "
			 "Kismet you're trying to connect to?  Connection will be terminated.",
			 MSGFLAG_ERROR);
		in_cli->KillConnection();
		return;
	}

	if (in_cli->RegisterProtoHandler("DOT11CLIENT", proto_dot11client_fields,
									 CPD11_DOT11CLIENT, this) < 0) {
		_MSG("Could not register *DOT11CLIENT sentence; is this an old version of "
			 "Kismet you're trying to connect to?  Connection will be terminated.",
			 MSGFLAG_ERROR);
		in_cli->KillConnection();
		return;
	}

	_MSG("Registered 802.11 client phy components", MSGFLAG_INFO);
}

void Client_Phy80211::Proto_DOT11SSID(CLIPROTO_CB_PARMS) {
	if ((int) proto_parsed->size() < proto_dot11ssid_fields_num)
		return;

	int fnum = 0;

	int tint;
	unsigned int tuint;
	mac_addr tmac;

	map<uint32_t, dot11_ssid *>::iterator dsi;

	vector<string> dot11d;

	tmac = mac_addr((*proto_parsed)[fnum++].word.c_str());
	if (tmac.error) {
		return;
	}
	tmac.SetPhy(phyid);

	kis_tracked_device *device =
		devicetracker->FetchDevice(tmac);

	bool ssid_new = false;
	dot11_ssid *ssid = NULL;

	if (device == NULL)
		return;

	dot11_device *dot11dev =
		(dot11_device *) device->fetch(devcomp_ref_dot11);

	if (dot11dev == NULL)
		return;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1)
		goto proto_fail;
	
	dsi = dot11dev->ssid_map.find(tuint);

	if (dsi == dot11dev->ssid_map.end()) {
		ssid_new = true;
		ssid = new dot11_ssid();

		ssid->checksum = tuint;
	} else {
		ssid = dsi->second;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		goto proto_fail;
	ssid->type = (dot11_ssid_type) tint;

	ssid->ssid = (*proto_parsed)[fnum++].word;

	ssid->beacon_info = (*proto_parsed)[fnum++].word;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		goto proto_fail;
	ssid->cryptset = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		goto proto_fail;
	ssid->ssid_cloaked = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1)
		goto proto_fail;
	ssid->first_time = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1)
		goto proto_fail;
	ssid->last_time = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1)
		goto proto_fail;
	ssid->beaconrate = tuint;
	
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1)
		goto proto_fail;
	ssid->beacons = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		goto proto_fail;
	ssid->channel = tint;

	dot11d = StrTokenize((*proto_parsed)[fnum++].word, ":");

	ssid->dot11d_vec.clear();

	if (dot11d.size() >= 2) {
		ssid->dot11d_country = MungeToPrintable(dot11d[0]);

		for (unsigned int x = 1; x < dot11d.size(); x++) {
			dot11_11d_range_info ri;
			if (sscanf(dot11d[x].c_str(), "%u-%u-%u", &(ri.startchan), 
					   &(ri.numchan), &(ri.txpower)) != 3) {
				goto proto_fail;
			}

			ssid->dot11d_vec.push_back(ri);
		}
	}

	if (ssid_new) {
		dot11dev->ssid_map[ssid->checksum] = ssid;
	}

	return;

proto_fail:
	_MSG("PHYDOT11 failed to process *DOT11SSID", MSGFLAG_ERROR);
	if (ssid_new) {
		delete(ssid);
	}

	return;
}

void Client_Phy80211::Proto_DOT11DEVICE(CLIPROTO_CB_PARMS) {
	if ((int) proto_parsed->size() < proto_dot11ssid_fields_num)
		return;

	int fnum = 0;

	int tint;
	unsigned int tuint;
	unsigned long tulong;
	mac_addr tmac;

	tmac = mac_addr((*proto_parsed)[fnum++].word.c_str());
	if (tmac.error) {
		return;
	}
	tmac.SetPhy(phyid);

	kis_tracked_device *device =
		devicetracker->FetchDevice(tmac);

	if (device == NULL)
		return;

	bool dot11dev_new = false;

	dot11_device *dot11dev =
		(dot11_device *) device->fetch(devcomp_ref_dot11);

	if (dot11dev == NULL) {
		dot11dev_new = true;
		dot11dev = new dot11_device();
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1)
		goto proto_fail;
	dot11dev->type_set = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%lu", &tulong) != 1)
		goto proto_fail;
	dot11dev->tx_cryptset = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%lu", &tulong) != 1)
		goto proto_fail;
	dot11dev->rx_cryptset = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1)
		goto proto_fail;
	dot11dev->decrypted = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1)
		goto proto_fail;
	dot11dev->client_disconnects = tuint;

	dot11dev->cdp_dev_id = (*proto_parsed)[fnum++].word;

	dot11dev->cdp_port_id = (*proto_parsed)[fnum++].word;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1)
		goto proto_fail;
	dot11dev->fragments = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1)
		goto proto_fail;
	dot11dev->retries = tuint;

	dot11dev->lastssid_str = (*proto_parsed)[fnum++].word;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1)
		goto proto_fail;
	dot11dev->lastssid_csum = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%lu", &tulong) != 1)
		goto proto_fail;
	dot11dev->tx_datasize = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%lu", &tulong) != 1)
		goto proto_fail;
	dot11dev->rx_datasize = tuint;

	tmac = mac_addr((*proto_parsed)[fnum++].word.c_str());
	if (tmac.error) 
		goto proto_fail;
	tmac.SetPhy(phyid);
	dot11dev->last_bssid = tmac;

	dot11dev->dhcp_host = (*proto_parsed)[fnum++].word;

	dot11dev->dhcp_vendor = (*proto_parsed)[fnum++].word;

	dot11dev->eap_id = (*proto_parsed)[fnum++].word;

	if (dot11dev_new) {
		device->insert(devcomp_ref_dot11, dot11dev);
	}

	return;

proto_fail:
	_MSG("PHYDOT11 failed to process *DOT11DEVICE", MSGFLAG_ERROR);
	if (dot11dev_new) {
		delete(dot11dev);
	}

	return;

}

void Client_Phy80211::Proto_DOT11CLIENT(CLIPROTO_CB_PARMS) {

}

