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
#include "kis_panel_frontend.h"
#include "kis_panel_windows.h"
#include "kis_client_devicetracker.h"

void CDT_AddCli(KPI_ADDCLI_CB_PARMS) {
	((Client_Devicetracker *) auxptr)->NetClientAdd(netcli, add);
}

void CDT_ConfigureCli(CLICONF_CB_PARMS) {
	((Client_Devicetracker *) auxptr)->NetClientConfigure(kcli, recon);
}

Client_Devicetracker::Client_Devicetracker(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	globalreg->InsertGlobal("CLIENT_DEVICE_TRACKER", this);

	next_componentid = 1;
	num_packets = num_datapackets = num_errorpackets =
		num_packetdelta = 0;

	devcomp_ref_common = RegisterDeviceComponent("COMMON");

	kpi = (KisPanelInterface *) globalreg->FetchGlobal("KIS_PANEL_INTERFACE");

	if (kpi == NULL) {
		fprintf(stderr, "FATAL OOPS: Missing KPI in Devicetracker\n");
		exit(1);
	}

	cli_addref = kpi->Add_NetCli_AddCli_CB(CDT_AddCli, (void *) this);
}

Client_Devicetracker::~Client_Devicetracker() {
	globalreg->InsertGlobal("CLIENT_DEVICE_TRACKER", NULL);
	kpi->Remove_Netcli_AddCli_CB(cli_addref);
	kpi->Remove_All_Netcli_Conf_CB(CDT_ConfigureCli);
}

int Client_Devicetracker::RegisterDeviceComponent(string in_component) {
	if (component_str_map.find(StrLower(in_component)) != component_str_map.end()) {
		return component_str_map[StrLower(in_component)];
	}

	int num = next_componentid++;

	component_str_map[StrLower(in_component)] = num;
	component_id_map[num] = StrLower(in_component);

	return num;
}

vector<kis_tracked_device *> *Client_Devicetracker::FetchDevices(int in_phy) {
	if (in_phy == KIS_PHY_ANY)
		return &tracked_vec;

	if (phy_device_vec.find(in_phy) == phy_device_vec.end())
		return NULL;

	return phy_device_vec[in_phy];
}

Client_Phy_Handler *Client_Devicetracker::FetchPhyHandler(int in_phy) {
	map<int, Client_Phy_Handler *>::iterator i = phy_handler_map.find(in_phy);

	if (i == phy_handler_map.end())
		return NULL;

	return i->second;
}

int Client_Devicetracker::FetchNumDevices(int in_phy) {
	int r = 0;

	if (in_phy == KIS_PHY_ANY)
		return tracked_map.size();

	for (unsigned int x = 0; x < tracked_vec.size(); x++) {
		if (tracked_vec[x]->phy_type == in_phy)
			r++;
	}

	return r;
}

int Client_Devicetracker::FetchNumPackets(int in_phy) {
	if (in_phy == KIS_PHY_ANY)
		return num_packets;

	map<int, int>::iterator i = phy_packets.find(in_phy);
	if (i != phy_packets.end())
		return i->second;

	return 0;
}

int Client_Devicetracker::FetchNumDatapackets(int in_phy) {
	if (in_phy == KIS_PHY_ANY)
		return num_datapackets;

	map<int, int>::iterator i = phy_datapackets.find(in_phy);
	if (i != phy_datapackets.end())
		return i->second;

	return 0;
}

int Client_Devicetracker::FetchNumCryptpackets(int in_phy) {
	int r = 0;

	kis_device_common *common;

	for (unsigned int x = 0; x < tracked_vec.size(); x++) {
		if (tracked_vec[x]->phy_type == in_phy || in_phy == KIS_PHY_ANY) {
			if ((common = 
				 (kis_device_common *) tracked_vec[x]->fetch(devcomp_ref_common)) != NULL)
				r += common->crypt_packets;
		}
	}

	return 0;
}

int Client_Devicetracker::FetchNumErrorpackets(int in_phy) {
	if (in_phy == KIS_PHY_ANY)
		return num_errorpackets;

	map<int, int>::iterator i = phy_errorpackets.find(in_phy);
	if (i != phy_errorpackets.end())
		return i->second;

	return 0;
}

int Client_Devicetracker::FetchPacketRate(int in_phy) {
	if (in_phy == KIS_PHY_ANY)
		return num_packetdelta;

	map<int, int>::iterator i = phy_packetdelta.find(in_phy);
	if (i != phy_packetdelta.end())
		return i->second;

	return 0;
}


void Client_Devicetracker::SetDeviceTag(mac_addr in_device, string in_tag, string in_data,
									   int in_persistent) {
	// TODO tags
}

void Client_Devicetracker::ClearDeviceTag(mac_addr in_device, string in_tag) {
	// TODO tags
}

void Client_Devicetracker::NetClientAdd(KisNetClient *in_cli, int add) {
	// TODO figure out how to resolve PHY#s
	if (add == 0)
		return;

	in_cli->AddConfCallback(CDT_ConfigureCli, 1, this);
}

void Client_Devicetracker::NetClientConfigure(KisNetClient *in_cli, int in_recon) {
	_MSG("CDT connected", MSGFLAG_INFO);
}


