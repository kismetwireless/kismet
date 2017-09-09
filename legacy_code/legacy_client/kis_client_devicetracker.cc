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
#include "kis_clinetframe.h"
#include "kis_panel_frontend.h"
#include "kis_panel_windows.h"
#include "kis_client_devicetracker.h"

void CDT_AddCli(KPI_ADDCLI_CB_PARMS) {
	((Client_Devicetracker *) auxptr)->NetClientAdd(netcli, add);
}

void CDT_ConfigureCli(CLICONF_CB_PARMS) {
	((Client_Devicetracker *) auxptr)->NetClientConfigure(kcli, recon);
}

void CDT_PHYMAP(CLIPROTO_CB_PARMS) {
	((Client_Devicetracker *) auxptr)->Proto_PHYMAP(globalreg, proto_string, 
													proto_parsed, srccli, 
													auxptr);
}

void CDT_DEVICE(CLIPROTO_CB_PARMS) {
	((Client_Devicetracker *) auxptr)->Proto_DEVICE(globalreg, proto_string,
													proto_parsed, srccli,
													auxptr);
}

void CDT_DEVTAG(CLIPROTO_CB_PARMS) {
	((Client_Devicetracker *) auxptr)->Proto_DEVTAG(globalreg, proto_string,
													proto_parsed, srccli,
													auxptr);
}

void CDT_DEVICEDONE(CLIPROTO_CB_PARMS) {
	((Client_Devicetracker *) auxptr)->Proto_DEVICEDONE(globalreg, proto_string,
													proto_parsed, srccli,
													auxptr);
}

const char *CDT_phymap_fields[] = {
	"phyid", "phyname", "packets", "datapackets", "errorpackets", 
	"filterpackets", "packetrate",
	NULL
};

const char *CDT_device_fields[] = {
	"phytype", "macaddr", "name", "typestring", "basictype", 
	"cryptstring", "basiccrypt",
	"firsttime", "lasttime",
	"packets", "llcpackets", "errorpackets",
	"datapackets", "cryptpackets", "filterpackets",
	"datasize", "newpackets", "channel", "frequency",
	"freqmhz", "manuf", 

	"gpsfixed",
	"minlat", "minlon", "minalt", "minspd",
	"maxlat", "maxlon", "maxalt", "maxspd",
	"signaldbm", "noisedbm", "minsignaldbm", "minnoisedbm",
	"signalrssi", "noiserssi", "minsignalrssi", "minnoiserssi",
	"maxsignalrssi", "maxnoiserssi",
	"bestlat", "bestlon", "bestalt",
	"agglat", "agglon", "aggalt", "aggpoints",

	NULL
};

const char *CDT_devtag_fields[] = { 
	"phytype", "macaddr", "tag", "value",
	NULL
};

const char *CDT_devicedone_fields[] = {
	"phytype", "macaddr",
	NULL
};

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

	proto_phymap_fields_num = TokenNullJoin(&proto_phymap_fields, CDT_phymap_fields);
	proto_device_fields_num = TokenNullJoin(&proto_device_fields, CDT_device_fields);
	proto_devtag_fields_num = TokenNullJoin(&proto_devtag_fields,
											CDT_devtag_fields);
	proto_devicedone_fields_num = 
		TokenNullJoin(&proto_devicedone_fields, CDT_devicedone_fields);

	cli_addref = kpi->Add_NetCli_AddCli_CB(CDT_AddCli, (void *) this);

	next_devicerx_id = 1;
	next_phyrx_id = 1;
}

Client_Devicetracker::~Client_Devicetracker() {
	for (map<int, observed_phy *>::iterator x = phy_handler_map.begin(); 
		 x != phy_handler_map.end(); ++x) {
		if (x->second->handler != NULL)
			delete x->second->handler;
	}

	globalreg->InsertGlobal("CLIENT_DEVICE_TRACKER", NULL);
	kpi->Remove_Netcli_AddCli_CB(cli_addref);
	kpi->Remove_All_Netcli_Conf_CB(CDT_ConfigureCli);
	kpi->Remove_All_Netcli_ProtoHandler("PHYMAP", CDT_PHYMAP, this);
	kpi->Remove_All_Netcli_ProtoHandler("DEVICE", CDT_DEVICE, this);
	kpi->Remove_All_Netcli_ProtoHandler("DEVTAG", CDT_DEVTAG, this);
	kpi->Remove_All_Netcli_ProtoHandler("DEVICEDONE", CDT_DEVICEDONE, this);
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

kis_tracked_device *Client_Devicetracker::FetchDevice(mac_addr in_mac) {
	map<mac_addr, kis_tracked_device *>::iterator tmi =
		tracked_map.find(in_mac);

	if (tmi == tracked_map.end())
		return NULL;

	return tmi->second;
}

void Client_Devicetracker::RegisterPhyHandler(Client_Phy_Handler *in_weak_handler) {
	// Look for an observed phy which hasn't got a handler record
	for (map<int, observed_phy *>::iterator x = phy_handler_map.begin();
		 x != phy_handler_map.end(); ++x) {
		if (x->second->handler != NULL)
			continue;
		if (x->second->phy_name == in_weak_handler->FetchPhyName()) {
			x->second->handler = 
				in_weak_handler->CreatePhyHandler(globalreg, this, x->second->phy_id);
			return;
		}
	}

	// Add it to the unassigned list in weak form
	unassigned_phy_vec.push_back(in_weak_handler);
}

Client_Phy_Handler *Client_Devicetracker::FetchPhyHandler(int in_phy) {
	map<int, observed_phy *>::iterator i = phy_handler_map.find(in_phy);

	if (i == phy_handler_map.end())
		return NULL;

	return i->second->handler;
}

string Client_Devicetracker::FetchPhyName(int in_phy) {
	map<int, observed_phy *>::iterator i = phy_handler_map.find(in_phy);

	if (i == phy_handler_map.end())
		return "Unknown";

	// Return name, not handler resolution, incase we don't have a 
	// client-side plugin enabled for this phy
	return i->second->phy_name;
}

string Client_Devicetracker::FetchDeviceComponentName(int in_id) {
	if (component_id_map.find(in_id) == component_id_map.end())
		return "<UNKNOWN>";

	return component_id_map[in_id];
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
	if (add == 0)
		return;

	in_cli->AddConfCallback(CDT_ConfigureCli, 1, this);
}

void Client_Devicetracker::NetClientConfigure(KisNetClient *in_cli, int in_recon) {
	_MSG("CDT connected", MSGFLAG_INFO);

	if (in_cli->RegisterProtoHandler("PHYMAP", proto_phymap_fields,
									 CDT_PHYMAP, this) < 0) {
		_MSG("Could not register *PHYMAP sentence; is this an old version of "
			 "Kismet you're trying to connect to?  Connection will be terminated.", 
			 MSGFLAG_ERROR);
		in_cli->KillConnection();
		return;
	}

	if (in_cli->RegisterProtoHandler("DEVICEDONE", proto_devicedone_fields,
									 CDT_DEVICEDONE, this) < 0) {
		_MSG("Could not register *DEVICEDONE sentence; is this an old version of "
			 "Kismet you're trying to connect to?  Connection will be terminated.", 
			 MSGFLAG_ERROR);
		in_cli->KillConnection();
		return;
	}

	if (in_cli->RegisterProtoHandler("DEVICE", proto_device_fields,
									 CDT_DEVICE, this) < 0) {
		_MSG("Could not register *DEVICE sentence; is this an old version of "
			 "Kismet you're trying to connect to?  Connection will be terminated.", 
			 MSGFLAG_ERROR);
		in_cli->KillConnection();
		return;
	}

	if (in_cli->RegisterProtoHandler("DEVTAG", proto_devtag_fields,
									 CDT_DEVTAG, this) < 0) {
		_MSG("Could not register *DEVTAG sentence; is this an old version of "
			 "Kismet you're trying to connect to?  Connection will be terminated.", 
			 MSGFLAG_ERROR);
		in_cli->KillConnection();
		return;
	}

	_MSG("CDT looking at phy handlers", MSGFLAG_INFO);
	for (map<int, observed_phy *>::iterator x = phy_handler_map.begin();
		 x != phy_handler_map.end(); ++x) {
		if (x->second->handler != NULL) {
			_MSG("Registering phyhandler network ", MSGFLAG_INFO);
			x->second->handler->NetClientConfigure(in_cli, in_recon);
		}
	}

}

int Client_Devicetracker::RegisterDevicerxCallback(DeviceRXEnableCB in_callback, void *in_aux) {
	devicerx_cb_rec *cbr = new devicerx_cb_rec;

	cbr->id = next_devicerx_id++;
	cbr->callback = in_callback;
	cbr->aux = in_aux;

	devicerx_cb_vec.push_back(cbr);

	return cbr->id;
}

void Client_Devicetracker::RemoveDevicerxCallback(int in_id) {
	for (unsigned int x = 0; x < devicerx_cb_vec.size(); x++) {
		if (devicerx_cb_vec[x]->id == in_id) {
			delete(devicerx_cb_vec[x]);
			devicerx_cb_vec.erase(devicerx_cb_vec.begin() + x);
			break;
		}
	}
}

int Client_Devicetracker::RegisterPhyrxCallback(PhyRXEnableCB in_callback, void *in_aux, bool on_any) {
	phyrx_cb_rec *cbr = new phyrx_cb_rec;

	cbr->id = next_phyrx_id++;
	cbr->callback = in_callback;
	cbr->aux = in_aux;
	cbr->on_any = on_any;

	phyrx_cb_vec.push_back(cbr);

	return cbr->id;
}

void Client_Devicetracker::RemovePhyrxCallback(int in_id) {
	for (unsigned int x = 0; x < phyrx_cb_vec.size(); x++) {
		if (phyrx_cb_vec[x]->id == in_id) {
			delete(phyrx_cb_vec[x]);
			phyrx_cb_vec.erase(phyrx_cb_vec.begin() + x);
			break;
		}
	}
}

void Client_Devicetracker::Proto_PHYMAP(CLIPROTO_CB_PARMS) {
	// _MSG("CDT proto_phymap", MSGFLAG_INFO);
	
	if (proto_parsed->size() < (unsigned int) proto_phymap_fields_num)
		return;

	int fnum = 0;

	int phy_id;
	int tint;

	bool new_phy = false;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &phy_id) != 1)
		return;

	map<int, observed_phy *>::iterator phmi;
	observed_phy *op = NULL;

	if ((phmi = phy_handler_map.find(phy_id)) == phy_handler_map.end()) {
		new_phy = true;

		op = new observed_phy();

		op->phy_id = phy_id;
		op->phy_name = (*proto_parsed)[fnum++].word;

		_MSG("Mapped new PHY: " + IntToString(op->phy_id) + " " + op->phy_name, MSGFLAG_INFO);

		for (unsigned int x = 0; x < unassigned_phy_vec.size(); x++) {
			if (unassigned_phy_vec[x]->FetchPhyName() == op->phy_name) {
				op->handler = 
					unassigned_phy_vec[x]->CreatePhyHandler(globalreg, this, op->phy_id);
				unassigned_phy_vec.erase(unassigned_phy_vec.begin() + x);
				break;
			}
		}

		// Subscribe it by sending it a network config event
		if (op->handler != NULL)
			op->handler->NetClientConfigure(srccli, 0);
		else
			_MSG("Server reports PHY type '" + op->phy_name + "', but there is no "
				 "support for it in this client.", MSGFLAG_INFO);

		phy_handler_map[op->phy_id] = op;

		phy_device_vec[op->phy_id] = new vector<kis_tracked_device *>;
	} else {
		op = phmi->second;

		// Look again for a handler, maybe a plugin got loaded
		if (op->handler == NULL) {
			for (unsigned int x = 0; x < unassigned_phy_vec.size(); x++) {
				if (unassigned_phy_vec[x]->FetchPhyName() == op->phy_name) {
					op->handler = 
						unassigned_phy_vec[x]->CreatePhyHandler(globalreg, this, op->phy_id);
					unassigned_phy_vec.erase(unassigned_phy_vec.begin() + x);
					break;
				}
			}

			// Subscribe it by sending it a network config event
			if (op->handler != NULL)
				op->handler->NetClientConfigure(srccli, 0);
		}

		fnum++;
	}

	// Local phy counts are directly reflected from the server phy data
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	phy_packets[phy_id] = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	phy_datapackets[phy_id] = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	phy_errorpackets[phy_id] = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	phy_filterpackets[phy_id] = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1)
		return;
	phy_packetdelta[phy_id] = tint;

	for (unsigned int x = 0; x < phyrx_cb_vec.size(); x++) {
		if (!phyrx_cb_vec[x]->on_any && !new_phy)
			continue;

		(*(phyrx_cb_vec[x]->callback))(phy_id, phyrx_cb_vec[x]->aux, globalreg);
	}
}

void Client_Devicetracker::Proto_DEVTAG(CLIPROTO_CB_PARMS) {
	if (proto_parsed->size() < (unsigned int) proto_devtag_fields_num)
		return;

	int fnum = 0;

	int phy_id;

	mac_addr tmac;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &phy_id) != 1)
		return;

	kis_tracked_device *device = NULL;
	kis_device_common *common = NULL;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &phy_id) != 1)
		return;

	// Check the PHY and bail early
	if (phy_handler_map.find(phy_id) == phy_handler_map.end()) {
		_MSG("CDT never saw mapped phy type " + IntToString(phy_id) + " throwing out *DEVTAG sentence", MSGFLAG_INFO);
		return;
	}

	// Get the device ref and look it up
	tmac = mac_addr((*proto_parsed)[fnum++].word.c_str());
	if (tmac.error) {
		return;
	}
	tmac.SetPhy(phy_id);

	map<mac_addr, kis_tracked_device *>::iterator ktdi = 
		tracked_map.find(tmac);

	if (ktdi == tracked_map.end()) {
		_MSG("Couldn't find device for tag", MSGFLAG_ERROR);
		return;
	} else {
		device = ktdi->second;
	}

	common = (kis_device_common *) device->fetch(devcomp_ref_common);

	// Don't insert the common record until we know we've got it all
	if (common == NULL) 
		return;

	string tag = StrLower((*proto_parsed)[fnum++].word);
	string value = MungeToPrintable((*proto_parsed)[fnum++].word);

	map<string, kis_tag_data *>::iterator ti = 
		common->arb_tag_map.find(tag);

	if (ti == common->arb_tag_map.end() && value != "") {
		kis_tag_data *data = new kis_tag_data();

		data->dirty = false;
		data->value = value;

		common->arb_tag_map[tag] = data;
	} else {
		if (value == "") {
			delete ti->second;
			common->arb_tag_map.erase(ti);
		} else {
			ti->second->value = value;
			ti->second->dirty = false;
		}
	}
}

void Client_Devicetracker::Proto_DEVICE(CLIPROTO_CB_PARMS) {
	// _MSG("CDT proto_device", MSGFLAG_INFO);
	
	if ((int) proto_parsed->size() < proto_device_fields_num)
		return;

	int fnum = 0;

	int phy_id;
	int tint;
	unsigned int tuint;
	long unsigned int tluint;
	float tfloat;
	mac_addr tmac;

	bool dev_new = false, common_new = false;

	vector<string> freqtoks;

	kis_tracked_device *device = NULL;
	kis_device_common *common = NULL;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &phy_id) != 1)
		return;

	// Check the PHY and bail early
	if (phy_handler_map.find(phy_id) == phy_handler_map.end()) {
		_MSG("CDT never saw mapped phy type " + IntToString(phy_id) + " throwing out *DEVICE sentence", MSGFLAG_INFO);
		return;
	}

	// Get the device ref and look it up
	tmac = mac_addr((*proto_parsed)[fnum++].word.c_str());
	if (tmac.error) {
		return;
	}
	tmac.SetPhy(phy_id);

	map<mac_addr, kis_tracked_device *>::iterator ktdi = 
		tracked_map.find(tmac);

	if (ktdi == tracked_map.end()) {
		// Make a new device, but do NOT insert it into tracked/dirty
		// until we get to the end and know we got a valid sentence!
		device = new kis_tracked_device(globalreg);

		device->key = tmac;
		device->phy_type = phy_id;

		dev_new = true;
	} else {
		device = ktdi->second;
	}

	common = (kis_device_common *) device->fetch(devcomp_ref_common);

	// Don't insert the common record until we know we've got it all
	if (common == NULL) {
		common = new kis_device_common;
		common->device = device;
		
		common_new = true;
	}

	common->name = (*proto_parsed)[fnum++].word;
	common->type_string = (*proto_parsed)[fnum++].word;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) 
		goto proto_fail;
	common->basic_type_set = tint;

	common->crypt_string = (*proto_parsed)[fnum++].word;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) 
		goto proto_fail;
	common->basic_crypt_set = tint;
	// fprintf(stderr, "%s cryptset %d\n", tmac.Mac2String().c_str(), tint);

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1) 
		goto proto_fail;
	common->first_time = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tuint) != 1) 
		goto proto_fail;
	common->last_time = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1) 
		goto proto_fail;
	common->packets = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1) 
		goto proto_fail;
	common->llc_packets = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1) 
		goto proto_fail;
	common->error_packets = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1) 
		goto proto_fail;
	common->data_packets = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1) 
		goto proto_fail;
	common->crypt_packets = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1) 
		goto proto_fail;
	common->filter_packets = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%lu", &tluint) != 1) 
		goto proto_fail;
	common->datasize = tluint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1) 
		goto proto_fail;
	common->new_packets = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) 
		goto proto_fail;
	common->channel = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1) 
		goto proto_fail;
	common->frequency = tuint;

	// Frequency packed field
	common->freq_mhz_map.clear();
	freqtoks = StrTokenize((*proto_parsed)[fnum++].word, "*");
	for (unsigned int fi = 0; fi < freqtoks.size(); fi++) {
		unsigned int freq, count;

		// Just ignore parse errors
		if (sscanf(freqtoks[fi].c_str(), "%u:%u", &freq, &count) != 2)
			continue;

		common->freq_mhz_map[freq] = count;
	}

	common->manuf = (*proto_parsed)[fnum++].word;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) 
		goto proto_fail;
	common->gpsdata.gps_valid = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		goto proto_fail;
	common->gpsdata.min_lat = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		goto proto_fail;
	common->gpsdata.min_lon = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		goto proto_fail;
	common->gpsdata.min_alt = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		goto proto_fail;
	common->gpsdata.min_spd = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		goto proto_fail;
	common->gpsdata.max_lat = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		goto proto_fail;
	common->gpsdata.max_lon = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		goto proto_fail;
	common->gpsdata.max_alt = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		goto proto_fail;
	common->gpsdata.max_spd = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) 
		goto proto_fail;
	common->snrdata.last_signal_dbm = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) 
		goto proto_fail;
	common->snrdata.last_noise_dbm = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) 
		goto proto_fail;
	common->snrdata.min_signal_dbm = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) 
		goto proto_fail;
	common->snrdata.min_noise_dbm = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) 
		goto proto_fail;
	common->snrdata.min_noise_dbm = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) 
		goto proto_fail;
	common->snrdata.last_signal_rssi = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) 
		goto proto_fail;
	common->snrdata.last_noise_rssi = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) 
		goto proto_fail;
	common->snrdata.min_signal_rssi = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &tint) != 1) 
		goto proto_fail;
	common->snrdata.min_noise_rssi = tint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		goto proto_fail;
	common->snrdata.peak_lat = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		goto proto_fail;
	common->snrdata.peak_lon = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		goto proto_fail;
	common->snrdata.peak_alt = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		goto proto_fail;
	common->gpsdata.aggregate_lat = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		goto proto_fail;
	common->gpsdata.aggregate_lon = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		goto proto_fail;
	common->gpsdata.aggregate_alt = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%lu", &tluint) != 1) 
		goto proto_fail;
	common->gpsdata.aggregate_points = tluint;

	if (common_new) {
		device->insert(devcomp_ref_common, common);
	} 
	
	if (dev_new) {
		tracked_map[device->key] = device;
		tracked_vec.push_back(device);
		phy_device_vec[phy_id]->push_back(device);
		// _MSG("CDT local tracking new device " + device->key.Mac2String(), MSGFLAG_INFO);
	}

	return;

proto_fail:
	_MSG("CDT failed to process *DEVICE", MSGFLAG_ERROR);
	if (common_new)
		delete common;
	if (dev_new)
		delete device;

	return;
}

void Client_Devicetracker::Proto_DEVICEDONE(CLIPROTO_CB_PARMS) {
	if (proto_parsed->size() < (unsigned int) proto_devicedone_fields_num)
		return;

	int fnum = 0;

	int phy_id;
	mac_addr tmac;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%d", &phy_id) != 1)
		return;

	// Check the PHY and bail early
	if (phy_handler_map.find(phy_id) == phy_handler_map.end()) {
		_MSG("CDT never saw mapped phy type " + IntToString(phy_id) + 
			 " throwing out *DEVICEDONE sentence", MSGFLAG_ERROR);
		return;
	}

	// Get the device ref and look it up
	tmac = mac_addr((*proto_parsed)[fnum++].word.c_str());
	if (tmac.error) {
		return;
	}
	tmac.SetPhy(phy_id);

	map<mac_addr, kis_tracked_device *>::iterator ktdi = 
		tracked_map.find(tmac);

	if (ktdi == tracked_map.end()) {
		_MSG("CDT never saw device " + tmac.Mac2String() + " but got devicedone?",
			 MSGFLAG_ERROR);
		return;
	}

	for (unsigned int x = 0; x < devicerx_cb_vec.size(); x++) {
		(*(devicerx_cb_vec[x]->callback))(ktdi->second, devicerx_cb_vec[x]->aux, globalreg);
	}
}

void Client_Devicetracker::PanelInitialized() {
	for (map<int, observed_phy *>::iterator x = phy_handler_map.begin();
		 x != phy_handler_map.end(); ++x) {
		if (x->second->handler != NULL) {
			x->second->handler->PanelInitialized();
		}
	}

	// They'll replace the columns when they're observed
	for (unsigned int x = 0; x < unassigned_phy_vec.size(); x++) {
		unassigned_phy_vec[x]->PanelInitialized();
	}

}

