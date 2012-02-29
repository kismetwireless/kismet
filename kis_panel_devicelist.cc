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

// Panel has to be here to pass configure, so just test these
#if (defined(HAVE_LIBNCURSES) || defined (HAVE_LIBCURSES))

#include "kis_panel_devicelist.h"
#include "kis_panel_windows.h"
#include "kis_panel_frontend.h"
#include "kis_panel_sort.h"
#include "kis_panel_widgets.h"

#include "soundcontrol.h"

void KDL_TIME(CLIPROTO_CB_PARMS) {
	((Kis_Devicelist *) auxptr)->Proto_TIME();
}

void KDL_AddCli(KPI_ADDCLI_CB_PARMS) {
	((Kis_Devicelist *) auxptr)->NetClientAdd(netcli, add);
}

void KDL_ConfigureCli(CLICONF_CB_PARMS) {
	((Kis_Devicelist *) auxptr)->NetClientConfigure(kcli, recon);
}

void kdl_devicerx_hook(kis_tracked_device *device, void *aux, 
					   GlobalRegistry *globalreg) {
	((Kis_Devicelist *) aux)->DeviceRX(device);
}

string KDL_Common_Column_Cb(KDL_COLUMN_PARMS) {
	return ((Kis_Devicelist *) aux)->CommonColumn(device, columnid, header);
}

Kis_Devicelist::Kis_Devicelist(GlobalRegistry *in_globalreg, Kis_Panel *in_panel) :
	Kis_Panel_Component(in_globalreg, in_panel) {

	globalreg->InsertGlobal("MAIN_DEVICELIST", this);

	kpinterface = in_panel->FetchPanelInterface();

	devicetracker = (Client_Devicetracker *) globalreg->FetchGlobal("CLIENT_DEVICE_TRACKER");

	if (devicetracker == NULL) {
		fprintf(stderr, "FATAL OOPS: Missing devicetracker in devicelist\n");
		exit(1);
	}

	cli_addref = kpinterface->Add_NetCli_AddCli_CB(KDL_AddCli, (void *) this);

	devcomp_ref_common = devicetracker->RegisterDeviceComponent("COMMON");

	draw_dirty = false;

	newdevref = devicetracker->RegisterDevicerxCallback(kdl_devicerx_hook, this);

	viewable_lines = 0;
	viewable_cols = 0;

	first_line = last_line = selected_line = hpos = 0;

	next_column_id = 1;

	// Register all our local columns
	col_active = RegisterColumn("Active", "Recently active", 1,
								LABEL_POS_LEFT, KDL_Common_Column_Cb, this, false);
	col_name = RegisterColumn("Name", "Name", 20,
							  LABEL_POS_LEFT, KDL_Common_Column_Cb, this, false);
	col_phy = RegisterColumn("Phy", "Phy", 10,
							 LABEL_POS_LEFT, KDL_Common_Column_Cb, this, false);
	col_addr = RegisterColumn("Address", "MAC or Identifier", 17,
							  LABEL_POS_LEFT, KDL_Common_Column_Cb, this, false);
	col_type = RegisterColumn("Type", "Device type", 10,
							  LABEL_POS_LEFT, KDL_Common_Column_Cb, this, false);
	col_basictype = RegisterColumn("BasicType", "Basic type", 10,
								   LABEL_POS_LEFT, KDL_Common_Column_Cb, this, false);
	col_packets = RegisterColumn("Packets", "Packets", 5,
								 LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_llc = RegisterColumn("LinkPackets", "Link packets", 5,
							 LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_error = RegisterColumn("ErrorPackets", "Error packets", 5,
							   LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_data = RegisterColumn("DataPackets", "Data packets", 5,
							  LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_crypt = RegisterColumn("CryptPackets", "Encrypted packets", 5,
							   LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_datasize = RegisterColumn("Datasize", "Data size", 6,
								  LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_newpackets = RegisterColumn("Packetrate", "Packet rate", 5,
									LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_channel = RegisterColumn("Channel", "Channel", 4,
								 LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_freq = RegisterColumn("Frequency", "Frequency", 4,
							  LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_alerts = RegisterColumn("Alerts", "Number of alerts", 3,
								LABEL_POS_RIGHT, KDL_Common_Column_Cb, this, false);
	col_manuf = RegisterColumn("Manuf", "Manufacturer", 12,
							   LABEL_POS_LEFT, KDL_Common_Column_Cb, this, false);

	ParseColumnConfig();

	string viewmode = kpinterface->prefs->FetchOpt("MAIN_VIEWSTYLE");

	if (viewmode == "network")
		display_mode = KDL_DISPLAY_NETWORKS;
	else if (viewmode == "device")
		display_mode = KDL_DISPLAY_DEVICES;
	else
		display_mode = KDL_DISPLAY_NETWORKS;
}

void Kis_Devicelist::ParseColumnConfig() {
	string cols = "active,phy,name,type,address,packets,datasize,channel,alerts";

	vector<string> toks = StrTokenize(cols, ",");
	string t;

	configured_column_vec.clear();

	for (unsigned int x = 0; x < toks.size(); x++) {
		t = StrLower(toks[x]);
		bool set = 0;

		// Sucks but only happens rarely
		for (map<int, kdl_column *>::iterator i = registered_column_map.begin();
			 i != registered_column_map.end(); ++i) {
			if (StrLower(i->second->name) == t && !i->second->subcolumn) {
				set = true;
				configured_column_vec.push_back(i->second);
				break;
			}
		}

		if (!set) {
			_MSG("Unknown column '" + t + "'", MSGFLAG_INFO);
		}
	}
}

Kis_Devicelist::~Kis_Devicelist() {
	globalreg->InsertGlobal("MAIN_DEVICELIST", NULL);
	devicetracker->RemoveDevicerxCallback(newdevref);
	kpinterface->Remove_Netcli_AddCli_CB(cli_addref);
	kpinterface->Remove_All_Netcli_Conf_CB(KDL_ConfigureCli);
}

void Kis_Devicelist::SetViewMode(int in_mode) {
	if (in_mode != display_mode) {
		display_mode = in_mode;
		draw_dirty = 1;
		RefreshDisplayList();
	}
}

void Kis_Devicelist::NetClientAdd(KisNetClient *in_cli, int add) {
	// TODO figure out how to resolve PHY#s on reconnect
	if (add == 0)
		return;

	in_cli->AddConfCallback(KDL_ConfigureCli, 1, this);
}

void Kis_Devicelist::NetClientConfigure(KisNetClient *in_cli, int in_recon) {
	if (in_cli->RegisterProtoHandler("TIME", "timesec",
									 KDL_TIME, this) < 0) {
		_MSG("KDL couldn't register *TIME?  Something is broken, badly.",
			 MSGFLAG_ERROR);
		in_cli->KillConnection();
		return;
	}
}

void Kis_Devicelist::DeviceRX(kis_tracked_device *device) {
	map<mac_addr, kdl_display_device *>::iterator ddmi =
		display_dev_map.find(device->key);

	// TODO - intelligent add to display list, etc
	if (ddmi == display_dev_map.end()) {
		kdl_display_device *dd = new kdl_display_device;
		dd->device = device;
		dd->dirty = true;

		display_dev_map[device->key] = dd;
		display_dev_vec.push_back(dd);

		// Determine if we put it in our draw vec
		kis_device_common *common =
			(kis_device_common *) device->fetch(devcomp_ref_common);

		// No common?  Fail
		if (common == NULL) {
			// fprintf(stderr, "debug - DeviceRX no common\n");
			return;
		}

		// Don't add it to our device list if it's not a network
		// If we're in device mode we get everything so don't filter
		if (display_mode == KDL_DISPLAY_NETWORKS &&
			!(common->basic_type_set & KIS_DEVICE_BASICTYPE_AP)) {
			// fprintf(stderr, "debug - Devicerx display network, type not network\n");
			return;
		}

		draw_vec.push_back(dd);
	} else {
		ddmi->second->dirty = 1;
	}
}

int Kis_Devicelist::RegisterColumn(string in_name, string in_desc, 
								   int in_width, KisWidget_LabelPos in_align,
								   KDL_Column_Callback in_cb, void *in_aux,
								   bool in_sub) {
	for (map<int, kdl_column *>::iterator x = registered_column_map.begin();
		 x != registered_column_map.end(); ++x) {
		if (StrLower(x->second->name) == StrLower(in_name) &&
			x->second->subcolumn == in_sub)
			return x->first;
	}

	next_column_id++;

	kdl_column *newc = new kdl_column;
	newc->name = in_name;
	newc->description = in_desc;
	newc->width = in_width;
	newc->subcolumn = in_sub;
	newc->id = next_column_id;
	newc->callback = in_cb;
	newc->cb_aux = in_aux;

	registered_column_map[newc->id] = newc;

	return newc->id;
}

void Kis_Devicelist::RemoveColumn(int in_id) {
	if (registered_column_map.find(in_id) != registered_column_map.end()) {
		kdl_column *c = registered_column_map[in_id];

		for (unsigned int x = 0; x < configured_column_vec.size(); x++) {
			if (configured_column_vec[x] == c) {
				configured_column_vec.erase(configured_column_vec.begin() + x);
				x = 0;
			}
		}
		
		for (unsigned int x = 0; x < configured_subcolumn_vec.size(); x++) {
			if (configured_subcolumn_vec[x] == c) {
				configured_subcolumn_vec.erase(configured_subcolumn_vec.begin() + x);
				x = 0;
			}
		}

		delete registered_column_map[in_id];
		registered_column_map.erase(in_id);
	}
}

void Kis_Devicelist::DrawComponent() {
	if (visible == 0)
		return;

	/*
	Kis_Panel_Specialtext::Mvwaddnstr(window, sy, sx, "\004uDevice list\004U", 
									  lx - 1, parent_panel);
									  */

	string hdr = " ";

	for (unsigned int x = hpos; x < configured_column_vec.size(); x++) {
		/*
		if (hdr.length() + configured_column_vec[x]->width > viewable_cols)
			break;
			*/

		hdr += "\004u" +
			(*(configured_column_vec[x]->callback))(
				NULL,
				configured_column_vec[x]->cb_aux,
				globalreg,
				configured_column_vec[x]->id,
				true) + 
			"\004U ";
	}

	Kis_Panel_Specialtext::Mvwaddnstr(window, sy, sx, hdr.c_str(), 
									  lx - 1, parent_panel);

	unsigned int dy = 0;
	string display_line;
	for (unsigned int x = first_line; dy < viewable_lines && 
		 x < draw_vec.size(); x++) {

		display_line = " ";

		for (unsigned int c = hpos; c < configured_column_vec.size(); c++) {
			if (display_line.length() + 
				configured_column_vec[c]->width > viewable_cols)
				break;

			display_line += 
				(*(configured_column_vec[c]->callback))(
						draw_vec[x],
						configured_column_vec[c]->cb_aux,
						globalreg,
						configured_column_vec[c]->id,
						false) + 
				" ";
		}

		dy++;

		if (selected_line == x && active)
			wattron(window, WA_REVERSE);

		Kis_Panel_Specialtext::Mvwaddnstr(window, sy + dy, sx, 
										  display_line, 
										  lx - 1, parent_panel);

		if (selected_line == x && active)
			wattroff(window, WA_REVERSE);

		last_line = x;

	}
}

void Kis_Devicelist::Activate(int subcomponent) {
	// _MSG("Activate devlist", MSGFLAG_INFO);
	active = 1;
}

void Kis_Devicelist::Deactivate() {
	active = 0;
}

void Kis_Devicelist::Proto_TIME() {
	DrawComponent();

	for (unsigned int x = 0; x < display_dev_vec.size(); x++) {
		display_dev_vec[x]->dirty = false;
	}
}

int Kis_Devicelist::KeyPress(int in_key) {
	if (visible == 0)
		return 0;

	// _MSG("Keypress devlist", MSGFLAG_INFO);

	if (in_key == KEY_DOWN || in_key == '+') {
		if (selected_line < first_line || selected_line > last_line) {
			selected_line = first_line;
			return 0;
		}

		// If we're at the bottom and can go further, slide the selection
		// and the first line down
		if (selected_line == last_line &&
			last_line < draw_vec.size() - 1) {
			selected_line++;
			first_line++;
		} else if (selected_line != last_line) {
			// Otherwise we just slide the selected line down
			selected_line++;
		}
	} else if (in_key == KEY_UP || in_key == '-') {
		if (selected_line < first_line || selected_line > last_line) {
			selected_line = first_line;
			return 0;
		}

		// if we're at the top and can go further, slide the selection
		// and first line of our view up
		if (selected_line == first_line && first_line > 0) {
			selected_line--;
			first_line--;
		} else if (selected_line != first_line) {
			// just move the selected line up
			selected_line--;
		}
	}

	return 0;
}

int Kis_Devicelist::MouseEvent(MEVENT *mevent) {
	return 0;
}

void Kis_Devicelist::SetPosition(int isx, int isy, int iex, int iey) {
	Kis_Panel_Component::SetPosition(isx, isy, iex, iey);

	viewable_lines = ly - 1;
	viewable_cols = ex;
}

string Kis_Devicelist::CommonColumn(kdl_display_device *in_dev, int in_columnid, 
									bool header) {
	char hdr[16];
	char buf[64];
	kdl_column *col = NULL;

	map<int, kdl_column *>::iterator ci = registered_column_map.find(in_columnid);

	if (ci == registered_column_map.end())
		return "INVALID";

	kis_device_common *common = NULL;

	col = ci->second;

	if (col->alignment == LABEL_POS_LEFT)
		snprintf(hdr, 16, "%%%ds", col->width);
	else
		snprintf(hdr, 16, "%%-%d.%ds", col->width, col->width);

	snprintf(buf, 64, hdr, "Unk");

	if (!header) {
		if (in_dev != NULL && in_dev->device != NULL)
			common = (kis_device_common *) in_dev->device->fetch(devcomp_ref_common);

		if (common == NULL) {
			snprintf(buf, 64, hdr, "NULL");
			return buf;
		}
	}

	if (in_columnid == col_active) {
		if (header) {
			snprintf(buf, 64, "A");
		} else {
			int oft = globalreg->timestamp.tv_sec - common->last_time;
			
			if (oft < 3)
				snprintf(buf, 64, "!");
			else if (oft < 6)
				snprintf(buf, 64, ".");
			else
				snprintf(buf, 64, " ");
		}
	} else if (in_columnid == col_phy) {
		if (header) {
			snprintf(buf, 64, hdr, "Phy");
		} else {
			snprintf(buf, 64, hdr, devicetracker->FetchPhyName(in_dev->device->phy_type).c_str());
		}
	} else if (in_columnid == col_addr) {
		if (header) {
			snprintf(buf, 64, hdr, "Addr");
		} else {
			snprintf(buf, 64, hdr, in_dev->device->key.Mac2String().c_str());
		}
	} else if (in_columnid == col_name) {
		if (header) {
			snprintf(buf, 64, hdr, "Name");
		} else {
			snprintf(buf, 64, hdr, common->name.c_str());
		}
	} else if (in_columnid == col_type) {
		if (header) {
			snprintf(buf, 64, hdr, "Type");
		} else {
			snprintf(buf, 64, hdr, common->type_string.c_str());
		}
	} else if (in_columnid == col_basictype) {
		if (header) {
			snprintf(buf, 64, hdr, "Basic");
		} else {
			if (common->basic_type_set == KIS_DEVICE_BASICTYPE_DEVICE)
				snprintf(buf, 64, hdr, "Device");
			else if (common->basic_type_set == KIS_DEVICE_BASICTYPE_AP)
				snprintf(buf, 64, hdr, "AP");
			else if (common->basic_type_set == KIS_DEVICE_BASICTYPE_WIRED)
				snprintf(buf, 64, hdr, "Wired");
			else if (common->basic_type_set == KIS_DEVICE_BASICTYPE_CLIENT)
				snprintf(buf, 64, hdr, "Client");
		}
	} else if (in_columnid == col_packets) {
		if (header) {
			snprintf(buf, 64, hdr, "Pkts");
		} else {
			snprintf(buf, 64, hdr, IntToString(common->packets).c_str());
		}
	} else if (in_columnid == col_llc) {
		if (header) {
			snprintf(buf, 64, hdr, "Link");
		} else {
			snprintf(buf, 64, hdr, IntToString(common->llc_packets).c_str());
		}
	} else if (in_columnid == col_error) {
		if (header) {
			snprintf(buf, 64, hdr, "Err");
		} else {
			snprintf(buf, 64, hdr, IntToString(common->error_packets).c_str());
		}
	} else if (in_columnid == col_data) {
		if (header) {
			snprintf(buf, 64, hdr, "Data");
		} else {
			snprintf(buf, 64, hdr, IntToString(common->data_packets).c_str());
		}
	} else if (in_columnid == col_crypt) {
		if (header) {
			snprintf(buf, 64, hdr, "Crypt");
		} else {
			snprintf(buf, 64, hdr, IntToString(common->crypt_packets).c_str());
		}
	} else if (in_columnid == col_datasize) {
		if (header) {
			snprintf(buf, 64, hdr, "Size");
		} else {
			if (common->datasize < 1024)
				snprintf(buf, 64, hdr, 
						 string(IntToString(common->datasize) + "B").c_str());
			else if (common->datasize < (1024 * 1024)) 
				snprintf(buf, 64, hdr,
						 string(IntToString(common->datasize / 1024) + "K").c_str());
			else if (common->datasize < (1024 * 1024 * 1024))
				snprintf(buf, 64, hdr,
						 string(IntToString(common->datasize / 1024 / 1024) + 
								"M").c_str());
			else
				snprintf(buf, 64, hdr,
						 string(IntToString(common->datasize / 1024 / 1024 / 1024) +
								"G").c_str());
		}
	} else if (in_columnid == col_newpackets) {
		if (header) 
			snprintf(buf, 64, hdr, "New");
		else
			snprintf(buf, 64, hdr, IntToString(common->new_packets).c_str());
	} else if (in_columnid == col_channel) {
		if (header)
			snprintf(buf, 64, hdr, "Chan");
		else
			snprintf(buf, 64, hdr, IntToString(common->channel).c_str());
	} else if (in_columnid == col_freq) {
		if (header)
			snprintf(buf, 64, hdr, "Freq");
		else
			snprintf(buf, 64, hdr, IntToString(common->frequency).c_str());
	} else if (in_columnid == col_alerts) {
		if (header)
			snprintf(buf, 64, hdr, "Alrt");
		else
			snprintf(buf, 64, hdr, IntToString(common->alert).c_str());
	} else if (in_columnid == col_manuf) {
		if (header)
			snprintf(buf, 64, hdr, "Manuf");
		else
			snprintf(buf, 64, hdr, common->manuf.c_str());
	} else if (in_columnid == col_signal) {
		if (header) {
			snprintf(buf, 64, hdr, "Sig");
		} else {

		}
	}

	return buf;
}

void Kis_Devicelist::RefreshDisplayList() {
	draw_vec.clear();

	fprintf(stderr, "debug - refreshing display list for view mode %d\n",
			display_mode);

	for (unsigned int x = 0; x < display_dev_vec.size(); x++) {
		// Determine if we put it in our draw vec
		kis_device_common *common =
			(kis_device_common *) display_dev_vec[x]->device->fetch(devcomp_ref_common);

		// No common?  Fail
		if (common == NULL) {
			fprintf(stderr, "debug - refresh, no common, skipping\n");
			continue;
		}

		// Don't add it to our device list if it's not a network
		// Devices get everything
		if (display_mode == KDL_DISPLAY_NETWORKS &&
			!(common->basic_type_set & KIS_DEVICE_BASICTYPE_AP)) {
			fprintf(stderr, "debug - network refresh, not an AP, skipping\n");
			continue;
		}

		draw_vec.push_back(display_dev_vec[x]);
		display_dev_vec[x]->dirty = 1;
	}
}


#endif // ncurses

