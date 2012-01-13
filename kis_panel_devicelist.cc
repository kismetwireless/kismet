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
}

Kis_Devicelist::~Kis_Devicelist() {
	globalreg->InsertGlobal("MAIN_DEVICELIST", NULL);
	devicetracker->RemoveDevicerxCallback(newdevref);
	kpinterface->Remove_Netcli_AddCli_CB(cli_addref);
	kpinterface->Remove_All_Netcli_Conf_CB(KDL_ConfigureCli);
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
	map<mac_addr, display_device *>::iterator ddmi =
		display_dev_map.find(device->key);

	// TODO - intelligent add to display list, etc
	if (ddmi == display_dev_map.end()) {
		display_device *dd = new display_device;
		dd->device = device;
		dd->dirty = true;

		display_dev_map[device->key] = dd;
		display_dev_vec.push_back(dd);
	} else {
		ddmi->second->dirty = 1;
	}
}

void Kis_Devicelist::DrawComponent() {
	if (visible == 0)
		return;

	Kis_Panel_Specialtext::Mvwaddnstr(window, sy, sx, "\004uDevice list\004U", 
									  lx - 1, parent_panel);

	unsigned int dy = 0;
	for (unsigned int x = 0; dy < viewable_lines && 
		 x < display_dev_vec.size(); x++) {

		if (!display_dev_vec[x]->dirty) {
			continue;
		}

		dy++;

		string devstr;
		kis_tracked_device *dev = display_dev_vec[x]->device;
		kis_device_common *com =
			(kis_device_common *) dev->fetch(devcomp_ref_common);

		if (com == NULL) {
			devstr = dev->key.Mac2String() + " " + IntToString(dev->phy_type) + " No common";
		} else {
			devstr = dev->key.Mac2String() + " " + IntToString(dev->phy_type) + " Common data";
		}

		Kis_Panel_Specialtext::Mvwaddnstr(window, sy + dy, sx, devstr, 
										  lx - 1, parent_panel);

	}

	if (dy == 0)
		Kis_Panel_Specialtext::Mvwaddnstr(window, sy + 1, sx, "No updated devices",
										  lx - 1, parent_panel);

}

void Kis_Devicelist::Activate(int subcomponent) {

}

void Kis_Devicelist::Deactivate() {

}

void Kis_Devicelist::Proto_TIME() {
	DrawComponent();

	for (unsigned int x = 0; x < display_dev_vec.size(); x++) {
		display_dev_vec[x]->dirty = false;
	}
}

int Kis_Devicelist::KeyPress(int in_key) {

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



#endif // ncurses

