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

void kdl_devicerx_hook(kis_tracked_device *device, void *aux, 
					   GlobalRegistry *globalreg) {
	((Kis_Devicelist *) aux)->DeviceRX(device);
}

Kis_Devicelist::Kis_Devicelist(GlobalRegistry *in_globalreg, Kis_Panel *in_panel) :
	Kis_Panel_Component(in_globalreg, in_panel) {

	kpinterface = in_panel->FetchPanelInterface();

	devicetracker = (Client_Devicetracker *) globalreg->FetchGlobal("CLIENT_DEVICE_TRACKER");

	if (devicetracker == NULL) {
		fprintf(stderr, "FATAL OOPS: Missing devicetracker in devicelist\n");
		exit(1);
	}

	draw_dirty = false;

	newdevref = devicetracker->RegisterDevicerxCallback(kdl_devicerx_hook, this);
}

Kis_Devicelist::~Kis_Devicelist() {
	devicetracker->RemoveDevicerxCallback(newdevref);
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

}

void Kis_Devicelist::Activate(int subcomponent) {

}

void Kis_Devicelist::Deactivate() {

}

int Kis_Devicelist::KeyPress(int in_key) {

	return 0;
}

int Kis_Devicelist::MouseEvent(MEVENT *mevent) {
	return 0;
}

void Kis_Devicelist::SetPosition(int isx, int isy, int iex, int iey) {

}



#endif // ncurses

