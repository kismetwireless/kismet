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

#ifndef __KIS_PANEL_DEVICELIST_H__
#define __KIS_PANEL_DEVICELIST_H__

#include "config.h"

// Panel has to be here to pass configure, so just test these
#if (defined(HAVE_LIBNCURSES) || defined (HAVE_LIBCURSES))

#include "netracker.h"
#include "kis_clinetframe.h"
#include "kis_panel_widgets.h"
#include "kis_panel_preferences.h"
#include "kis_client_devicetracker.h"

class Kis_Devicelist : public Kis_Panel_Component {
public:
	Kis_Devicelist() {
		fprintf(stderr, "FATAL OOPS: Kis_Devicelist()\n");
		exit(1);
	}

	Kis_Devicelist(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_Devicelist();

	virtual void DrawComponent();
	virtual void Activate(int subcomponent);
	virtual void Deactivate();

	virtual int KeyPress(int in_key);
	virtual int MouseEvent(MEVENT *mevent);

	virtual void SetPosition(int isx, int isy, int iex, int iey);

	void DeviceRX(kis_tracked_device *device);

protected:
	class display_device {
	public:
		kis_tracked_device *device;
		string display_line;
		string display_aux;
		bool dirty;
	};

	vector<display_device *> display_dev_vec;
	map<mac_addr, display_device *> display_dev_map;

	vector<display_device *> draw_vec;

	bool draw_dirty;

	int newdevref;

	KisPanelInterface *kpinterface;
	Client_Devicetracker *devicetracker;
};


#endif // ncurses

#endif
