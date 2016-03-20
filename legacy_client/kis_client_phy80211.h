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

#ifndef __KIS_CLIENT_Phy80211_H__
#define __KIS_CLIENT_Phy80211_H__

#include "config.h"

#include "globalregistry.h"
#include "devicetracker.h"
#include "kis_clinetframe.h"
#include "kis_panel_widgets.h"
#include "kis_client_devicetracker.h"

class Kis_Devicelist;
class kdl_display_device;

class Client_Phy80211 : public Client_Phy_Handler {
public:
	Client_Phy80211() {
		fprintf(stderr, "FATAL OOPS: Client_Phy80211()\n");
		exit(1);
	}

	Client_Phy80211(GlobalRegistry *in_globalreg) : Client_Phy_Handler(in_globalreg) {
		phyname = "IEEE802.11";
		devcomp_ref_common = MAX_TRACKER_COMPONENTS;
		devcomp_ref_dot11 = MAX_TRACKER_COMPONENTS;
		PanelInitialized();
	}

	Client_Phy80211(GlobalRegistry *in_globalreg, Client_Devicetracker *in_tracker,
					int in_phyid);

	virtual Client_Phy80211 *CreatePhyHandler(GlobalRegistry *in_globalreg, 
											  Client_Devicetracker *in_tracker,
											  int in_phyid) {
		return new Client_Phy80211(in_globalreg, in_tracker, in_phyid);
	}

	virtual void NetClientConfigure(KisNetClient *in_cli, int in_recon);

	void Proto_DOT11SSID(CLIPROTO_CB_PARMS);
	void Proto_DOT11DEVICE(CLIPROTO_CB_PARMS);
	void Proto_DOT11CLIENT(CLIPROTO_CB_PARMS);

	virtual void PanelInitialized();

	string Dot11Column(kdl_display_device *in_dev, int columnid, bool header);

	virtual void PanelDetails(Kis_DevDetails_Panel *in_panel,
							  kis_tracked_device *in_dev);
	virtual void PanelDetailsText(Kis_Free_Text *in_textbox, 
								  kis_tracked_device *in_dev);

protected:
	Kis_Devicelist *devicelist;

	int devcomp_ref_dot11, devcomp_ref_common;

	string proto_dot11ssid_fields, proto_dot11device_fields, proto_dot11client_fields;
	int proto_dot11ssid_fields_num, proto_dot11device_fields_num, 
		proto_dot11client_fields_num;

	int col_dot11d;
	int col_sub_lastssid;
};


#endif
