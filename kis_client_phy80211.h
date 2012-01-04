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
#include "kis_panel_network.h"
#include "kis_client_devicetracker.h"

class Client_Phy80211 : public Client_Phy_Handler {
public:
	Client_Phy80211() {
		fprintf(stderr, "FATAL OOPS: Client_Phy80211()\n");
		exit(1);
	}

	Client_Phy80211(GlobalRegistry *in_globalreg) : Client_Phy_Handler(in_globalreg) {
		phyname = "IEEE802.11";
	}

	Client_Phy80211(GlobalRegistry *in_globalreg, Client_Devicetracker *in_tracker,
					int in_phyid);

	virtual Client_Phy80211 *CreatePhyHandler(GlobalRegistry *in_globalreg, Client_Devicetracker *in_tracker,
											  int in_phyid) {
		return new Client_Phy80211(in_globalreg, in_tracker, in_phyid);
	}

	virtual void NetClientConfigure(KisNetClient *in_cli, int in_recon);
	virtual void NetClientAdd(KisNetClient *in_cli, int add);
};


#endif
