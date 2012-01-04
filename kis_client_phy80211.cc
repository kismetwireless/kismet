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

Client_Phy80211::Client_Phy80211(GlobalRegistry *in_globalreg, Client_Devicetracker *in_tracker,
								 int in_phyid) : Client_Phy_Handler(in_globalreg, in_tracker, in_phyid) {
	_MSG("Making strong Phy80211 client\n", MSGFLAG_INFO);
	phyname = "IEEE802.11";
}

void Client_Phy80211::NetClientConfigure(KisNetClient *in_cli, int in_recon) {

}

void Client_Phy80211::NetClientAdd(KisNetClient *in_cli, int add) {

}

