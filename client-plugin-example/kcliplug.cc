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

#include <config.h>

#include <stdio.h>
#include <string.h>

#include <globalregistry.h>

#include <kis_panel_plugin.h>
#include <kis_panel_frontend.h>
#include <kis_panel_windows.h>

// Menu event plugin
int menu_callback(void *auxptr) {
	((KisPanelPluginData *) auxptr)->kpinterface->RaiseAlert("Example",
		"Example plugin raising alert since \n"
		"you picked it from the menu.\n");

	return 1;
}

// Init plugin gets called when plugin loads
extern "C" {
int panel_plugin_init(GlobalRegistry *globalreg, KisPanelPluginData *pdata) {
	_MSG("Loading kcli example plugin", MSGFLAG_INFO);

	pdata->mainpanel->AddPluginMenuItem("Example Plugin", menu_callback, pdata);

	return 1;
}
}

