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

#ifndef __KIS_PANEL_PLUGIN_H__
#define __KIS_PANEL_PLUGIN_H__

/* 
 * Kismet panel frontend plugin data
 *
 * This class is similar to the global registry.  It exports required
 * data from inside various panel frontends which plugins need access
 * to to get network lists, create panels, or add themselves to the 
 * plugin menu
 */

#include "globalregistry.h"

#include <string>

class KisPanelInterface;
class Kis_Panel;
class Kis_Main_Panel;

class KisPanelPluginData {
public:
	KisPanelInterface *kpinterface;
	Kis_Main_Panel *mainpanel;
	GlobalRegistry *globalreg;
	void *pluginaux;
};

/* Plugin hook definition.  This function is the only function which will
 * be called on a panel plugin.  The plugin is then responsible for registering
 * itself with the system. */
typedef int (*panel_plugin_hook)(GlobalRegistry *, KisPanelPluginData *);

struct panel_plugin_meta {
	string filename;
	string objectname;

	void *dlfileptr;
};

#endif

