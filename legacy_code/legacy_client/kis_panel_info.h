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

#ifndef __KIS_PANEL_NETWORK_H__
#define __KIS_PANEL_NETWORK_H__

#include "config.h"

// Panel has to be here to pass configure, so just test these
#if (defined(HAVE_LIBNCURSES) || defined (HAVE_LIBCURSES))

#include "kis_clinetframe.h"
#include "kis_panel_widgets.h"
#include "kis_panel_preferences.h"

enum info_items {
	info_elapsed, info_numnets, info_numpkts, info_pktrate, info_filtered 
};

extern const char *info_bits_details[][2];

// Infobits main info pane widget is derived from a packbox - we contain our 
// own sub-widgets and pack them into ourselves, and let all the other normal
// code take care of things like spacing and such.  Plugins can then append
// after the main info block.
class Kis_Info_Bits : public Kis_Panel_Packbox {
public:
	Kis_Info_Bits() {
		fprintf(stderr, "FATAL OOPS: Kis_Info_Bits()\n");
		exit(1);
	}
	Kis_Info_Bits(GlobalRegistry *in_globalreg, Kis_Panel *in_panel);
	virtual ~Kis_Info_Bits();

	void NetClientConfigure(KisNetClient *in_cli, int in_recon);
	void NetClientAdd(KisNetClient *in_cli, int add);
	void Proto_INFO(CLIPROTO_CB_PARMS);
	void Proto_TIME(CLIPROTO_CB_PARMS);

	void DrawComponent();

	int UpdatePrefs();

protected:
	int addref;

	KisPanelInterface *kpinterface;

	vector<int> infovec;
	map<int, Kis_Free_Text *> infowidgets;
	Kis_Free_Text *title;
	time_t first_time;
	time_t last_time;

	int num_networks;
	int num_packets;
	int packet_rate;
	int filtered_packets;

	int info_color_normal;

	string asm_time_fields, asm_info_fields;
	int asm_time_num, asm_info_num;
};

#endif // panel
#endif // header

