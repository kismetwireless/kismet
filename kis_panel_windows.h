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

#ifndef __KIS_PANEL_WINDOWS_H__
#define __KIS_PANEL_WINDOWS_H__

#include "config.h"

// Panel has to be here to pass configure, so just test these
#if (defined(HAVE_LIBNCURSES) || defined (HAVE_LIBCURSES))

#include "globalregistry.h"
#include "kis_panel_widgets.h"

class Kis_Main_Panel : public Kis_Panel {
public:
	Kis_Main_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_Main_Panel() called w/out globalreg\n");
		exit(1);
	}
	Kis_Main_Panel(GlobalRegistry *in_globalreg);
	virtual ~Kis_Main_Panel();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();
	virtual int KeyPress(int in_key);

protected:
	int mn_file, mn_view, mn_sort, mn_tools;
	int mi_connect, mi_quit;
	int mi_showtext, mi_showfields, mi_showinput;

	Kis_Free_Text *ftxt;
	Kis_Field_List *fl;
	Kis_Single_Input *sinp;
	Kis_Scrollable_Table *sct;
};

class Kis_Connect_Panel : public Kis_Panel {
public:
	Kis_Connect_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_Connect_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_Connect_Panel(GlobalRegistry *in_globalreg);
	virtual ~Kis_Connect_Panel();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();
	virtual int KeyPress(int in_key);

protected:
	Kis_Single_Input *hostname;
	Kis_Single_Input *hostport;
	Kis_Button *okbutton;
	Kis_Button *cancelbutton;

	vector<Kis_Panel_Component *> tab_components;
	int tab_pos;
};

class Kis_ServerList_Panel : public Kis_Panel {
public:
	Kis_ServerList_Panel() {
		fprintf(stderr, "FATAL OOPS: Kis_ServerList_Panel called w/out globalreg\n");
		exit(1);
	}

	Kis_ServerList_Panel(GlobalRegistry *in_globalreg);
	virtual ~Kis_ServerList_Panel();

	virtual void Position(int in_sy, int in_sx, int in_y, int in_x);
	virtual void DrawPanel();
	virtual int KeyPress(int in_key);

protected:
	
};

#endif

#endif
