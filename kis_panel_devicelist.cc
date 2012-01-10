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

Kis_Devicelist::Kis_Devicelist(GlobalRegistry *in_globalreg, Kis_Panel *in_panel) :
	Kis_Panel_Component(in_globalreg, in_panel) {

	kpinterface = in_panel->FetchPanelInterface();

}

#endif // ncurses

