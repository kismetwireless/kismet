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

#include "kis_panel_widgets.h"
#include "kis_panel_windows.h"
#include "kis_panel_frontend.h"

KisPanelInterface::KisPanelInterface() {
	fprintf(stderr, "FATAL OOPS: KisPanelInterface not called with globalreg\n");
	exit(-1);
}

KisPanelInterface::KisPanelInterface(GlobalRegistry *in_globalreg) :
	PanelInterface(in_globalreg) {
	globalreg = in_globalreg;

}

KisPanelInterface::~KisPanelInterface() {
	for (unsigned int x = 0; x < client_vec.size(); x++)
		delete client_vec[x];
}

int KisPanelInterface::AddNetClient(string in_host, int in_reconnect) {
	KisNetClient *netcl = new KisNetClient(globalreg);

	if (netcl->Connect(in_host, in_reconnect) < 0)
		return -1;

	client_vec.push_back(netcl);

	return 1;
}

#endif

