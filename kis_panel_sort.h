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

#ifndef __KIS_PANEL_SORT_H__
#define __KIS_PANEL_SORT_H__

#include "config.h"

#include "kis_panel_network.h"
#include "kis_panel_frontend.h"

class KisNetlist_Sort_Type {
public:
	inline bool operator()(Kis_Display_NetGroup *x, 
						   Kis_Display_NetGroup *y) const {
		Netracker::tracked_network *xm = x->FetchNetwork();
		Netracker::tracked_network *ym = y->FetchNetwork();

		if (xm == NULL || ym == NULL)
			return 0;

		return xm->type < ym->type;
	}
};

class KisNetlist_Sort_Channel {
public:
	inline bool operator()(Kis_Display_NetGroup *x, 
						   Kis_Display_NetGroup *y) const {
		Netracker::tracked_network *xm = x->FetchNetwork();
		Netracker::tracked_network *ym = y->FetchNetwork();

		if (xm == NULL || ym == NULL)
			return 0;

		return xm->channel < ym->channel;
	}
};

class KisNetlist_Sort_First {
public:
	inline bool operator()(Kis_Display_NetGroup *x, 
						   Kis_Display_NetGroup *y) const {
		Netracker::tracked_network *xm = x->FetchNetwork();
		Netracker::tracked_network *ym = y->FetchNetwork();

		if (xm == NULL || ym == NULL)
			return 0;

		return xm->first_time < ym->first_time;
	}
};

class KisNetlist_Sort_FirstDesc {
public:
	inline bool operator()(Kis_Display_NetGroup *x, 
						   Kis_Display_NetGroup *y) const {
		Netracker::tracked_network *xm = x->FetchNetwork();
		Netracker::tracked_network *ym = y->FetchNetwork();

		if (xm == NULL || ym == NULL)
			return 0;

		return xm->first_time > ym->first_time;
	}
};

class KisNetlist_Sort_Last {
public:
	inline bool operator()(Kis_Display_NetGroup *x, 
						   Kis_Display_NetGroup *y) const {
		Netracker::tracked_network *xm = x->FetchNetwork();
		Netracker::tracked_network *ym = y->FetchNetwork();

		if (xm == NULL || ym == NULL)
			return 0;

		return xm->last_time < ym->last_time;
	}
};

class KisNetlist_Sort_LastDesc {
public:
	inline bool operator()(Kis_Display_NetGroup *x, 
						   Kis_Display_NetGroup *y) const {
		Netracker::tracked_network *xm = x->FetchNetwork();
		Netracker::tracked_network *ym = y->FetchNetwork();

		if (xm == NULL || ym == NULL)
			return 0;

		return xm->last_time > ym->last_time;
	}
};

class KisNetlist_Sort_Bssid {
public:
	inline bool operator()(Kis_Display_NetGroup *x, 
						   Kis_Display_NetGroup *y) const {
		Netracker::tracked_network *xm = x->FetchNetwork();
		Netracker::tracked_network *ym = y->FetchNetwork();

		if (xm == NULL || ym == NULL)
			return 0;

		return xm->bssid < ym->bssid;
	}
};

class KisNetlist_Sort_Ssid {
public:
	inline bool operator()(Kis_Display_NetGroup *x, 
						   Kis_Display_NetGroup *y) const {
		Netracker::tracked_network *xm = x->FetchNetwork();
		Netracker::tracked_network *ym = y->FetchNetwork();

		if (xm == NULL || ym == NULL)
			return 0;

		if (xm->lastssid == NULL || ym->lastssid == NULL)
			return 0;

		return xm->lastssid->ssid < ym->lastssid->ssid;
	}
};

class KisNetlist_Sort_Sdbm {
public:
	inline bool operator()(Kis_Display_NetGroup *x,
						   Kis_Display_NetGroup *y) const {
		Netracker::tracked_network *xm = x->FetchNetwork();
		Netracker::tracked_network *ym = y->FetchNetwork();

		if (xm == NULL || ym == NULL )
			return 0;
		
		if (time(0) - xm->last_time > 5)
			return 0;

		if (time(0) - ym->last_time > 5)
			return 1;

		return xm->snrdata.last_signal_dbm > ym->snrdata.last_signal_dbm;
	}
};

class KisNetlist_Sort_Packets {
public:
	inline bool operator()(Kis_Display_NetGroup *x, 
						   Kis_Display_NetGroup *y) const {
		Netracker::tracked_network *xm = x->FetchNetwork();
		Netracker::tracked_network *ym = y->FetchNetwork();

		if (xm == NULL || ym == NULL)
			return 0;

		return (xm->llc_packets + xm->data_packets) < 
			(ym->llc_packets + ym->data_packets);
	}
};

class KisNetlist_Sort_PacketsDesc {
public:
	inline bool operator()(Kis_Display_NetGroup *x, 
						   Kis_Display_NetGroup *y) const {
		Netracker::tracked_network *xm = x->FetchNetwork();
		Netracker::tracked_network *ym = y->FetchNetwork();

		if (xm == NULL || ym == NULL)
			return 0;

		return (xm->llc_packets + xm->data_packets) > 
			(ym->llc_packets + ym->data_packets);
	}
};

class KisNetlist_Sort_Crypt {
public:
	inline bool operator()(Kis_Display_NetGroup *x, 
						   Kis_Display_NetGroup *y) const {
		Netracker::tracked_network *xm = x->FetchNetwork();
		Netracker::tracked_network *ym = y->FetchNetwork();

		if (xm == NULL || ym == NULL)
			return 0;

		if (xm->lastssid == NULL || ym->lastssid == NULL)
			return 0;

		return (xm->lastssid->cryptset) < (ym->lastssid->cryptset);
	}
};

class KisNetlist_Sort_Clients {
public:
	inline bool operator()(Kis_Display_NetGroup *x, 
						   Kis_Display_NetGroup *y) const {
		Netracker::tracked_network *xm = x->FetchNetwork();
		Netracker::tracked_network *ym = y->FetchNetwork();

		if (xm == NULL || ym == NULL)
			return 0;

		if (xm == NULL || ym == NULL)
			return 0;

		return (xm->client_map.size()) < (ym->client_map.size());
	}
};

class KisClientlist_Sort_First {
public:
	inline bool operator()(Kis_Clientlist::display_client x, 
						   Kis_Clientlist::display_client y) const {
		return x.cli->first_time < y.cli->first_time;
	}
};

class KisClientlist_Sort_FirstDesc {
public:
	inline bool operator()(Kis_Clientlist::display_client x, 
						   Kis_Clientlist::display_client y) const {
		return x.cli->first_time > y.cli->first_time;
	}
};

class KisClientlist_Sort_Last {
public:
	inline bool operator()(Kis_Clientlist::display_client x, 
						   Kis_Clientlist::display_client y) const {
		return x.cli->last_time < y.cli->last_time;
	}
};

class KisClientlist_Sort_LastDesc {
public:
	inline bool operator()(Kis_Clientlist::display_client x, 
						   Kis_Clientlist::display_client y) const {
		return x.cli->last_time > y.cli->last_time;
	}
};

class KisClientlist_Sort_Mac {
public:
	inline bool operator()(Kis_Clientlist::display_client x, 
						   Kis_Clientlist::display_client y) const {
		return x.cli->mac < y.cli->mac;
	}
};

class KisClientlist_Sort_Type {
public:
	inline bool operator()(Kis_Clientlist::display_client x, 
						   Kis_Clientlist::display_client y) const {
		return x.cli->type < y.cli->type;
	}
};

class KisClientlist_Sort_Packets {
public:
	inline bool operator()(Kis_Clientlist::display_client x, 
						   Kis_Clientlist::display_client y) const {
		return (x.cli->llc_packets + x.cli->data_packets) < 
			(y.cli->llc_packets + x.cli->data_packets);
	}
};

class KisClientlist_Sort_PacketsDesc {
public:
	inline bool operator()(Kis_Clientlist::display_client x, 
						   Kis_Clientlist::display_client y) const {
		return (x.cli->llc_packets + x.cli->data_packets) > 
			(y.cli->llc_packets + x.cli->data_packets);
	}
};

#endif

