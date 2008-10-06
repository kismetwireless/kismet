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

#ifndef __KIS_PANEL_NETWORT_H__
#define __KIS_PANEL_NETWORT_H__

#include "config.h"

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

class KisNetlist_Sort_Packets {
public:
	inline bool operator()(Kis_Display_NetGroup *x, 
						   Kis_Display_NetGroup *y) const {
		Netracker::tracked_network *xm = x->FetchNetwork();
		Netracker::tracked_network *ym = y->FetchNetwork();

		if (xm == NULL || ym == NULL)
			return 0;

		return (xm->llc_packets + xm->data_packets) < 
			(ym->llc_packets + xm->data_packets);
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
			(ym->llc_packets + xm->data_packets);
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

#endif

