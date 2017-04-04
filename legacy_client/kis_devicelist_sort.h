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

#ifndef __KIS_PANEL_DEVICELIST_SORT_H__
#define __KIS_PANEL_DEVICELIST_SORT_H__

#include "config.h"

#include "kis_panel_device.h"
#include "kis_panel_frontend.h"

class KDL_Sort_Abstract {
public:
	virtual bool operator()(kdl_display_device *x, 
							kdl_display_device *y) const = 0;
};

class KDL_Sort_Proxy {
public:
	KDL_Sort_Proxy(KDL_Sort_Abstract &f) : f(f) {}
	bool operator()(kdl_display_device *x, 
					kdl_display_device *y) const {
		return f(x, y);
	}
	KDL_Sort_Abstract &f;
};

class KDL_Sort_Type : public KDL_Sort_Abstract {
public:
	int devcomp_ref_common;

	KDL_Sort_Type(int in_common) {
		devcomp_ref_common = in_common;
	}

	inline bool operator()(kdl_display_device *x, 
						   kdl_display_device *y) const {
		if (x->device == NULL || y->device == NULL)
			return 0;

		kis_device_common *xc =
			(kis_device_common *) x->device->fetch(devcomp_ref_common);
		kis_device_common *yc =
			(kis_device_common *) y->device->fetch(devcomp_ref_common);

		if (xc == NULL || yc == NULL)
			return 0;

		return xc->basic_type_set < yc->basic_type_set;
	}
};

class KDL_Sort_Channel : public KDL_Sort_Abstract {
public:
	int devcomp_ref_common;

	KDL_Sort_Channel(int in_common) {
		devcomp_ref_common = in_common;
	}

	inline bool operator()(kdl_display_device *x, 
						   kdl_display_device *y) const {
		if (x->device == NULL || y->device == NULL)
			return 0;

		kis_device_common *xc =
			(kis_device_common *) x->device->fetch(devcomp_ref_common);
		kis_device_common *yc =
			(kis_device_common *) y->device->fetch(devcomp_ref_common);

		if (xc == NULL || yc == NULL)
			return 0;

		return xc->channel < yc->channel;
	}
};

class KDL_Sort_First : public KDL_Sort_Abstract {
public:
	int devcomp_ref_common;

	KDL_Sort_First(int in_common) {
		devcomp_ref_common = in_common;
	}

	inline bool operator()(kdl_display_device *x, 
						   kdl_display_device *y) const {
		if (x->device == NULL || y->device == NULL)
			return 0;

		kis_device_common *xc =
			(kis_device_common *) x->device->fetch(devcomp_ref_common);
		kis_device_common *yc =
			(kis_device_common *) y->device->fetch(devcomp_ref_common);

		if (xc == NULL || yc == NULL)
			return 0;

		return xc->first_time > yc->first_time;
	}
};

class KDL_Sort_FirstDesc : public KDL_Sort_Abstract {
public:
	int devcomp_ref_common;

	KDL_Sort_FirstDesc(int in_common) {
		devcomp_ref_common = in_common;
	}

	inline bool operator()(kdl_display_device *x, 
						   kdl_display_device *y) const {
		if (x->device == NULL || y->device == NULL)
			return 0;

		kis_device_common *xc =
			(kis_device_common *) x->device->fetch(devcomp_ref_common);
		kis_device_common *yc =
			(kis_device_common *) y->device->fetch(devcomp_ref_common);

		if (xc == NULL || yc == NULL)
			return 0;

		return xc->first_time < yc->first_time;
	}
};

class KDL_Sort_Last : public KDL_Sort_Abstract {
public:
	int devcomp_ref_common;

	KDL_Sort_Last(int in_common) {
		devcomp_ref_common = in_common;
	}

	inline bool operator()(kdl_display_device *x, 
						   kdl_display_device *y) const {
		if (x->device == NULL || y->device == NULL)
			return 0;

		kis_device_common *xc =
			(kis_device_common *) x->device->fetch(devcomp_ref_common);
		kis_device_common *yc =
			(kis_device_common *) y->device->fetch(devcomp_ref_common);

		if (xc == NULL || yc == NULL)
			return 0;

		return xc->last_time > yc->last_time;
	}
};

class KDL_Sort_LastDesc : public KDL_Sort_Abstract {
public:
	int devcomp_ref_common;

	KDL_Sort_LastDesc(int in_common) {
		devcomp_ref_common = in_common;
	}

	inline bool operator()(kdl_display_device *x, 
						   kdl_display_device *y) const {
		if (x->device == NULL || y->device == NULL)
			return 0;

		kis_device_common *xc =
			(kis_device_common *) x->device->fetch(devcomp_ref_common);
		kis_device_common *yc =
			(kis_device_common *) y->device->fetch(devcomp_ref_common);

		if (xc == NULL || yc == NULL)
			return 0;

		return xc->last_time < yc->last_time;
	}
};

class KDL_Sort_Packets : public KDL_Sort_Abstract {
public:
	int devcomp_ref_common;

	KDL_Sort_Packets(int in_common) {
		devcomp_ref_common = in_common;
	}

	inline bool operator()(kdl_display_device *x, 
						   kdl_display_device *y) const {
		if (x->device == NULL || y->device == NULL) {
			return 0;
		}

		kis_device_common *xc =
			(kis_device_common *) x->device->fetch(devcomp_ref_common);
		kis_device_common *yc =
			(kis_device_common *) y->device->fetch(devcomp_ref_common);

		if (xc == NULL || yc == NULL) {
			return 0;
		}

		return xc->packets > yc->packets;
	}
};

class KDL_Sort_PacketsDesc : public KDL_Sort_Abstract {
public:
	int devcomp_ref_common;

	KDL_Sort_PacketsDesc(int in_common) {
		devcomp_ref_common = in_common;
	}

	inline bool operator()(kdl_display_device *x, 
						   kdl_display_device *y) const {
		if (x->device == NULL || y->device == NULL)
			return 0;

		kis_device_common *xc =
			(kis_device_common *) x->device->fetch(devcomp_ref_common);
		kis_device_common *yc =
			(kis_device_common *) y->device->fetch(devcomp_ref_common);

		if (xc == NULL || yc == NULL)
			return 0;

		return xc->packets < yc->packets;
	}
};

class KDL_Sort_Crypt : public KDL_Sort_Abstract {
public:
	int devcomp_ref_common;

	KDL_Sort_Crypt(int in_common) {
		devcomp_ref_common = in_common;
	}

	inline bool operator()(kdl_display_device *x, 
						   kdl_display_device *y) const {
		if (x->device == NULL || y->device == NULL)
			return 0;

		kis_device_common *xc =
			(kis_device_common *) x->device->fetch(devcomp_ref_common);
		kis_device_common *yc =
			(kis_device_common *) y->device->fetch(devcomp_ref_common);

		if (xc == NULL || yc == NULL)
			return 0;

		return xc->basic_crypt_set < yc->basic_crypt_set;
	}
};

class KDL_Sort_Phy : public KDL_Sort_Abstract {
public:
	int devcomp_ref_common;

	KDL_Sort_Phy(int in_common) {
		devcomp_ref_common = in_common;
	}

	inline bool operator()(kdl_display_device *x, 
						   kdl_display_device *y) const {
		if (x->device == NULL || y->device == NULL)
			return 0;

		return x->device->phy_type < y->device->phy_type;
	}
};


#endif

