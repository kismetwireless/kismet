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

#ifndef __NETWORKSORT_H__
#define __NETWORKSORT_H__

#include "config.h"
#include "packetracker.h"

class SortLastTime {
public:
    bool operator() (const wireless_network *x, const wireless_network *y) const {
        if (x->last_time > y->last_time)
            return 1;
        return 0;
    }
};

class SortLastTimeLT {
public:
    bool operator() (const wireless_network *x, const wireless_network *y) const {
        if (x->last_time < y->last_time)
            return 1;
        return 0;
    }
};


class SortFirstTime {
public:
    bool operator() (const wireless_network *x, const wireless_network *y) const {
        if (x->first_time > y->first_time)
            return 1;
        return 0;
    }
};

class SortFirstTimeLT {
public:
    bool operator() (const wireless_network *x, const wireless_network *y) const {
        if (x->first_time < y->first_time)
            return 1;
        return 0;
    }
};

class SortBSSID {
public:
    bool operator() (const wireless_network *x, const wireless_network *y) const {
        if (y->bssid < x->bssid)
            return 1;
        return 0;
    }
};

class SortBSSIDLT {
public:
    bool operator() (const wireless_network *x, const wireless_network *y) const {
        if (x->bssid < y->bssid)
            return 1;
        return 0;
    }
};


class SortSSID {
public:
    bool operator() (const wireless_network *x, const wireless_network *y) const {
        if (x->ssid > y->ssid)
            return 1;
        return 0;
    }
};

class SortSSIDLT {
public:
    bool operator() (const wireless_network *x, const wireless_network *y) const {
        if (x->ssid < y->ssid)
            return 1;
        return 0;
    }
};

class SortWEP {
public:
    bool operator() (const wireless_network *x, const wireless_network *y) const {
        if (x->wep > y->wep)
            return 1;
        return 0;
    }
};

class SortChannel {
public:
    bool operator() (const wireless_network *x, const wireless_network *y) const {
        if (x->channel < y->channel)
            return 1;
        return 0;
    }
};

class SortPacketsLT {
public:
    bool operator() (const wireless_network *x, const wireless_network *y) const {
        if ((x->llc_packets + x->data_packets) <
            (y->llc_packets + y->data_packets))
            return 1;
        return 0;
    }
};

class SortPackets {
public:
    bool operator() (const wireless_network *x, const wireless_network *y) const {
        if ((x->llc_packets + x->data_packets) >
            (y->llc_packets + y->data_packets))
            return 1;
        return 0;
    }
};

class SortQuality {
public:
    bool operator() (const wireless_network *x, const wireless_network *y) const {
        if (x->quality > y->quality)
            return 1;
        return 0;
    }
};

class SortSignal {
public:
    bool operator() (const wireless_network *x, const wireless_network *y) const {
        if (x->signal > y->signal)
            return 1;
        return 0;
    }
};

#endif

