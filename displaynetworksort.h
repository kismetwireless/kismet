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

#ifndef __DISPLAYNETWORKSORT_H__
#define __DISPLAYNETWORKSORT_H__

#include "config.h"
#include "frontend.h"
#include "packetracker.h"

class DisplaySortLastTime {
public:
    bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet.last_time > y->virtnet.last_time)
            return 1;
        return 0;
    }
};

class DisplaySortLastTimeLT {
public:
    bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet.last_time < y->virtnet.last_time)
            return 1;
        return 0;
    }
};


class DisplaySortFirstTime {
public:
    bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet.first_time > y->virtnet.first_time)
            return 1;
        return 0;
    }
};

class DisplaySortFirstTimeLT {
public:
    bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet.first_time < y->virtnet.first_time)
            return 1;
        return 0;
    }
};

class DisplaySortBSSID {
public:
    bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet.bssid > y->virtnet.bssid)
            return 1;
        return 0;
    }
};

class DisplaySortBSSIDLT {
public:
    bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet.bssid < y->virtnet.bssid)
            return 1;
        return 0;
    }
};


class DisplaySortSSID {
public:
    bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet.ssid > y->virtnet.ssid)
            return 1;
        return 0;
    }
};

class DisplaySortSSIDLT {
public:
    bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet.ssid < y->virtnet.ssid)
            return 1;
        return 0;
    }
};

class DisplaySortWEP {
public:
    bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet.wep > y->virtnet.wep)
            return 1;
        return 0;
    }
};

class DisplaySortChannel {
public:
    bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet.channel < y->virtnet.channel)
            return 1;
        return 0;
    }
};

class DisplaySortPacketsLT {
public:
    bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if ((x->virtnet.llc_packets + x->virtnet.data_packets) <
            (y->virtnet.llc_packets + y->virtnet.data_packets))
            return 1;
        return 0;
    }
};

class DisplaySortPackets {
public:
    bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if ((x->virtnet.llc_packets + x->virtnet.data_packets) >
            (y->virtnet.llc_packets + y->virtnet.data_packets))
            return 1;
        return 0;
    }
};


#endif

