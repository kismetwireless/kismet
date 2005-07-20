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
    inline bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet->last_time > y->virtnet->last_time)
            return 1;
        return 0;
    }
};

class DisplaySortLastTimeLT {
public:
    inline bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet->last_time < y->virtnet->last_time)
            return 1;
        return 0;
    }
};


class DisplaySortFirstTime {
public:
    inline bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet->first_time > y->virtnet->first_time)
            return 1;
        return 0;
    }
};

class DisplaySortFirstTimeLT {
public:
    inline bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet->first_time < y->virtnet->first_time)
            return 1;
        return 0;
    }
};

class DisplaySortBSSID {
public:
    inline bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (y->virtnet->bssid < x->virtnet->bssid)
            return 1;
        return 0;
    }
};

class DisplaySortBSSIDLT {
public:
    inline bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet->bssid < y->virtnet->bssid)
            return 1;
        return 0;
    }
};


class DisplaySortSSID {
public:
    inline bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet->ssid > y->virtnet->ssid)
            return 1;
        return 0;
    }
};

class DisplaySortSSIDLT {
public:
    inline bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet->ssid < y->virtnet->ssid)
            return 1;
        return 0;
    }
};

class DisplaySortWEP {
public:
    inline bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet->crypt_set > y->virtnet->crypt_set)
            return 1;
        return 0;
    }
};

class DisplaySortChannel {
public:
    inline bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet->channel < y->virtnet->channel)
            return 1;
        return 0;
    }
};

class DisplaySortPacketsLT {
public:
    inline bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if ((x->virtnet->llc_packets + x->virtnet->data_packets) <
            (y->virtnet->llc_packets + y->virtnet->data_packets))
            return 1;
        return 0;
    }
};

class DisplaySortPackets {
public:
    inline bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if ((x->virtnet->llc_packets + x->virtnet->data_packets) >
            (y->virtnet->llc_packets + y->virtnet->data_packets))
            return 1;
        return 0;
    }
};

class DisplaySortQuality {
public:
    inline bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet->quality > y->virtnet->quality)
            return 1;
        return 0;
    }
};

class DisplaySortSignal {
public:
    inline bool operator() (const display_network *x, const display_network *y) const {
        if (x->type == group_empty)
            return 0;
        if (y->type == group_empty)
            return 1;

        if (x->virtnet->signal > y->virtnet->signal)
            return 1;
        return 0;
    }
};

class ClientSortLastTime {
public:
    inline bool operator() (const wireless_client *x, const wireless_client *y) const {
        if (x->last_time > y->last_time)
            return 1;
        return 0;
    }
};

class ClientSortLastTimeLT {
public:
    inline bool operator() (const wireless_client *x, const wireless_client *y) const {
        if (x->last_time < y->last_time)
            return 1;
        return 0;
    }
};


class ClientSortFirstTime {
public:
    inline bool operator() (const wireless_client *x, const wireless_client *y) const {
        if (x->first_time > y->first_time)
            return 1;
        return 0;
    }
};

class ClientSortFirstTimeLT {
public:
    inline bool operator() (const wireless_client *x, const wireless_client *y) const {
        if (x->first_time < y->first_time)
            return 1;
        return 0;
    }

};

class ClientSortMAC {
public:
    inline bool operator() (const wireless_client *x, const wireless_client *y) const {
        if (y->mac < x->mac)
            return 1;
        return 0;
    }
};

class ClientSortMACLT {
public:
    inline bool operator() (const wireless_client *x, const wireless_client *y) const {
        if (x->mac < y->mac)
            return 1;
        return 0;
    }
};

class ClientSortWEP {
public:
    inline bool operator() (const wireless_client *x, const wireless_client *y) const {
        if (x->crypt_set > y->crypt_set)
            return 1;
        return 0;
    }
};

class ClientSortChannel {
public:
    inline bool operator() (const wireless_client *x, const wireless_client *y) const {
        if (x->channel < y->channel)
            return 1;
        return 0;
    }
};

class ClientSortPacketsLT {
public:
    inline bool operator() (const wireless_client *x, const wireless_client *y) const {
        if (x->data_packets < y->data_packets)
            return 1;
        return 0;
    }
};

class ClientSortPackets {
public:
    inline bool operator() (const wireless_client *x, const wireless_client *y) const {
        if (x->data_packets > y->data_packets)
            return 1;
        return 0;
    }
};

class ClientSortQuality {
public:
    inline bool operator() (const wireless_client *x, const wireless_client *y) const {
        if (x->quality > y->quality)
            return 1;
        return 0;
    }
};

class ClientSortSignal {
public:
    inline bool operator() (const wireless_client *x, const wireless_client *y) const {
        if (x->signal > y->signal)
            return 1;
        return 0;
    }
};

#endif

