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
        if (x->bssid > y->bssid)
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


#endif

