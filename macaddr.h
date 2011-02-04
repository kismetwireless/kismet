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

#ifndef __MACADDR_H__
#define __MACADDR_H__

#include "config.h"

#include <stdio.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <algorithm>
#include <string>
#include <vector>
#include <map>

#define MAC_LEN 6
#define MAC_STR_LEN ((MAC_LEN * 2) + 6)

// Mac address transformed into 64bit int for fast sorting
// Optional PHY encoding for multi-phy MAC collisions
// Phy set assumes phy numbering starts at 1 (0 implies no phy set)
// Setting a new mac clears the phy
struct mac_addr {
    uint64_t longmac;
    uint64_t longmask;
    int error;

    // Convert a string mac address to the long-int storage format, with 
	// mask conversion if present.
    void string2long(const char *in) {
        short unsigned int *bs_in = new short unsigned int[MAC_LEN];

        error = 0;
        longmac = 0;
        longmask = (uint64_t) -1;

        // Get the MAC
        if (sscanf(in, "%hX:%hX:%hX:%hX:%hX:%hX",
                   &bs_in[0], &bs_in[1], &bs_in[2], 
                   &bs_in[3], &bs_in[4], &bs_in[5]) == 6) {

			longmac |= (uint64_t) bs_in[0] << ((MAC_LEN - 0 - 1) * 8);
			longmac |= (uint64_t) bs_in[1] << ((MAC_LEN - 1 - 1) * 8);
			longmac |= (uint64_t) bs_in[2] << ((MAC_LEN - 2 - 1) * 8);
			longmac |= (uint64_t) bs_in[3] << ((MAC_LEN - 3 - 1) * 8);
			longmac |= (uint64_t) bs_in[4] << ((MAC_LEN - 4 - 1) * 8);
			longmac |= (uint64_t) bs_in[5] << ((MAC_LEN - 5 - 1) * 8);

            // If it has a mask component, get that
            const char *in_mask = strchr(in, '/');
            if (in_mask != NULL) {
                longmask = 0;

                // See if it's numerical or expanded
                if (strchr(in_mask + 1, ':') != NULL) {
                    // expanded, sscanf hex octets
                    if (sscanf(in_mask + 1, "%hX:%hX:%hX:%hX:%hX:%hX",
                               &bs_in[0], &bs_in[1], &bs_in[2],
                               &bs_in[3], &bs_in[4], &bs_in[5]) == 6) {

						longmask |= (uint64_t) bs_in[0] << ((MAC_LEN - 0 - 1) * 8);
						longmask |= (uint64_t) bs_in[1] << ((MAC_LEN - 1 - 1) * 8);
						longmask |= (uint64_t) bs_in[2] << ((MAC_LEN - 2 - 1) * 8);
						longmask |= (uint64_t) bs_in[3] << ((MAC_LEN - 3 - 1) * 8);
						longmask |= (uint64_t) bs_in[4] << ((MAC_LEN - 4 - 1) * 8);
						longmask |= (uint64_t) bs_in[5] << ((MAC_LEN - 5 - 1) * 8);

                    } else {
                        error = 1;
                    }
                } else {
                    // numerical, scan and shift
                    int nummask;
                    if (sscanf(in_mask + 1, "%d", &nummask) == 1) {
                        if (nummask == 48)
                            nummask = 0;

                        longmask = ((uint64_t) -1 << (48 - nummask));

                    } else {
                        error = 1;
                    }
                }
            }

        } else {
            error = 1;
        }

        delete[] bs_in;
    }

    inline mac_addr() {
        longmac = 0;
        longmask = (uint64_t) -1;
        error = 0;
    }

    inline mac_addr(const uint8_t *in) {
        longmac = 0;
        longmask = (uint64_t) -1;
        error = 0;

		longmac |= (uint64_t) in[0] << ((MAC_LEN - 0 - 1) * 8);
		longmac |= (uint64_t) in[1] << ((MAC_LEN - 1 - 1) * 8);
		longmac |= (uint64_t) in[2] << ((MAC_LEN - 2 - 1) * 8);
		longmac |= (uint64_t) in[3] << ((MAC_LEN - 3 - 1) * 8);
		longmac |= (uint64_t) in[4] << ((MAC_LEN - 4 - 1) * 8);
		longmac |= (uint64_t) in[5] << ((MAC_LEN - 5 - 1) * 8);
    }

    inline mac_addr(const uint8_t *in, const uint8_t *maskin) {
        longmac = 0;
        longmask = 0;
        error = 0;

		longmac |= (uint64_t) in[0] << ((MAC_LEN - 0 - 1) * 8);
		longmac |= (uint64_t) in[1] << ((MAC_LEN - 1 - 1) * 8);
		longmac |= (uint64_t) in[2] << ((MAC_LEN - 2 - 1) * 8);
		longmac |= (uint64_t) in[3] << ((MAC_LEN - 3 - 1) * 8);
		longmac |= (uint64_t) in[4] << ((MAC_LEN - 4 - 1) * 8);
		longmac |= (uint64_t) in[5] << ((MAC_LEN - 5 - 1) * 8);

		longmask |= (uint64_t) maskin[0] << ((MAC_LEN - 0 - 1) * 8);
		longmask |= (uint64_t) maskin[1] << ((MAC_LEN - 1 - 1) * 8);
		longmask |= (uint64_t) maskin[2] << ((MAC_LEN - 2 - 1) * 8);
		longmask |= (uint64_t) maskin[3] << ((MAC_LEN - 3 - 1) * 8);
		longmask |= (uint64_t) maskin[4] << ((MAC_LEN - 4 - 1) * 8);
		longmask |= (uint64_t) maskin[5] << ((MAC_LEN - 5 - 1) * 8);
    }

    inline mac_addr(const unsigned short int *in) {
        longmac = 0;
        longmask = (uint64_t) -1;
        error = 0;

		longmac |= (uint64_t) in[0] << ((MAC_LEN - 0 - 1) * 8);
		longmac |= (uint64_t) in[1] << ((MAC_LEN - 1 - 1) * 8);
		longmac |= (uint64_t) in[2] << ((MAC_LEN - 2 - 1) * 8);
		longmac |= (uint64_t) in[3] << ((MAC_LEN - 3 - 1) * 8);
		longmac |= (uint64_t) in[4] << ((MAC_LEN - 4 - 1) * 8);
		longmac |= (uint64_t) in[5] << ((MAC_LEN - 5 - 1) * 8);
    }

    inline mac_addr(const char *in) {
        string2long(in);
    }

	inline mac_addr(const string in) {
		string2long(in.c_str());
	}

	inline mac_addr(const string in, uint8_t in_phy) {
		string2long(in.c_str());
		SetPhy(in_phy);
	}

    inline mac_addr(int in) {
		in = in; // Silence gcc
        longmac = 0;
        longmask = 0;
        error = 0;
    } 

    // Masked MAC compare
    inline bool operator== (const mac_addr& op) const {
        if (longmask < op.longmask)
            return ((longmac & longmask) == (op.longmac & longmask));

        return ((longmac & op.longmask) == (op.longmac & op.longmask));
    }

    // MAC compare
    inline bool operator!= (const mac_addr& op) const {
        if (longmask < op.longmask)
            return ((longmac & longmask) != (op.longmac & longmask));

        return ((longmac & op.longmask) != (op.longmac & op.longmask));
    }

    // mac less-than-eq
    inline bool operator<=(const mac_addr& op) const {
        return (longmac & op.longmask) == (op.longmac & op.longmask);
    }

    // MAC less-than for STL sorts...
    inline bool operator< (const mac_addr& op) const {
        return ((longmac & longmask) < (op.longmac & longmask));
    }

    mac_addr& operator= (const mac_addr& op) {
        longmac = op.longmac;
        longmask = op.longmask;
        error = op.error;
        return *this;
    }

    mac_addr& operator= (const char *in) {
        string2long(in);

        return *this;
    }

    mac_addr& operator++() {
        longmac++;
        return *this;
    }

    mac_addr operator++(int) {
        mac_addr tmp = *this;
        ++*this;
        return tmp;
    }

    inline uint8_t index64(uint64_t val, int index) const {
        // Bitshift kung-foo
        return (uint8_t) (val >> ((MAC_LEN - index - 1) * 8));
    }

    inline const uint8_t operator[] (int index) const {
        int mdex = index;
        if (index < 0 || index >= MAC_LEN)
            mdex = 0;

        return index64(longmac, mdex);
    }

	inline void SetPhy(uint8_t in_phy) {
		longmac |= (uint64_t) in_phy << (6 * 8);
		// Force enable checking of the phy once one is set
		longmask |= (uint64_t) 0xFF << (6 * 6);
	}

	inline uint8_t GetPhy() {
		return index64(longmac, 5);
	}

	inline uint32_t OUI() const {
		return (longmac >> 24);
	}

    inline string Mac2String() const {
        char tempstr[MAC_STR_LEN];

        snprintf(tempstr, MAC_STR_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
				 index64(longmac, 0), index64(longmac, 1), index64(longmac, 2),
				 index64(longmac, 3), index64(longmac, 4), index64(longmac, 5));
        return string(tempstr);
    }

    inline string MacMask2String() const {
        uint64_t maskedmac = longmac & longmask;

        char tempstr[(MAC_STR_LEN * 2) + 1];

        snprintf(tempstr, (MAC_STR_LEN * 2) + 1, 
				 "%02X:%02X:%02X:%02X:%02X:%02X/%02X:%02X:%02X:%02X:%02X:%02X",
                 index64(maskedmac, 0), index64(maskedmac, 1), index64(maskedmac, 2),
                 index64(maskedmac, 3), index64(maskedmac, 4), index64(maskedmac, 5),
                 index64(longmask, 0), index64(longmask, 1), index64(longmask, 2),
                 index64(longmask, 3), index64(longmask, 4), index64(longmask, 5));
        return tempstr;
    }

};


// A templated container for storing groups of masked mac addresses.  A stl-map 
// will work for single macs, but we need this for smart mask matching on 
// more complex sets.  Iterators in this class only work as incremental, 
// because thats all I need right now.  This whole thing is really an ugly, 
// ugly kluge, and if I really had any need for it to be more extendible I'd 
// rewrite it to use std::iterator and other good stuff.  But, I don't,
// it works, and I need to move on to other areas.
template<class T>
class macmap {
protected:
    struct mask_vec_content {
        mac_addr mac;
        T value;
    };

    struct mask_vec_offsets {
        unsigned int first;
        unsigned int last;
    };

    class SortMaskVec {
    public:
        inline bool operator() (const macmap::mask_vec_content x, 
								const macmap::mask_vec_content y) const {
            return (x.mac < y.mac);
        }
    };

public:
    // This isn't quite like STL iterators, because I'm too damned lazy to deal 
	// with all the nasty STL hoop-jumping.  This does provide a somewhat-stl-ish 
	// interface to iterating through the singleton and masked maps
    class iterator {
        friend class macmap;

    public:
        inline iterator(macmap<T> *in_owner) {
            owner = in_owner;

            if (owner->singleton_map.size() > 0) {
                singleton_itr = owner->singleton_map.begin();
                vector_itr = -1;
                first = singleton_itr->first;
                second = &(singleton_itr->second);
            } else if (owner->mask_vec.size() > 0) {
                singleton_itr = owner->singleton_map.end();
                vector_itr = 0;
                first = owner->mask_vec[0].mac;
                second = &(owner->mask_vec[0].value);
            } else {
                singleton_itr = owner->singleton_map.end();
                vector_itr = owner->mask_vec.size();
				second = NULL;
            }
        }

        // Prefix
        inline iterator& operator++() {
            if (singleton_itr == owner->singleton_map.end()) {
                if ((++vector_itr) < (int) owner->mask_vec.size()) {
                    first = owner->mask_vec[vector_itr].mac;
                    second = &(owner->mask_vec[vector_itr].value);
                }
            } else if (++singleton_itr == owner->singleton_map.end()) {
                if ((++vector_itr) < (int) owner->mask_vec.size()) {
                    first = owner->mask_vec[vector_itr].mac;
                    second = &(owner->mask_vec[vector_itr].value);
                }
            } else {
                first = singleton_itr->first;
                second = &(singleton_itr->second);
            }

            return *this;
        }

        // Postfix
        inline iterator operator++(int) {
            iterator tmp = *this;
            ++*this;
            return tmp;
        }

        // equal
        inline bool operator==(const iterator& op) {
            return (singleton_itr == op.singleton_itr) && 
				(vector_itr == op.vector_itr);
        }

        // not
        inline bool operator!=(const iterator& op) {
            return (singleton_itr != op.singleton_itr) || 
				(vector_itr != op.vector_itr);
        }

        // pointer fake
        inline iterator *operator->() {
            return this;
        }

        mac_addr first;
        T *second;

    protected:
        inline void assign(typename map<mac_addr, T>::iterator in_itr) {
            singleton_itr = in_itr;
            vector_itr = -1;

            if (in_itr != owner->singleton_map.end()) {
                first = singleton_itr->first;
                second = &(singleton_itr->second);
            }
        }

        inline void assign(int in_itr) {
            singleton_itr = owner->singleton_map.end();
            vector_itr = in_itr;

            if (in_itr < (int) owner->mask_vec.size()) {
                first = owner->mask_vec[vector_itr].mac;
                second = &(owner->mask_vec[vector_itr].value);
            }
        }

        typename map<mac_addr, T>::iterator singleton_itr;
        int vector_itr;
        macmap<T> *owner;
    };

    friend class macmap<T>::iterator;

    inline iterator begin() {
        iterator ret(this);

        return ret;
    }

    inline iterator end() {
        iterator ret(this);
        ret.singleton_itr = singleton_map.end();
        ret.vector_itr = mask_vec.size();

        return ret;
    }

    // The caller will rebuild the index before using us...
    inline void fast_insert(mac_addr in_mac, T in_data) {
        // Single macs go into the singleton map
        if (in_mac.longmask == (uint64_t) -1) {
            singleton_map[in_mac] = in_data;
            return;
        }

        // Put them into the vector
        mask_vec_content content;
        content.mac = in_mac;
        content.value = in_data;
        mask_vec.push_back(content);
    }
    
    // This is a very expensive insert but it builds a system that allows
    // for fast searching, which is where we REALLY need the speed.
    inline void insert(mac_addr in_mac, T in_data) {
        // Single macs go into the singleton map
        if (in_mac.longmask == (uint64_t) -1) {
            singleton_map[in_mac] = in_data;
            return;
        }

        // Put them into the vector
        mask_vec_content content;
        content.mac = in_mac;
        content.value = in_data;
        mask_vec.push_back(content);

        reindex();
    }

    // Do a relatively fast find...
    inline iterator find(mac_addr in_mac) {
        iterator ret(this);

        if (in_mac.longmask == (uint64_t) -1) {
            // Look in the singleton map... This is very fast.
            typename map<mac_addr, T>::iterator sitr = singleton_map.find(in_mac);
            if (sitr != singleton_map.end()) {
                ret.assign(sitr);
                return ret;
            }
        }

        if (vec_offset_map.find(in_mac) != vec_offset_map.end()) {
            // We matched a large key in the vector map.  The vector is sorted
            // in decreasing granularity, so the first one we match we can count
            // as good and get out of here
            mask_vec_offsets oft = vec_offset_map[in_mac];
            for (unsigned int x = oft.last; x >= oft.first; x--) {
                if (in_mac <= mask_vec[x].mac) {
                    ret.assign(x);
                    return ret;
                }
            }
        }

        return end();
    }

    inline void erase(mac_addr in_mac) {
        iterator itr = find(in_mac);

        if (itr == end())
            return;

        if (itr.singleton_itr != singleton_map.end()) {
            singleton_map.erase(itr.singleton_itr);
            reindex();
            return;
        }

        if (itr.vector_itr >= 0 && itr.vector_itr < (int) mask_vec.size()) {
            mask_vec.erase(mask_vec.begin() + itr.vector_itr);
            reindex();
            return;
        }

    }

    inline T& operator[](mac_addr& index) {
        iterator foo = find(index);

        // This isn't very clean but its better than heap corruption 
        // and other horrible stuff
        if (foo == end()) {
            fprintf(stderr, "Something tried to use macmap[] to reference an "
                    "element that doesn't exist.  Fix me.\n");
            exit(1);
        }

        return *(foo->second);
    }

    int size() {
        return singleton_map.size() + mask_vec.size();
    }

	inline void clear(void) {
		vec_offset_map.clear();
		singleton_map.clear();
		mask_vec.clear();
	}

    inline void reindex(void) {
        // Order it
        if (mask_vec.size() == 0)
            return;

        stable_sort(mask_vec.begin(), mask_vec.end(), SortMaskVec());

        // Clear our old map of content
        vec_offset_map.clear();

        // Split it into offset groups
        mask_vec_offsets ofst;
        ofst.last = mask_vec.size() - 1;
        ofst.first = mask_vec.size() - 1;
        mac_addr owner = mask_vec[ofst.last].mac;
        for (unsigned int x = 0; x < mask_vec.size(); x++) {
            // Masked compare... is it still a subset of us?
            if (owner != mask_vec[x].mac) {
                vec_offset_map[owner] = ofst;
                ofst.first = x;
                ofst.last = x;
                owner = mask_vec[x].mac;
            } else {
                ofst.last = x;
            }
        }
        // Clean up the last stuff
        vec_offset_map[owner] = ofst;
        vec_offset_map[owner] = ofst;
    }

protected:
    map<mac_addr, T> singleton_map;
    vector<mask_vec_content> mask_vec;
    map<mac_addr, mask_vec_offsets> vec_offset_map;
};


#endif

