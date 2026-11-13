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

#ifndef __BTLE_COROTATION_H__
#define __BTLE_COROTATION_H__

#include "config.h"

#include <stdint.h>

#include <unordered_map>
#include <vector>

#include "kis_mutex.h"
#include "trackedelement.h"

// A device sending several advertising sets rotates all their addresses at the same
// moment.  When the linker settles one rotation (the anchor: an address followed by
// its next), the other sets that went quiet and started within a moment of it, on the
// same receiver at a similar signal, are that device's too - if every set's structure
// shows up exactly once on each side, so each quiet one pairs with one new one.
//
// Another device could rotate at the same moment by chance, so a pairing only counts
// once the anchor's next rotation shows the same sets rotating together again; after
// that each rotation joins at once.
class btle_corotation {
public:
    struct params {
        // Quiet and new addresses within this long of the anchor's
        int64_t window_ms;
        // and within this many dB of its signal
        int signal_window;
        // Addresses not heard for longer than this are forgotten
        int64_t keep_ms;
        // A device's sets are remembered this long after their last rotation
        int64_t chain_keep_ms;
    };

    static constexpr size_t max_addrs = 4096;
    static constexpr size_t max_chains = 64;

    // key belongs in pred's group
    struct join {
        device_key key;
        device_key pred;
    };

    btle_corotation(const params& p) :
        p_{p} { }

    // A rotating random address was heard; structure is its advertisement's structure
    // fingerprint, 0 for none
    void observe(const device_key& key, int64_t now_ms, uint64_t structure, int signal,
            uint64_t source);

    // The linker settled key as the address after pred; joins for the device's other
    // sets are appended to out
    void rotated(const device_key& key, const device_key& pred, std::vector<join>& out);

protected:
    struct addr {
        int64_t first_ms;
        int64_t last_ms;
        int first_signal;
        int last_signal;
        uint64_t source;
        uint64_t structure;
    };

    // One of the device's other sets at a rotation: its address before and after, and
    // whether it rotated with the anchor at the rotation before too
    struct member {
        uint64_t structure;
        device_key quiet;
        device_key next;
        bool confirmed;
    };

    // One device's sets as of its last rotation, keyed by the anchor's newest address
    struct chain {
        std::vector<member> members;
        int64_t last_ms;
    };

    void prune(int64_t now_ms);

    params p_;

    kis_mutex mutex;
    std::unordered_map<device_key, addr> addrs_;
    std::unordered_map<device_key, chain> chains_;
    int64_t last_prune_ms = 0;
};

#endif
