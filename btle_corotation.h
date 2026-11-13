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

#include <array>
#include <unordered_map>
#include <vector>

#include "kis_mutex.h"
#include "trackedelement.h"

// A device sending several advertising sets rotates all their addresses at the same
// moment: on one receiver, two or more of its addresses go quiet and as many new ones
// start within a moment of each other, at a similar signal, with the same advertisement
// structures.  No payload or counter has to carry across.
//
// Another device could rotate at the same moment by chance, so a rotation only counts
// once the next one shows the same addresses rotating together again; after that each
// rotation counts at once.
class btle_corotation {
public:
    struct params {
        // Quiet and new addresses within this long of each other
        int64_t window_ms;
        // and within this many dB of the signal of the new address being checked
        int signal_window;
        // A new address is checked this long after it starts, once the ones it
        // replaced have stayed quiet
        int64_t settle_ms;
        // Addresses not heard for longer than this are forgotten
        int64_t keep_ms;
        // A device's sets are remembered this long after their last rotation
        int64_t chain_keep_ms;
    };

    static constexpr size_t max_addrs = 4096;
    static constexpr size_t max_chains = 64;
    // Receivers timed per address, and most sets in one rotation
    static constexpr size_t max_sources = 4;
    static constexpr size_t max_sets = 16;
    // Most new addresses checked per pass, under a flood
    static constexpr size_t max_checks = 64;

    // One device's addresses before and after a confirmed rotation, sorted
    struct rotation {
        std::vector<device_key> quiet;
        std::vector<device_key> fresh;
    };

    btle_corotation(const params& p) :
        p_{p} { }

    // A rotating random address was heard; structure is its advertisement's structure
    // fingerprint, 0 for none.  Rotations confirmed by this call are appended to out.
    void observe(const device_key& key, int64_t now_ms, uint64_t structure, int signal,
            uint64_t source, std::vector<rotation>& out);

protected:
    struct sighting {
        uint64_t source;
        int64_t first_ms;
        int64_t last_ms;
        // Running average, in 1/16 dB, over n_signal frames up to 16: one frame's
        // signal swings several dB by channel
        int avg16;
        uint8_t n_signal;
    };

    struct addr {
        // On any receiver
        int64_t first_ms;
        int64_t last_ms;
        uint64_t structure;
        std::array<sighting, max_sources> seen;
        uint8_t n_seen;
        // Its rotation was looked for
        bool checked;
    };

    // The addresses of a device's sets after its last rotation
    struct chain {
        std::vector<device_key> fresh;
        int64_t last_ms;
    };

    static const sighting *on(const addr& a, uint64_t source);
    static sighting *on(addr& a, uint64_t source);
    void prune(int64_t now_ms);
    void check(int64_t now_ms, std::vector<rotation>& out);
    // The addresses that went quiet and started with key's start on s's receiver
    bool find_rotation(const addr& a, const sighting& s, std::vector<device_key>& quiet,
            std::vector<device_key>& fresh) const;
    void record(std::vector<device_key>& quiet, std::vector<device_key>& fresh,
            int64_t now_ms, std::vector<rotation>& out);

    params p_;

    kis_mutex mutex;
    std::unordered_map<device_key, addr> addrs_;
    // New addresses whose rotation hasn't been looked for yet
    std::vector<device_key> waiting_;
    std::vector<chain> chains_;
    int64_t last_prune_ms = 0;
    int64_t last_check_ms = 0;
};

#endif
