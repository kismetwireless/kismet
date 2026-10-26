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

#ifndef __RANDOMIZED_ALIAS_H__
#define __RANDOMIZED_ALIAS_H__

#include "config.h"

#include <time.h>

#include <unordered_map>
#include <vector>

#include "kis_mutex.h"
#include "trackedelement.h"

// Links the randomized addresses a device cycles through.  The phy reduces what a
// device sends to a fingerprint which stays the same across an address change (a
// Wi-Fi probe request's IEs, a BTLE advertisement's payload); a new address is the
// next one of an earlier address when it appears with the same fingerprint shortly
// after the earlier one goes quiet, and the earlier one stays quiet.
//
// A sequence number, when the protocol has one that carries across the change, picks
// between several candidates.  Without one, a link is only made when no other device
// with the same fingerprint is around, since it could be either.
class randomized_alias_linker {
public:
    struct params {
        // A new address must appear within this long of the earlier one going quiet
        time_t window;
        // and the earlier one stay quiet this long after
        time_t confirm;
        // A first sequence number this far after the earlier one's last is a match
        int seq_window;
        // Name of a link made without a sequence number match
        const char *unique_method;
        // Addresses quiet for longer than this are forgotten
        time_t keep;
    };

    // method is "sequence" or params::unique_method; nullptr means key only moved to
    // another group because the address it was linked to did
    struct link {
        device_key key;
        device_key pred;
        device_key group;
        const char *method;
    };

    randomized_alias_linker(const params& p) :
        p_{p} { }

    // A device sent something with this fingerprint; seq < 0 when there is none.
    // Links settled by this call are appended to out.
    void observe(uint64_t fingerprint, const device_key& key, time_t now, int seq,
            std::vector<link>& out);

protected:
    struct rec {
        device_key key;
        time_t first;
        time_t last;
        int last_seq;
        // A later address is linked, or waiting to be, to this one
        bool succeeded;
    };

    // A link waiting for the earlier address to stay quiet
    struct pending {
        uint64_t fingerprint;
        device_key key;
        device_key pred;
        time_t first;
        const char *method;
    };

    struct seen {
        time_t last;
        device_key group;
    };

    void prune(time_t now);

    params p_;

    kis_mutex mutex;
    std::unordered_map<uint64_t, std::vector<rec>> recs_;
    // Across every fingerprint, so an address heard again with another one still
    // counts as heard
    std::unordered_map<device_key, seen> seen_;
    std::vector<pending> pending_;
    time_t last_prune = 0;
};

#endif
