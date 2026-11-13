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

#include <array>
#include <limits>
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
// between several candidates.  Without one, the signal can: the candidate whose last
// signal on the same source is closest to the new address's first, when it is clearly
// closer than the others.  Otherwise a link is only made when no other device with the
// same fingerprint is around, since it could be either.
//
// seq_rules set how one call's numbers are read: their range, and whether the number
// is the only evidence, as with a counter every device of a kind sends.  Two addresses
// heard at once with the same such number can be linked as one device sending two
// sets.  State is bounded; under a flood, new addresses are ignored, not linked.
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
        // A signal match is at most this many dB from the new address's signal, and
        // this many dB closer than the next candidate, by averages compared once the
        // link has settled; 0 turns signal matching off
        int signal_window;
        int signal_margin;
    };

    static constexpr int no_signal = std::numeric_limits<int>::min();

    // Bounds on what's kept, whatever arrives
    static constexpr size_t max_seen = 16384;
    static constexpr size_t max_pending = 256;
    static constexpr size_t max_recs_total = 32768;
    // Two addresses with the same sequence number must both be heard again, still
    // matching, at least this long after they were first matched
    static constexpr time_t same_confirm = 5;

    // How one call's sequence numbers are read
    struct seq_rules {
        // Numbers run from 0 to modulus - 1, then wrap
        int modulus = 4096;
        // A first number this far after an earlier address's last is a match
        int window = 0;
        const char *method = "sequence";
        // The number is the only evidence: no unique or signal links, it only moves
        // forward, and an address it links gets no second earlier address
        bool only = false;
        // Two addresses heard within this long with the same number, on the same
        // receiver at a similar signal, are one device sending two sets; 0 is off
        time_t same_window = 0;
        const char *same_method = nullptr;
        // Most addresses kept with one fingerprint
        size_t max_recs = 32;
    };

    // carry: key is the next address of pred.  same: key and pred are heard at once
    // with the same sequence number.  join: made outside the linker by join()
    enum class link_kind : uint8_t { carry, same, join };

    // method is "sequence", "signal", params::unique_method or a seq_rules method;
    // nullptr means key only moved to another group because the address it was
    // linked to did
    struct link {
        device_key key;
        device_key pred;
        device_key group;
        const char *method;
        link_kind kind = link_kind::carry;
    };

    randomized_alias_linker(const params& p) :
        p_{p} { }

    // A device sent something with this fingerprint; seq < 0 when there is none, and
    // signal is no_signal when there is none.  source names the receiver the signal was
    // measured on.  Links settled by this call are appended to out.
    void observe(uint64_t fingerprint, const device_key& key, time_t now, int seq,
            std::vector<link>& out, int signal = no_signal, uint64_t source = 0);

    // The same, with the sequence number read by rules
    void observe(uint64_t fingerprint, const device_key& key, time_t now, int seq,
            std::vector<link>& out, int signal, uint64_t source, const seq_rules& rules);

    // Puts key's group into pred's, for a link found outside the linker; both must
    // have been observed and not yet forgotten
    void join(const device_key& key, const device_key& pred, const char *method,
            std::vector<link>& out);

    // The group key is in; key itself when it's in none
    device_key group(const device_key& key);

protected:
    struct rec {
        device_key key;
        time_t first;
        time_t last;
        int last_seq;
        // Running average in 1/16 dB on last_source, over n_signal frames up to 16;
        // one frame's signal swings several dB by channel
        int avg16;
        uint8_t n_signal;
        uint64_t last_source;
        // A later address is linked, or waiting to be, to this one
        bool succeeded;
    };

    // Most earlier addresses a signal link chooses between
    static constexpr size_t max_signal_cands = 8;

    // signal: key waits to be linked to whichever of cands its average signal picks
    enum class pending_kind : uint8_t { carry, same, signal };

    // A link waiting for the earlier address to stay quiet, or for two addresses with
    // the same number to keep it; method nullptr when cancelled
    struct pending {
        uint64_t fingerprint;
        device_key key;
        device_key pred;
        time_t first;
        const char *method;
        pending_kind kind;
        // A sequence match under seq_rules::only, which overrides weaker links for key
        bool strong;
        bool only;
        std::array<device_key, max_signal_cands> cands{};
        uint8_t n_cands = 0;
    };

    // The candidate key's average signal picks once it has settled, or nullptr
    rec *signal_pick(const pending& pl);

    // An address, under any fingerprint
    struct seen {
        time_t first;
        time_t last;
        device_key group;
    };

    void prune(time_t now);
    device_key group_of(const device_key& k) const;
    rec *find_rec(uint64_t fingerprint, const device_key& k);
    // The earlier address of a cancelled link can be linked again
    void release(pending& pl);
    bool has_strong(const device_key& k) const;
    bool push_pending(const pending& pl);
    void merge(const device_key& key, const device_key& pred, const char *method,
            link_kind kind, std::vector<link>& out);
    void settle(time_t now, std::vector<link>& out);

    params p_;

    kis_mutex mutex;
    std::unordered_map<uint64_t, std::vector<rec>> recs_;
    size_t rec_count_ = 0;
    // Across every fingerprint, so an address heard again with another one still
    // counts as heard
    std::unordered_map<device_key, seen> seen_;
    std::vector<pending> pending_;
    time_t last_prune = 0;
};

#endif
