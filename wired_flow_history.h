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

#ifndef __WIRED_FLOW_HISTORY_H__
#define __WIRED_FLOW_HISTORY_H__

// Traffic history of one wired flow: bytes and packets each way, per second over the last
// minute, per minute over the last hour and per hour over the last day.  The vectors it
// gives out have the shape of kis_tracked_rrd's (slot t % 60, (t / 60) % 60, (t / 3600) % 24;
// units per second, then per-second averages over each minute and hour), so the UI reads
// them the same way.
//
// Times are server seconds.  The current second is counted in its slot and folded into the
// running minute and hour totals when a later second arrives; skipped slots are zeroed, at
// most 144 per series however long the gap.  A sample up to max_backstep_s older than the
// newest is counted in the newest second, as packet threads can read the clock a little
// apart; an older one means the clock stepped back, and the history restarts.
//
// Totals are kept as integers and divided only when the vectors are built.  No Kismet
// dependencies, so the tests build it alone.

#include <array>
#include <atomic>
#include <cstdint>
#include <ctime>

struct flow_history {
    enum class series : uint8_t { bytes_ab, bytes_ba, packets_ab, packets_ba };
    static constexpr size_t n_series = 4;

    static constexpr time_t max_backstep_s = 60;

    // One series as kis_tracked_rrd serializes it
    struct rrd_vectors {
        time_t last_time = 0;
        std::array<double, 60> minute{};
        std::array<double, 60> hour{};
        std::array<double, 24> day{};
    };

    // Times before the epoch count as 0, so slot indexes stay in range
    static constexpr time_t clamp_time(time_t t) { return t < 0 ? 0 : t; }

    explicit flow_history(time_t now) :
        last{clamp_time(now)},
        start{clamp_time(now)} { }

    // One packet of the flow at server time now; inline for the common same-second case
    void record(time_t now, bool a_to_b, uint64_t bytes) {
        if (now != last) [[unlikely]]
            move_to(now);

        auto& s = sec[static_cast<size_t>(last % 60)];
        const size_t d = a_to_b ? 0 : 1;
        s[d] = add_sat32(s[d], bytes);
        s[2 + d] = add_sat32(s[2 + d], 1);
    }

    // Moves the history forward to now with no traffic; never back
    void advance_to(time_t now);

    rrd_vectors vectors(series s) const;

    // Everything still in the history for s, the current second included
    uint64_t day_total(series s) const;

    time_t last_time() const { return last; }
    time_t start_time() const { return start; }

    // Hot fields first; the slot arrays are touched one entry at a time
    time_t last = 0;
    time_t start = 0;
    // Finished seconds of the current minute, finished minutes of the current hour
    std::array<uint64_t, n_series> acc_min{};
    std::array<uint64_t, n_series> acc_hr{};
    // The count the owner gives back when this is freed; copies hold nullptr
    std::atomic<size_t>* pool = nullptr;

    // A minute's totals; packets saturate at 2^32 a minute (71 million a second)
    struct min_slot {
        std::array<uint64_t, 2> bytes{};
        std::array<uint32_t, 2> packets{};

        uint64_t get(size_t i) const { return i < 2 ? bytes[i] : packets[i - 2]; }
        void set(size_t i, uint64_t v);
    };

    // Per second, saturating: 4 GiB in one second is 34 Gbit/s
    std::array<std::array<uint32_t, n_series>, 60> sec{};
    std::array<min_slot, 60> min{};
    std::array<std::array<uint64_t, n_series>, 24> hr{};

private:
    void reset(time_t now);

    // Where a sample at now is counted: forward, folded into last, or a restart
    void move_to(time_t now);

    static constexpr uint32_t add_sat32(uint32_t a, uint64_t b) {
        constexpr uint32_t max32 = UINT32_MAX;
        return b >= max32 - a ? max32 : static_cast<uint32_t>(a + b);
    }
};

// record() indexes a second's slot by direction: bytes at 0 and 1, packets at 2 and 3
static_assert(static_cast<size_t>(flow_history::series::bytes_ba) == 1 &&
        static_cast<size_t>(flow_history::series::packets_ab) == 2 &&
        static_cast<size_t>(flow_history::series::packets_ba) == 3);
static_assert(sizeof(flow_history) <= 3264, "flow_history grew; update the wired_flow_history_max memory figures");

#endif
