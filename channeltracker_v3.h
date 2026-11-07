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

#ifndef __CHANNELTRACKER_V3__
#define __CHANNELTRACKER_V3__

#include <array>
#include <unordered_map>

#include "devicetracker_component_v2.h"
#include "json_adapter_v2.h"
#include "rrd_v2.h"

// One noise window of retry-capable frames on a frequency, with a bounded table of the
// transmitters heard; transmitters past the table count only in the totals
struct channel_noise_window {
    static constexpr size_t max_tx = 32;

    struct tx_rec {
        uint64_t addr;
        uint64_t frames;
        uint64_t retries;
    };

    std::array<tx_rec, max_tx> tx{};
    size_t n_tx = 0;
    uint64_t frames = 0;
    uint64_t retries = 0;
    time_t start = 0;

    void reset(time_t now) {
        n_tx = 0;
        frames = 0;
        retries = 0;
        start = now;
    }

    void add(uint64_t addr, bool retry) {
        frames++;
        retries += retry;

        for (size_t i = 0; i < n_tx; i++) {
            if (tx[i].addr == addr) {
                tx[i].frames++;
                tx[i].retries += retry;
                return;
            }
        }

        if (n_tx < max_tx)
            tx[n_tx++] = tx_rec{addr, 1, retry};
    }
};

class channel_tracker_v3;
class channel_tracker_v3_channel : public json_adapter_v2::jsonable {
    friend class channel_tracker_v3;

public:
    channel_tracker_v3_channel() :
        channel{"unknown"},
        frequency{0} { }

    channel_tracker_v3_channel(channel_tracker_v3_channel&& c) :
        channel{c.channel},
        frequency{c.frequency},
        packets_rrd{std::move(c.packets_rrd)},
        data_rrd{std::move(c.data_rrd)},
        device_rrd{std::move(c.device_rrd)},
        retry_frames{c.retry_frames},
        retry_count{c.retry_count},
        retry_frames_rrd{std::move(c.retry_frames_rrd)},
        retry_rrd{std::move(c.retry_rrd)},
        noise_win{c.noise_win},
        noise_channel{std::move(c.noise_channel)} { }

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    std::string channel;
    double frequency;
    // Packets and bytes per second, and devices active on the frequency
    kis_rrd_v2<kis_rrd_v2_sum_aggregator> packets_rrd;
    kis_rrd_v2<kis_rrd_v2_sum_aggregator> data_rrd;
    kis_rrd_v2<kis_rrd_v2_peak_aggregator> device_rrd;
    kis_tracked_signal_data_v2 signal_data;

    // Frames whose retry flag means something (802.11 data and management), and how many
    // of them were retries; totals and per second
    uint64_t retry_frames{0};
    uint64_t retry_count{0};
    kis_rrd_v2<kis_rrd_v2_sum_aggregator> retry_frames_rrd;
    kis_rrd_v2<kis_rrd_v2_sum_aggregator> retry_rrd;

    // Noise estimate, kept per frequency only: the window being filled, and the result of
    // the last one closed
    channel_noise_window noise_win;
    uint64_t noise_frames{0};
    uint64_t noise_retries{0};
    unsigned int noise_retry_tx{0};
    double noise_retry_pct{0};
    double noise_score{0};
    double noise_baseline_pct{-1};
    bool noisy{false};
    time_t noise_since{0};
    time_t noise_last_qualified{0};
    std::string noise_channel;
};

template<> struct json_adapter_v2::json_encode<channel_tracker_v3_channel> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, channel_tracker_v3_channel& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, channel_tracker_v3_channel *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, channel_tracker_v3_channel& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, channel_tracker_v3_channel *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};

class channel_tracker_v3 : public lifetime_global, public deferred_startup,
    public json_adapter_v2::jsonable {
public:
    static std::string global_name() { return "CHANNEL_TRACKER"; }

    static std::shared_ptr<channel_tracker_v3> create_channeltracker() {
        std::shared_ptr<channel_tracker_v3> mon(new channel_tracker_v3());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        Globalreg::globalreg->register_deferred_global(mon);
        return mon;
    }

private:
    channel_tracker_v3();

public:
    virtual ~channel_tracker_v3();

    virtual void trigger_deferred_startup() override;

    // Update device counts - kept public so that the worker can access it
    int device_decay;
    void update_device_counts(std::unordered_map<double, unsigned int> in_counts, time_t in_ts);

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override;
    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override;

protected:
    kis_mutex lock;

    std::shared_ptr<device_tracker> devicetracker;
    std::shared_ptr<time_tracker> timetracker;
    std::shared_ptr<entry_tracker> entrytracker;

    // packetchain callback
    static int packet_chain_handler(CHAINCALL_PARMS);

    // Seen channels as string-named channels, aggregated across all the phys
    using channel_map_iter_t = std::unordered_map<std::string, channel_tracker_v3_channel>::iterator;
    std::unordered_map<std::string, channel_tracker_v3_channel> channel_map;

    using frequency_map_iter_t = std::unordered_map<double, channel_tracker_v3_channel>::iterator;
    std::unordered_map<double, channel_tracker_v3_channel> frequency_map;

    int pack_comp_devinfo, pack_comp_device;

    int timer_id;
    int gather_devices_event(int event_id);

    // Retry-based noise detection; see dot11_channel_noise in kismet_80211.conf
    bool noise_enabled;
    unsigned int noise_window_sec;
    unsigned int noise_min_frames;
    unsigned int noise_min_tx;
    double noise_set_pct;
    double noise_clear_pct;
    unsigned int noise_hold_sec;
    int alert_noise_ref;

    void evaluate_noise(time_t now);
};

template<> struct json_adapter_v2::json_encode<channel_tracker_v3> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, channel_tracker_v3& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, channel_tracker_v3 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, channel_tracker_v3& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, channel_tracker_v3 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};

#endif /* __CHANNELTRACKER_V3__ */
