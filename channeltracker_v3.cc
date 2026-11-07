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

#include "channeltracker_v3.h"

#include <algorithm>
#include <utility>

#include "alertracker.h"
#include "censor.h"
#include "configfile.h"
#include "devicetracker.h"
#include "devicetracker_component.h"
#include "devicetracker_view_workers.h"
#include "trackedelement.h"
#include "kis_net_beast_httpd.h"
#include "devicetracker_component.h"
#include "packetchain.h"
#include "timetracker.h"

void channel_tracker_v3_channel::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    fmt::print(os, "{{");

    json_adapter_v2::json_encode_keyed<std::string>{}(os, "kismet.channelrec.channel", opts, channel);
    json_adapter_v2::json_encode_keyed<double>{}(os, "kismet.channelrec.frequency", opts, frequency);
    json_adapter_v2::json_encode_keyed<decltype(packets_rrd)>{}(os, "kismet.channelrec.packets_rrd", opts, packets_rrd);
    json_adapter_v2::json_encode_keyed<decltype(data_rrd)>{}(os, "kismet.channelrec.data_rrd", opts, data_rrd);
    json_adapter_v2::json_encode_keyed<decltype(device_rrd)>{}(os, "kismet.channelrec.device_rrd", opts, device_rrd);
    json_adapter_v2::json_encode_keyed<kis_tracked_signal_data_v2>{}(os, "kismet.channelrec.signal", opts, signal_data);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.channelrec.retry_frames", opts, retry_frames);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.channelrec.retry_count", opts, retry_count);
    json_adapter_v2::json_encode_keyed<decltype(retry_frames_rrd)>{}(os, "kismet.channelrec.retry_frames_rrd", opts, retry_frames_rrd);
    json_adapter_v2::json_encode_keyed<decltype(retry_rrd)>{}(os, "kismet.channelrec.retry_rrd", opts, retry_rrd);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.channelrec.noise_frames", opts, noise_frames);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.channelrec.noise_retries", opts, noise_retries);
    json_adapter_v2::json_encode_keyed<unsigned int>{}(os, "kismet.channelrec.noise_retry_tx", opts, noise_retry_tx);
    json_adapter_v2::json_encode_keyed<double>{}(os, "kismet.channelrec.noise_retry_pct", opts, noise_retry_pct);
    json_adapter_v2::json_encode_keyed<double>{}(os, "kismet.channelrec.noise_score", opts, noise_score);
    json_adapter_v2::json_encode_keyed<double>{}(os, "kismet.channelrec.noise_baseline_pct", opts, noise_baseline_pct);
    json_adapter_v2::json_encode_keyed<bool>{}(os, "kismet.channelrec.noise", opts, noisy);
    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.channelrec.noise_since", opts, static_cast<uint64_t>(noise_since));

    fmt::print(os, "}}");

    opts->next_key_comma = sv_comma;
}

void channel_tracker_v3_channel::filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
    if (fields.size() == 0) {
        return as_json(os, opts);
    }

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    fmt::print(os, "{{");

    json_adapter_v2::field_group_map subgroup;

    for (const auto& f : fields) {
        switch (json_adapter_v2::consthash(f.first)) {
            case json_adapter_v2::consthash("kismet.channelrec.channel"):
                json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, channel);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.frequency"):
                json_adapter_v2::json_encode_keyed<double>{}(os, f.second.rename, opts, frequency);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.packets_rrd"):
                subgroup.clear();
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed<decltype(packets_rrd)>{}(os, f.second.rename, opts, packets_rrd, subgroup);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.data_rrd"):
                subgroup.clear();
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed<decltype(data_rrd)>{}(os, f.second.rename, opts, data_rrd, subgroup);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.device_rrd"):
                subgroup.clear();
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed<decltype(device_rrd)>{}(os, f.second.rename, opts, device_rrd, subgroup);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.signal"):
                subgroup.clear();
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed<kis_tracked_signal_data_v2>{}(os, f.second.rename, opts, signal_data, subgroup);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.retry_frames"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, retry_frames);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.retry_count"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, retry_count);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.retry_frames_rrd"):
                subgroup.clear();
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed<decltype(retry_frames_rrd)>{}(os, f.second.rename, opts, retry_frames_rrd, subgroup);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.retry_rrd"):
                subgroup.clear();
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed<decltype(retry_rrd)>{}(os, f.second.rename, opts, retry_rrd, subgroup);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.noise_frames"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, noise_frames);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.noise_retries"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, noise_retries);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.noise_retry_tx"):
                json_adapter_v2::json_encode_keyed<unsigned int>{}(os, f.second.rename, opts, noise_retry_tx);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.noise_retry_pct"):
                json_adapter_v2::json_encode_keyed<double>{}(os, f.second.rename, opts, noise_retry_pct);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.noise_score"):
                json_adapter_v2::json_encode_keyed<double>{}(os, f.second.rename, opts, noise_score);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.noise_baseline_pct"):
                json_adapter_v2::json_encode_keyed<double>{}(os, f.second.rename, opts, noise_baseline_pct);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.noise"):
                json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, noisy);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.noise_since"):
                json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, static_cast<uint64_t>(noise_since));
                break;
            default:
                json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
        }
    }

    fmt::print(os, "}}");
    opts->next_key_comma = sv_comma;
}

channel_tracker_v3::channel_tracker_v3() :
    lifetime_global() {

    lock.set_name("channeltracker_v3");

    // Number of seconds we consider a device to be active on a frequency
    // after the last time we see it
    device_decay = 30;

    auto conf = Globalreg::globalreg->kismet_config;

    noise_enabled = conf->fetch_opt_bool("dot11_channel_noise", true);
    noise_window_sec = std::clamp(conf->fetch_opt_uint("dot11_channel_noise_window", 10), 1U, 600U);
    noise_min_frames = std::clamp(conf->fetch_opt_uint("dot11_channel_noise_min_frames", 50), 1U, 1000000U);
    noise_min_tx = std::clamp(conf->fetch_opt_uint("dot11_channel_noise_min_transmitters", 3), 1U,
            static_cast<unsigned int>(channel_noise_window::max_tx));
    noise_set_pct = std::clamp(conf->fetch_opt_as<double>("dot11_channel_noise_retry_pct", 30.0), 0.0, 100.0);
    noise_clear_pct = std::clamp(conf->fetch_opt_as<double>("dot11_channel_noise_clear_pct", 15.0), 0.0, noise_set_pct);
    noise_hold_sec = std::clamp(conf->fetch_opt_uint("dot11_channel_noise_hold", 60), noise_window_sec, 86400U);

    alert_noise_ref = -1;
    if (noise_enabled) {
        auto alertracker = Globalreg::fetch_mandatory_global_as<alert_tracker>();
        alert_noise_ref =
            alertracker->activate_configured_alert("CHANNOISE",
                    "SYSTEM", kis_alert_severity::low,
                    "Many 802.11 frames on a channel are being retransmitted, by several "
                    "transmitters at once.  This usually means interference Kismet can't "
                    "decode: non-Wi-Fi devices, overlapping networks, or a jammer.");
    }

    auto packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>("PACKETCHAIN");

    timetracker =
        Globalreg::fetch_mandatory_global_as<time_tracker>();

    entrytracker =
        Globalreg::fetch_mandatory_global_as<entry_tracker>();


    packetchain->register_handler(&packet_chain_handler, this, CHAINPOS_LOGGING, 0);

    pack_comp_device = packetchain->register_packet_component("DEVICE");

    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>("DEVICETRACKER");

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/channels/channels", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_jsonable_endpoint>(this, lock));

    timer_id = timetracker->register_timer(SERVER_TIMESLICES_SEC, nullptr, 1,
            [this](int evt_id) -> int {
                return gather_devices_event(evt_id);
            });
}

channel_tracker_v3::~channel_tracker_v3() {
    // Remove the handler before taking the lock; remove_handler() waits for packet threads
    // still in packet_chain_handler(), which takes it
    auto packetchain = Globalreg::fetch_global_as<packet_chain>("PACKETCHAIN");
    if (packetchain != nullptr)
        packetchain->remove_handler(&packet_chain_handler, CHAINPOS_LOGGING);

    // Before taking the lock; the timer callback takes it too
    auto timetracker = Globalreg::fetch_global_as<time_tracker>("TIMETRACKER");
    if (timetracker != nullptr)
        timetracker->remove_timer(timer_id);

    kis_lock_guard<kis_mutex> lk(lock, __func__);

    Globalreg::globalreg->remove_global(global_name());
}

void channel_tracker_v3::trigger_deferred_startup() {
    gather_devices_event(0);
}

class channeltracker_v3_device_worker : public device_tracker_view_worker {
public:
    channeltracker_v3_device_worker(channel_tracker_v3 *channelv3) {
        this->channelv3 = channelv3;
        stime = time(0);
    }

    virtual ~channeltracker_v3_device_worker() { }

    // Count all the devices.  We use a filter worker but 'match' on all
    // and count them into our local map
    virtual bool match_device(std::shared_ptr<kis_tracked_device_base> device) override {
        auto freq = device->get_frequency();
        if (freq == 0)
            return false;

        auto i = device_count.find(freq);

        if (i != device_count.end()) {
            if (device->get_last_time() > (stime - channelv3->device_decay))
                i->second++;
        } else {
            if (device->get_last_time() > (stime - channelv3->device_decay))
                device_count[freq] = 1;
            else
                device_count[freq] = 0;
        }

        return false;
    }

    // Send it back to our channel tracker
    virtual void finalize() override {
        channelv3->update_device_counts(device_count, stime);
    }

protected:
    channel_tracker_v3 *channelv3;

    std::unordered_map<double, unsigned int> device_count;

    time_t stime;
};


int channel_tracker_v3::gather_devices_event(int event_id __attribute__((unused))) {
    channeltracker_v3_device_worker worker(this);
    devicetracker->do_readonly_device_work(worker);

    if (noise_enabled)
        evaluate_noise(Globalreg::globalreg->last_tv_sec);

    return 1;
}

// Close the noise windows that have run their time.  A window's retry percentage leaves out
// its worst transmitter, so one station retrying to a far-away peer can't mark the channel,
// and the score is scaled down until enough frames and enough retrying transmitters are
// heard.  Windows with too few frames don't change the flag, so an idle channel keeps its
// state until the hold time runs out.  The baseline only learns from windows that aren't
// flagged, so it stays the channel's usual level through a noisy spell.
void channel_tracker_v3::evaluate_noise(time_t now) {
    struct noise_alert {
        std::string channel;
        double mhz;
        double pct;
        uint64_t frames;
        unsigned int tx;
        double baseline;
    };

    std::vector<noise_alert> alerts;

    {
        kis_lock_guard<kis_mutex> lk(lock, __func__);

        for (auto& fi : frequency_map) {
            auto& f = fi.second;
            auto& w = f.noise_win;

            auto hold_expired = [&]() {
                if (f.noisy && now - f.noise_last_qualified >= static_cast<time_t>(noise_hold_sec)) {
                    f.noisy = false;
                    f.noise_since = 0;
                    f.noise_score = 0;
                }
            };

            if (w.start == 0) {
                hold_expired();
                continue;
            }

            // Clock stepped back; start over
            if (now < w.start) {
                w.reset(now);
                continue;
            }

            if (now - w.start < static_cast<time_t>(noise_window_sec))
                continue;

            // Retrying transmitters, and the one retrying the most
            unsigned int retry_tx = 0;
            const channel_noise_window::tx_rec *worst = nullptr;

            for (size_t i = 0; i < w.n_tx; i++) {
                const auto& t = w.tx[i];

                if (t.retries >= 2)
                    retry_tx++;

                if (t.retries > 0 && (worst == nullptr || t.retries > worst->retries))
                    worst = &t;
            }

            auto frames = w.frames;
            auto retries = w.retries;

            if (worst != nullptr) {
                frames -= worst->frames;
                retries -= worst->retries;
            }

            const double pct = frames > 0 ? 100.0 * retries / frames : 0.0;
            const double conf_frames = std::min(1.0, static_cast<double>(w.frames) / noise_min_frames);
            const double conf_tx = std::min(1.0, static_cast<double>(retry_tx) / noise_min_tx);

            f.noise_frames = w.frames;
            f.noise_retries = w.retries;
            f.noise_retry_tx = retry_tx;

            if (w.frames >= noise_min_frames) {
                f.noise_last_qualified = now;
                f.noise_retry_pct = pct;
                f.noise_score = pct * conf_frames * conf_tx;

                if (!f.noisy && f.noise_score >= noise_set_pct) {
                    f.noisy = true;
                    f.noise_since = now;

                    if (alert_noise_ref >= 0)
                        alerts.push_back(noise_alert{f.noise_channel, f.frequency / 1000,
                                pct, w.frames, retry_tx, f.noise_baseline_pct});
                } else if (f.noisy && f.noise_score < noise_clear_pct) {
                    f.noisy = false;
                    f.noise_since = 0;
                }

                if (!f.noisy) {
                    if (f.noise_baseline_pct < 0)
                        f.noise_baseline_pct = pct;
                    else
                        f.noise_baseline_pct = 0.9 * f.noise_baseline_pct + 0.1 * pct;
                }
            } else {
                hold_expired();
            }

            // An idle channel stops evaluating until it hears another frame
            w.reset(w.frames > 0 ? now : 0);
        }
    }

    if (alerts.empty())
        return;

    auto alertracker = Globalreg::fetch_global_as<alert_tracker>();
    if (alertracker == nullptr)
        return;

    for (const auto& a : alerts) {
        const auto mhz = fmt::format("{:.0f}", a.mhz);
        const auto chan = a.channel.empty() ? mhz : a.channel;

        // Sources that name channels by frequency would otherwise read "2412 (2412 MHz)"
        const auto where = chan == mhz ? fmt::format("{} MHz", mhz) :
            fmt::format("Channel {} ({} MHz)", chan, mhz);
        const auto usual = a.baseline < 0 ? std::string{} :
            fmt::format("; usually {:.0f}%", a.baseline);

        alertracker->raise_alert(alert_noise_ref, nullptr,
                mac_addr{}, mac_addr{}, mac_addr{}, mac_addr{}, chan,
                censor::format("{} may have interference: {:.0f}% of the 802.11 data and "
                    "management frames were retries over the last {} seconds, from {} retrying "
                    "transmitters ({} frames, the worst transmitter left out{}).", where, a.pct,
                    noise_window_sec, a.tx, a.frames, usual));
    }
}

void channel_tracker_v3::update_device_counts(std::unordered_map<double, unsigned int> in_counts, time_t ts) {
    kis_lock_guard<kis_mutex> lk(lock, __func__);

    for (const auto& i : in_counts) {
        auto const& imi_idx = frequency_map.try_emplace(i.first, channel_tracker_v3_channel{});
        auto& freq = imi_idx.first->second;

        if (imi_idx.second) {
            freq.frequency = i.first;
        }

        freq.device_rrd.add_sample(i.second, ts);
    }
}

int channel_tracker_v3::packet_chain_handler(CHAINCALL_PARMS) {
    channel_tracker_v3 *cv3 = (channel_tracker_v3 *) auxdata;

    kis_lock_guard<kis_mutex> lk(cv3->lock, __func__);

    // auto l1info = in_pack->fetch<kis_layer1_packinfo>(cv3->pack_comp_l1data);

    // Nothing to do with no l1info
    if (!in_pack->signal_info.data_ok)
        return 1;

    // Retries count once however many sources heard them, and only from frames that decoded
    const bool retry_ok = in_pack->common_info.common_info_ok && in_pack->common_info.retry_valid &&
        !in_pack->duplicate && !in_pack->error && !(in_pack->crc_ok && !in_pack->checksum_valid);
    const bool retry = in_pack->common_info.retry;

    auto count_retry = [retry](channel_tracker_v3_channel& c) {
        c.retry_frames++;
        c.retry_frames_rrd.add_sample(1, Globalreg::globalreg->last_tv_sec);

        if (retry) {
            c.retry_count++;
            c.retry_rrd.add_sample(1, Globalreg::globalreg->last_tv_sec);
        }
    };

    // Find or make a frequency record if we know our frequency
    if (in_pack->signal_info.freq_khz != 0) {
        auto const& imi_idx = cv3->frequency_map.try_emplace(in_pack->signal_info.freq_khz, channel_tracker_v3_channel{});
        auto& freq = imi_idx.first->second;

        if (imi_idx.second) {
            freq.frequency = in_pack->signal_info.freq_khz;
        }

        freq.signal_data.append_signal(in_pack->signal_info, false, 0);
        freq.packets_rrd.add_sample(1, Globalreg::globalreg->last_tv_sec);

        if (in_pack->common_info.common_info_ok) {
            freq.data_rrd.add_sample(in_pack->common_info.datasize,
                    Globalreg::globalreg->last_tv_sec);
        }

        if (retry_ok) {
            count_retry(freq);

            if (cv3->noise_enabled) {
                if (freq.noise_win.start == 0)
                    freq.noise_win.start = Globalreg::globalreg->last_tv_sec;

                // Named once, for the alert
                if (freq.noise_channel.empty() && !(in_pack->common_info.channel == "0" ||
                            in_pack->common_info.channel.empty()))
                    freq.noise_channel = in_pack->common_info.channel.substr(0, 32);

                freq.noise_win.add(in_pack->common_info.link_tx.longmac, retry);
            }
        }
    }

    if (in_pack->common_info.common_info_ok) {
        if (!(in_pack->common_info.channel == "0" || in_pack->common_info.channel == "")) {
            auto const& smi_idx =
                cv3->channel_map.try_emplace(in_pack->common_info.channel, channel_tracker_v3_channel{});
            auto& chan = smi_idx.first->second;

            if (smi_idx.second) {
                chan.channel = in_pack->common_info.channel;
                chan.frequency = in_pack->signal_info.freq_khz;
            }

            chan.signal_data.append_signal(in_pack->signal_info, false, 0);
            chan.packets_rrd.add_sample(1, Globalreg::globalreg->last_tv_sec);
            chan.data_rrd.add_sample(in_pack->common_info.datasize, Globalreg::globalreg->last_tv_sec);

            if (retry_ok)
                count_retry(chan);
        }
    }

    return 1;
}

void channel_tracker_v3::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    fmt::print(os, "{{");

    json_adapter_v2::json_encode_keyed_map<channel_map_iter_t>{}(os, "kismet.channeltracker.channel_map", opts, channel_map.begin(), channel_map.end());
    json_adapter_v2::json_encode_keyed_map<frequency_map_iter_t>{}(os, "kismet.channeltracker.frequency_map", opts, frequency_map.begin(), frequency_map.end());

    fmt::print(os, "}}");

    opts->next_key_comma = sv_comma;
}

void channel_tracker_v3::filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts,
        const json_adapter_v2::field_group_map& fields) {

    if (fields.size() == 0) {
        return as_json(os, opts);
    }

    auto sv_comma = opts->next_key_comma;
    opts->next_key_comma = false;

    fmt::print(os, "{{");

    json_adapter_v2::field_group_map subgroup;

    for (const auto& f : fields) {
        switch (json_adapter_v2::consthash(f.first)) {
            case json_adapter_v2::consthash("kismet.channeltracker.channel_map"):
                subgroup.clear();
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed_map<channel_map_iter_t>{}(os, f.second.rename, opts,
                        channel_map.begin(), channel_map.end(), subgroup);
                break;
            case json_adapter_v2::consthash("kismet.channeltracker.frequency_map"):
                subgroup.clear();
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::json_encode_keyed_map<frequency_map_iter_t>{}(os, f.second.rename, opts,
                        frequency_map.begin(), frequency_map.end(), subgroup);
                break;
        }
    }

    fmt::print(os, "}}");

    opts->next_key_comma = sv_comma;
}

