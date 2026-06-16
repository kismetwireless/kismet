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

#include <utility>

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

	json_adapter_v2::encode_keyed(os, "kismet.channelrec.channel", opts, channel);
	json_adapter_v2::encode_keyed(os, "kismet.channelrec.frequency", opts, frequency);
	json_adapter_v2::encode_keyed<json_adapter_v2::jsonable>(os, "kismet.channelrec.packets_rrd", opts, &packets_rrd);
	json_adapter_v2::encode_keyed<json_adapter_v2::jsonable>(os, "kismet.channelrec.data_rrd", opts, &data_rrd);
	json_adapter_v2::encode_keyed<json_adapter_v2::jsonable>(os, "kismet.channelrec.device_rrd", opts, &device_rrd);
	json_adapter_v2::encode_keyed<json_adapter_v2::jsonable>(os, "kismet.channelrec.signal", opts, &signal_data);

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
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, channel);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.frequency"):
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, frequency);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.packets_rrd"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::encode_filtered_keyed(os, f.first, opts, packets_rrd, subgroup);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.data_rrd"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::encode_filtered_keyed(os, f.first, opts, data_rrd, subgroup);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.device_rrd"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::encode_filtered_keyed(os, f.first, opts, device_rrd, subgroup);
                break;
            case json_adapter_v2::consthash("kismet.channelrec.signal"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::encode_filtered_keyed(os, f.first, opts, signal_data, subgroup);
                break;
            default:
                json_adapter_v2::encode_keyed(os, f.second.rename, opts, 0);
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

    auto packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>("PACKETCHAIN");

    timetracker =
        Globalreg::fetch_mandatory_global_as<time_tracker>();

    entrytracker =
        Globalreg::fetch_mandatory_global_as<entry_tracker>();


    packetchain->register_handler(&packet_chain_handler, this, CHAINPOS_LOGGING, 0);

	pack_comp_device = packetchain->register_packet_component("DEVICE");
	pack_comp_l1data = packetchain->register_packet_component("RADIODATA");

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
    kis_lock_guard<kis_mutex> lk(lock, __func__);

    auto timetracker = Globalreg::fetch_global_as<time_tracker>("TIMETRACKER");
    if (timetracker != nullptr)
        timetracker->remove_timer(timer_id);

    auto packetchain = Globalreg::fetch_global_as<packet_chain>("PACKETCHAIN");
    if (packetchain != nullptr)
        packetchain->remove_handler(&packet_chain_handler, CHAINPOS_LOGGING);

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

    return 1;
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

    auto l1info = in_pack->fetch<kis_layer1_packinfo>(cv3->pack_comp_l1data);

    // Nothing to do with no l1info
    if (l1info == nullptr)
        return 1;

    // Find or make a frequency record if we know our frequency
    if (l1info->freq_khz != 0) {
		auto const& imi_idx = cv3->frequency_map.try_emplace(l1info->freq_khz, channel_tracker_v3_channel{});
		auto& freq = imi_idx.first->second;

		if (imi_idx.second) {
			freq.frequency = l1info->freq_khz;
		}

		freq.signal_data.append_signal(*l1info, false, 0);
		freq.packets_rrd.add_sample(1, Globalreg::globalreg->last_tv_sec);

		if (in_pack->common_info_ok) {
			freq.data_rrd.add_sample(in_pack->common_info.datasize,
					Globalreg::globalreg->last_tv_sec);
		}
    }

    if (in_pack->common_info_ok) {
        if (!(in_pack->common_info.channel == "0" || in_pack->common_info.channel == "")) {
			auto const& smi_idx =
                cv3->channel_map.try_emplace(in_pack->common_info.channel, channel_tracker_v3_channel{});
			auto& chan = smi_idx.first->second;

			if (smi_idx.second) {
				chan.channel = in_pack->common_info.channel;
				chan.frequency = l1info->freq_khz;
			}

			chan.signal_data.append_signal(*l1info, false, 0);
			chan.packets_rrd.add_sample(1, Globalreg::globalreg->last_tv_sec);
			chan.data_rrd.add_sample(in_pack->common_info.datasize, Globalreg::globalreg->last_tv_sec);
		}
    }

    return 1;
}

void channel_tracker_v3::as_json(std::ostream& os, json_adapter_v2::opts *opts) {
	auto sv_comma = opts->next_key_comma;
	opts->next_key_comma = false;

	fmt::print(os, "{{");

	json_adapter_v2::encode_keyed_map<json_adapter_v2::jsonable&>(os, "kismet.channeltracker.channel_map", opts, channel_map.begin(), channel_map.end());
	json_adapter_v2::encode_keyed_map<json_adapter_v2::jsonable&>(os, "kismet.channeltracker.frequency_map", opts, frequency_map.begin(), frequency_map.end());

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
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::encode_filtered_keyed_map<json_adapter_v2::jsonable>(os, f.second.rename, opts, subgroup,
                        channel_map.begin(), channel_map.end());
                break;
            case json_adapter_v2::consthash("kismet.channeltracker.frequency_map"):
                json_adapter_v2::group_fields(f.second.subfields, subgroup);
                json_adapter_v2::encode_filtered_keyed_map<json_adapter_v2::jsonable>(os, f.second.rename, opts, subgroup,
                        frequency_map.begin(), frequency_map.end());
                break;
        }
    }

	fmt::print(os, "}}");

    opts->next_key_comma = sv_comma;
}

