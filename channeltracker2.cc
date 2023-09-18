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

#include "util.h"

#include "channeltracker2.h"
#include "json_adapter.h"
#include "devicetracker.h"
#include "devicetracker_component.h"
#include "devicetracker_view_workers.h"
#include "packinfo_signal.h"

channel_tracker_v2::channel_tracker_v2() :
    lifetime_global() {

    lock.set_name("channeltrackerv2");

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
	pack_comp_common = packetchain->register_packet_component("COMMON");
	pack_comp_l1data = packetchain->register_packet_component("RADIODATA");

    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>("DEVICETRACKER");

    frequency_map =
        entrytracker->register_and_get_field_as<tracker_element_double_map>(
                "kismet.channeltracker.frequency_map", 
                tracker_element_factory<tracker_element_double_map>(),
                "Usage by frequency");

    channel_map =
        entrytracker->register_and_get_field_as<tracker_element_string_map>(
                "kismet.channeltracker.channel_map",
                tracker_element_factory<tracker_element_string_map>(),
                "Usage by named channel");

    channel_entry_id = 
        entrytracker->register_field("kismet.channeltracker.channel",
                tracker_element_factory<channel_tracker_v2_channel>(),
                "channel/frequency entry");

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_route("/channels/channels", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection>) {
                    auto ret = std::make_shared<tracker_element_map>();
                    ret->insert(channel_map);
                    ret->insert(frequency_map);
                    return ret;
                }, lock));


    timer_id = timetracker->register_timer(SERVER_TIMESLICES_SEC, nullptr, 1, 
            [this](int evt_id) -> int {
                return gather_devices_event(evt_id);
            });
}

channel_tracker_v2::~channel_tracker_v2() {
    kis_lock_guard<kis_mutex> lk(lock, "~channel_tracker_v2");

    auto timetracker = Globalreg::fetch_global_as<time_tracker>("TIMETRACKER");
    if (timetracker != nullptr)
        timetracker->remove_timer(timer_id);

    auto packetchain = Globalreg::fetch_global_as<packet_chain>("PACKETCHAIN");
    if (packetchain != nullptr)
        packetchain->remove_handler(&packet_chain_handler, CHAINPOS_LOGGING);

    Globalreg::globalreg->remove_global("CHANNEL_TRACKER");
}

void channel_tracker_v2::trigger_deferred_startup() {
    gather_devices_event(0);
}

class channeltracker_v2_device_worker : public device_tracker_view_worker {
public:
    channeltracker_v2_device_worker(channel_tracker_v2 *channelv2) {
        this->channelv2 = channelv2;
        stime = time(0);
    }

    virtual ~channeltracker_v2_device_worker() { }

    // Count all the devices.  We use a filter worker but 'match' on all
    // and count them into our local map
    virtual bool match_device(std::shared_ptr<kis_tracked_device_base> device) override {
        auto freq = device->get_frequency();
        if (freq == 0)
            return false;

        auto i = device_count.find(freq);

        if (i != device_count.end()) {
            if (device->get_last_time() > (stime - channelv2->device_decay))
                i->second++;
        } else {
            if (device->get_last_time() > (stime - channelv2->device_decay))
                device_count[freq] = 1;
            else
                device_count[freq] = 0;
        }

        return false;
    }

    // Send it back to our channel tracker
    virtual void finalize() override {
        channelv2->update_device_counts(device_count, stime);
    }

protected:
    channel_tracker_v2 *channelv2;

    std::unordered_map<double, unsigned int> device_count;

    time_t stime;
};


int channel_tracker_v2::gather_devices_event(int event_id __attribute__((unused))) {
    channeltracker_v2_device_worker worker(this);
    devicetracker->do_readonly_device_work(worker);

    return 1;
}

void channel_tracker_v2::update_device_counts(std::unordered_map<double, unsigned int> in_counts, time_t ts) {
    kis_lock_guard<kis_mutex> lk(lock, "channel_tracker_v2 update_device_counts");

    // frequency_map->clear();

    for (const auto& i : in_counts) {
        auto imi = frequency_map->find(i.first);

        // _MSG_DEBUG("Freq {} devices {}", i.first, i.second);

        // Make a frequency
        if (imi == frequency_map->end()) {
            auto freq_channel = entrytracker->get_shared_instance_as<channel_tracker_v2_channel>(channel_entry_id);
            frequency_map->insert(i.first, freq_channel);
            freq_channel->set_frequency(i.first);
            freq_channel->get_device_rrd()->add_sample(i.second, ts);
        } else {
            auto freq_channel = static_cast<channel_tracker_v2_channel *>(imi->second.get());
            freq_channel->get_device_rrd()->add_sample(i.second, ts);
        }

    }
}

int channel_tracker_v2::packet_chain_handler(CHAINCALL_PARMS) {
    channel_tracker_v2 *cv2 = (channel_tracker_v2 *) auxdata;

    kis_lock_guard<kis_mutex> lk(cv2->lock, "channel_tracker_v2 packet_chain_handler");

    auto l1info = in_pack->fetch<kis_layer1_packinfo>(cv2->pack_comp_l1data);
	auto common = in_pack->fetch<kis_common_info>(cv2->pack_comp_common);

    // Nothing to do with no l1info
    if (l1info == nullptr)
        return 1;

    // Find or make a frequency record if we know our frequency
    if (l1info->freq_khz != 0) {
        auto imi = cv2->frequency_map->find(l1info->freq_khz);

        if (imi == cv2->frequency_map->end()) {
            auto freq_channel =
                cv2->entrytracker->get_shared_instance_as<channel_tracker_v2_channel>(cv2->channel_entry_id);
            freq_channel->set_frequency(l1info->freq_khz);
            cv2->frequency_map->insert(l1info->freq_khz, freq_channel);

            freq_channel->get_signal_data()->append_signal(*l1info, false, 0);
            freq_channel->get_packets_rrd()->add_sample(1, Globalreg::globalreg->last_tv_sec);

            if (common != NULL) {
                freq_channel->get_data_rrd()->add_sample(common->datasize, Globalreg::globalreg->last_tv_sec);
            }

        } else {
            auto freq_channel = static_cast<channel_tracker_v2_channel *>(imi->second.get());

            freq_channel->get_signal_data()->append_signal(*l1info, false, 0);
            freq_channel->get_packets_rrd()->add_sample(1, Globalreg::globalreg->last_tv_sec);

            if (common != NULL) {
                freq_channel->get_data_rrd()->add_sample(common->datasize, Globalreg::globalreg->last_tv_sec);
            }
        }
    }

    if (common != nullptr) {
        if (!(common->channel == "0") && !(common->channel == "")) {
            auto smi = cv2->channel_map->find(common->channel);

            if (smi == cv2->channel_map->end()) {
                auto chan_channel =
                    cv2->entrytracker->get_shared_instance_as<channel_tracker_v2_channel>(cv2->channel_entry_id);

                chan_channel->set_channel(common->channel);
                cv2->channel_map->insert(common->channel, chan_channel);

                chan_channel->get_signal_data()->append_signal(*l1info, false, 0);
                chan_channel->get_packets_rrd()->add_sample(1, Globalreg::globalreg->last_tv_sec);

                if (common != NULL) {
                    chan_channel->get_data_rrd()->add_sample(common->datasize, Globalreg::globalreg->last_tv_sec);
                }

            } else {
                auto chan_channel = static_cast<channel_tracker_v2_channel *>(smi->second.get());

                chan_channel->get_signal_data()->append_signal(*l1info, false, 0);
                chan_channel->get_packets_rrd()->add_sample(1, Globalreg::globalreg->last_tv_sec);

                if (common != NULL) {
                    chan_channel->get_data_rrd()->add_sample(common->datasize, Globalreg::globalreg->last_tv_sec);
                }
            }
        }
    }


    return 1;
}

