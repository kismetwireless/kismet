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
#include "packinfo_signal.h"

channel_tracker_v2::channel_tracker_v2(global_registry *in_globalreg) :
    tracker_component(),
    kis_net_httpd_cppstream_handler() {

    // Number of seconds we consider a device to be active on a frequency 
    // after the last time we see it
    device_decay = 5;

    register_fields();
    reserve_fields(NULL);

    auto packetchain = Globalreg::fetch_mandatory_global-as<packet_chain>("PACKETCHAIN");

    packetchain->RegisterHandler(&packet_chain_handler, this, CHAINPOS_LOGGING, 0);

	pack_comp_device = packetchain->RegisterPacketComponent("DEVICE");
	pack_comp_common = packetchain->RegisterPacketComponent("COMMON");
	pack_comp_l1data = packetchain->RegisterPacketComponent("RADIODATA");

    devicetracker =
        Globalreg::fetch_mandatory_global-as<device_tracker>("DEVICETRACKER");

    struct timeval trigger_tm;
    trigger_tm.tv_sec = time(0) + 1;
    trigger_tm.tv_usec = 0;

    timetracker =
        Globalreg::fetch_mandatory_global-as<time_tracker>("TIMETRACKER");

    timer_id = timetracker->RegisterTimer(0, &trigger_tm, 0, this);

    Bind_Httpd_Server();
}

channel_tracker_v2::~channel_tracker_v2() {
    local_locker locker(&lock);

    auto timetracker = Globalreg::FetchGlobalAs<time_tracker>("TIMETRACKER");
    if (timetracker != nullptr)
        timetracker->RemoveTimer(timer_id);

    auto packetchain = Globalreg::FetchGlobalAs<packet_chain>("PACKETCHAIN");
    if (packetchain != nullptr)
        packetchain->RemoveHandler(&packet_chain_handler, CHAINPOS_LOGGING);

    Globalreg::globalreg->RemoveGlobal("CHANNEL_TRACKER");
}

void channel_tracker_v2::register_fields() {
    tracker_component::register_fields();

    register_field("kismet.channeltracker.frequency_map", "Frequency use", &frequency_map);
    register_field("kismet.channeltracker.channel_map", "Channel use", &channel_map);

    channel_entry_id = 
        register_field("kismet.channeltracker.channel",
                tracker_element_factory<channel_tracker_v2_channel>(),
                "channel/frequency entry");
}

bool channel_tracker_v2::httpd_verify_path(const char *path, const char *method) {
    if (strcmp(method, "GET") != 0)
        return false;

    if (!Httpd_CanSerialize(path))
        return false;

    std::string stripped = Httpd_StripSuffix(path);

    if (stripped == "/channels/channels")
        return true;

    return false;
}

void channel_tracker_v2::httpd_create_stream_response(
        kis_net_httpd *httpd __attribute__((unused)),
        kis_net_httpd_connection *connection __attribute__((unused)),
        const char *path, const char *method, 
        const char *upload_data __attribute__((unused)),
        size_t *upload_data_size __attribute__((unused)), 
        std::stringstream &stream) {

    if (strcmp(method, "GET") != 0) {
        return;
    }

    std::string stripped = Httpd_StripSuffix(path);

    if (stripped == "/channels/channels") {
        local_shared_locker locker(&lock);
        auto cv2 = Globalreg::fetch_mandatory_global-as<channel_tracker_v2>("CHANNEL_TRACKER");
        Httpd_Serialize(path, stream, cv2);
    }

}

class channeltracker_v2_device_worker : public device_tracker_filter_worker {
public:
    channeltracker_v2_device_worker(channel_tracker_v2 *channelv2) {
        this->channelv2 = channelv2;
        stime = time(0);
    }

    virtual ~channeltracker_v2_device_worker() { }

    // Count all the devices.  We use a filter worker but 'match' on all
    // and count them into our local map
    virtual bool MatchDevice(device_tracker *devicetracker __attribute__((unused)),
            std::shared_ptr<kis_tracked_device_base> device) {
        if (device == NULL)
            return false;

        if (device->get_frequency() == 0)
            return false;

        {
            local_locker lock(&workermutex);

            auto i = device_count.find(device->get_frequency());

            if (i != device_count.end()) {
                if (device->get_last_time() > (stime - channelv2->device_decay))
                    i->second++;
            } else {
                if (device->get_last_time() > (stime - channelv2->device_decay))
                    device_count.insert(std::make_pair(device->get_frequency(), 1));
                else
                    device_count.insert(std::make_pair(device->get_frequency(), 0));
            }
        }

        return false;
    }

    // Send it back to our channel tracker
    virtual void Finalize(device_tracker *devicetracker __attribute__((unused))) {
        channelv2->update_device_counts(device_count);
    }

protected:
    channel_tracker_v2 *channelv2;

    std::map<double, unsigned int> device_count;

    time_t stime;

    kis_recursive_timed_mutex workermutex;
};


int channel_tracker_v2::timetracker_event(int event_id __attribute__((unused))) {
    local_locker locker(&lock);

    auto worker = std::make_shared<channeltracker_v2_device_worker>(this);
    devicetracker->MatchOnReadonlyDevices(worker);

    // Reschedule
    struct timeval trigger_tm;
    trigger_tm.tv_sec = time(0) + 1;
    trigger_tm.tv_usec = 0;

    timer_id = timetracker->RegisterTimer(0, &trigger_tm, 0, this);

    return 1;
}

void channel_tracker_v2::update_device_counts(std::map<double, unsigned int> in_counts) {
    local_locker locker(&lock);
    time_t ts = time(0);

    for (auto i : in_counts) {
        auto imi = frequency_map->find(i.first);

        // If we can't find the device, skip it
        if (imi == frequency_map->end())
            continue;

        // Update the device RRD for the count
        std::static_pointer_cast<channel_tracker_v2_channel>(imi->second)->get_device_rrd()->add_sample(i.second, ts);
    }
}

int channel_tracker_v2::packet_chain_handler(CHAINCALL_PARMS) {
    channel_tracker_v2 *cv2 = (channel_tracker_v2 *) auxdata;

    local_locker locker(&(cv2->lock));

    auto l1info = in_pack->fetch<kis_layer1_packinfo>(cv2->pack_comp_l1data);
	auto common = in_pack->fetch<kis_common_info>(cv2->pack_comp_common);

    // Nothing to do with no l1info
    if (l1info == nullptr)
        return 1;

    std::shared_ptr<channel_tracker_v2_channel> freq_channel;
    std::shared_ptr<channel_tracker_v2_channel> chan_channel;

    // Find or make a frequency record if we know our frequency
    if (l1info->freq_khz != 0) {
        auto imi = cv2->frequency_map->find(l1info->freq_khz);

        if (imi == cv2->frequency_map->end()) {
            freq_channel =
                std::make_shared<channel_tracker_v2_channel>(cv2->channel_entry_id);
            freq_channel->set_frequency(l1info->freq_khz);
            cv2->frequency_map->insert(l1info->freq_khz, freq_channel);
        } else {
            freq_channel = std::static_pointer_cast<channel_tracker_v2_channel>(imi->second);
        }
    }

    if (common != nullptr) {
        if (!(common->channel == "0") && !(common->channel == "")) {
            auto smi = cv2->channel_map->find(common->channel);

            if (smi == cv2->channel_map->end()) {
                chan_channel =
                    std::make_shared<channel_tracker_v2_channel>(cv2->channel_entry_id);

                chan_channel->set_channel(common->channel);
                cv2->channel_map->insert(common->channel, chan_channel);
            } else {
                chan_channel = std::static_pointer_cast<channel_tracker_v2_channel>(smi->second);
            }
        }
    }

    // didn't find anything
    if (freq_channel == NULL && chan_channel == NULL)
        return 1;

    time_t stime = time(0);

    if (freq_channel) {
        freq_channel->get_signal_data()->append_signal(*l1info, false, 0);
        freq_channel->get_packets_rrd()->add_sample(1, stime);

        if (common != NULL) {
            freq_channel->get_data_rrd()->add_sample(common->datasize, stime);

            /*
            freq_channel->seen_device_map[common->device] = true;
            */
        }

    }

    if (chan_channel) {
        chan_channel->get_signal_data()->append_signal(*l1info, false, 0);
        chan_channel->get_packets_rrd()->add_sample(1, stime);

        if (common != NULL) {
            chan_channel->get_data_rrd()->add_sample(common->datasize, stime);
        }

        /*
        // Track unique devices
        if (globalreg->timestamp.tv_sec != chan_channel->last_device_sec) {
            chan_channel->last_device_sec = globalreg->timestamp.tv_sec;
            chan_channel->seen_device_map.clear();
        }
        */

        /*
        chan_channel->seen_device_map[common->device] = true;

        chan_channel->get_device_rrd()->add_sample(
                chan_channel->seen_device_map.size(),
                globalreg->timestamp.tv_sec);
                */
    }

    return 1;
}

