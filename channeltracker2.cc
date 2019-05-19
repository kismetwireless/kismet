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

Channeltracker_V2::Channeltracker_V2(GlobalRegistry *in_globalreg) :
    tracker_component(),
    Kis_Net_Httpd_CPPStream_Handler() {

    // Number of seconds we consider a device to be active on a frequency 
    // after the last time we see it
    device_decay = 5;

    register_fields();
    reserve_fields(NULL);

    auto packetchain = Globalreg::FetchMandatoryGlobalAs<Packetchain>("PACKETCHAIN");

    packetchain->RegisterHandler(&PacketChainHandler, this, CHAINPOS_LOGGING, 0);

	pack_comp_device = packetchain->RegisterPacketComponent("DEVICE");
	pack_comp_common = packetchain->RegisterPacketComponent("COMMON");
	pack_comp_l1data = packetchain->RegisterPacketComponent("RADIODATA");

    devicetracker =
        Globalreg::FetchMandatoryGlobalAs<Devicetracker>("DEVICETRACKER");

    struct timeval trigger_tm;
    trigger_tm.tv_sec = time(0) + 1;
    trigger_tm.tv_usec = 0;

    timetracker =
        Globalreg::FetchMandatoryGlobalAs<Timetracker>("TIMETRACKER");

    timer_id = timetracker->RegisterTimer(0, &trigger_tm, 0, this);

    Bind_Httpd_Server();
}

Channeltracker_V2::~Channeltracker_V2() {
    local_locker locker(&lock);

    auto timetracker = Globalreg::FetchGlobalAs<Timetracker>("TIMETRACKER");
    if (timetracker != nullptr)
        timetracker->RemoveTimer(timer_id);

    auto packetchain = Globalreg::FetchGlobalAs<Packetchain>("PACKETCHAIN");
    if (packetchain != nullptr)
        packetchain->RemoveHandler(&PacketChainHandler, CHAINPOS_LOGGING);

    Globalreg::globalreg->RemoveGlobal("CHANNEL_TRACKER");
}

void Channeltracker_V2::register_fields() {
    tracker_component::register_fields();

    RegisterField("kismet.channeltracker.frequency_map", "Frequency use", &frequency_map);
    RegisterField("kismet.channeltracker.channel_map", "Channel use", &channel_map);

    channel_entry_id = 
        RegisterField("kismet.channeltracker.channel",
                TrackerElementFactory<Channeltracker_V2_Channel>(),
                "channel/frequency entry");
}

bool Channeltracker_V2::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") != 0)
        return false;

    if (!Httpd_CanSerialize(path))
        return false;

    std::string stripped = Httpd_StripSuffix(path);

    if (stripped == "/channels/channels")
        return true;

    return false;
}

void Channeltracker_V2::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        Kis_Net_Httpd_Connection *connection __attribute__((unused)),
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
        auto cv2 = Globalreg::FetchMandatoryGlobalAs<Channeltracker_V2>("CHANNEL_TRACKER");
        Httpd_Serialize(path, stream, cv2);
    }

}

class channeltracker_v2_device_worker : public DevicetrackerFilterWorker {
public:
    channeltracker_v2_device_worker(Channeltracker_V2 *channelv2) {
        this->channelv2 = channelv2;
        stime = time(0);
    }

    virtual ~channeltracker_v2_device_worker() { }

    // Count all the devices.  We use a filter worker but 'match' on all
    // and count them into our local map
    virtual bool MatchDevice(Devicetracker *devicetracker __attribute__((unused)),
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
    virtual void Finalize(Devicetracker *devicetracker __attribute__((unused))) {
        channelv2->update_device_counts(device_count);
    }

protected:
    Channeltracker_V2 *channelv2;

    std::map<double, unsigned int> device_count;

    time_t stime;

    kis_recursive_timed_mutex workermutex;
};


int Channeltracker_V2::timetracker_event(int event_id __attribute__((unused))) {
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

void Channeltracker_V2::update_device_counts(std::map<double, unsigned int> in_counts) {
    local_locker locker(&lock);
    time_t ts = time(0);

    for (auto i : in_counts) {
        auto imi = frequency_map->find(i.first);

        // If we can't find the device, skip it
        if (imi == frequency_map->end())
            continue;

        // Update the device RRD for the count
        std::static_pointer_cast<Channeltracker_V2_Channel>(imi->second)->get_device_rrd()->add_sample(i.second, ts);
    }
}

int Channeltracker_V2::PacketChainHandler(CHAINCALL_PARMS) {
    Channeltracker_V2 *cv2 = (Channeltracker_V2 *) auxdata;

    local_locker locker(&(cv2->lock));

    auto l1info = in_pack->fetch<kis_layer1_packinfo>(cv2->pack_comp_l1data);
	auto common = in_pack->fetch<kis_common_info>(cv2->pack_comp_common);

    // Nothing to do with no l1info
    if (l1info == nullptr)
        return 1;

    std::shared_ptr<Channeltracker_V2_Channel> freq_channel;
    std::shared_ptr<Channeltracker_V2_Channel> chan_channel;

    // Find or make a frequency record if we know our frequency
    if (l1info->freq_khz != 0) {
        auto imi = cv2->frequency_map->find(l1info->freq_khz);

        if (imi == cv2->frequency_map->end()) {
            freq_channel =
                std::make_shared<Channeltracker_V2_Channel>(cv2->channel_entry_id);
            freq_channel->set_frequency(l1info->freq_khz);
            cv2->frequency_map->insert(l1info->freq_khz, freq_channel);
        } else {
            freq_channel = std::static_pointer_cast<Channeltracker_V2_Channel>(imi->second);
        }
    }

    if (common != nullptr) {
        if (!(common->channel == "0") && !(common->channel == "")) {
            auto smi = cv2->channel_map->find(common->channel);

            if (smi == cv2->channel_map->end()) {
                chan_channel =
                    std::make_shared<Channeltracker_V2_Channel>(cv2->channel_entry_id);

                chan_channel->set_channel(common->channel);
                cv2->channel_map->insert(common->channel, chan_channel);
            } else {
                chan_channel = std::static_pointer_cast<Channeltracker_V2_Channel>(smi->second);
            }
        }
    }

    // didn't find anything
    if (freq_channel == NULL && chan_channel == NULL)
        return 1;

    time_t stime = time(0);

    if (freq_channel) {
        freq_channel->get_signal_data()->append_signal(*l1info, false);
        freq_channel->get_packets_rrd()->add_sample(1, stime);

        if (common != NULL) {
            freq_channel->get_data_rrd()->add_sample(common->datasize, stime);

            /*
            freq_channel->seen_device_map[common->device] = true;
            */
        }

    }

    if (chan_channel) {
        chan_channel->get_signal_data()->append_signal(*l1info, false);
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

