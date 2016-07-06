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
#include "msgpack_adapter.h"
#include "devicetracker.h"
#include "devicetracker_component.h"
#include "packinfo_signal.h"

Channeltracker_V2::Channeltracker_V2(GlobalRegistry *in_globalreg) :
    tracker_component(in_globalreg, 0), Kis_Net_Httpd_Stream_Handler(in_globalreg) {

    globalreg = in_globalreg;

    globalreg->InsertGlobal("CHANNEL_TRACKER", this);

    register_fields();
    reserve_fields(NULL);

    globalreg->packetchain->RegisterHandler(&PacketChainHandler, this, 
            CHAINPOS_LOGGING, 0);

	pack_comp_device = _PCM(PACK_COMP_DEVICE) =
		globalreg->packetchain->RegisterPacketComponent("DEVICE");

	pack_comp_common =  _PCM(PACK_COMP_COMMON) =
		globalreg->packetchain->RegisterPacketComponent("COMMON");

	pack_comp_l1data = 
		globalreg->packetchain->RegisterPacketComponent("RADIODATA");

}

Channeltracker_V2::~Channeltracker_V2() {
    globalreg->RemoveGlobal("CHANNEL_TRACKER");
    globalreg->packetchain->RemoveHandler(&PacketChainHandler, CHAINPOS_LOGGING);
    fprintf(stderr, "debug: channeltracker freed\n");
}

void Channeltracker_V2::register_fields() {
    tracker_component::register_fields();

    freq_map_id =
        RegisterField("kismet.channeltracker.frequency_map", TrackerDoubleMap,
                "Frequency use", (void **) &frequency_map);

    channel_map_id =
        RegisterField("kismet.channeltracker.channel_map", TrackerStringMap,
                "Channel use", (void **) &channel_map);

    Channeltracker_V2_Channel *chan_builder = 
        new Channeltracker_V2_Channel(globalreg, 0);
    channel_entry_id = RegisterComplexField("kismet.channeltracker.channel",
            chan_builder, "channel/frequency entry");
    delete(chan_builder);
}

bool Channeltracker_V2::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") != 0)
        return false;

    if (strcmp(path, "/channels/channels.msgpack") == 0)
        return true;

    return false;
}

void Channeltracker_V2::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        struct MHD_Connection *connection __attribute__((unused)),
        const char *path, const char *method, 
        const char *upload_data __attribute__((unused)),
        size_t *upload_data_size __attribute__((unused)), 
        std::stringstream &stream) {

    if (strcmp(method, "GET") != 0) {
        return;
    }

    if (strcmp(path, "/channels/channels.msgpack") == 0) {
        MsgpackAdapter::Pack(globalreg, stream, this);
        return;
    }

}

int Channeltracker_V2::PacketChainHandler(CHAINCALL_PARMS) {
    Channeltracker_V2 *cv2 = (Channeltracker_V2 *) auxdata;

    kis_layer1_packinfo *l1info =
        (kis_layer1_packinfo *) in_pack->fetch(cv2->pack_comp_l1data);
    /*
	kis_tracked_device_info *devinfo = 
		(kis_tracked_device_info *) in_pack->fetch(cv2->pack_comp_device);
    */
	kis_common_info *common = 
		(kis_common_info *) in_pack->fetch(cv2->pack_comp_common);

    // Nothing to do with no l1info
    if (l1info == NULL)
        return 1;

    Channeltracker_V2_Channel *freq_channel = NULL;
    Channeltracker_V2_Channel *chan_channel = NULL;

    // Find or make a frequency record if we know our frequency
    if (l1info->freq_khz != 0) {
        TrackerElement::double_map_iterator imi =
            cv2->frequency_map->double_find(l1info->freq_khz);

        if (imi == cv2->frequency_map->double_end()) {
            freq_channel = 
                new Channeltracker_V2_Channel(cv2->globalreg, cv2->channel_entry_id);
            freq_channel->set_frequency(l1info->freq_khz);
            cv2->frequency_map->add_doublemap(l1info->freq_khz, freq_channel);
        } else {
            freq_channel = (Channeltracker_V2_Channel *) imi->second;
        }
    }

    if (common != NULL) {
        if (!(common->channel == "0") && !(common->channel == "")) {
            TrackerElement::string_map_iterator smi =
                cv2->channel_map->string_find(common->channel);

            if (smi == cv2->channel_map->string_end()) {
                chan_channel =
                    new Channeltracker_V2_Channel(cv2->globalreg, cv2->channel_entry_id);
                chan_channel->set_channel(common->channel);
                cv2->channel_map->add_stringmap(common->channel, chan_channel);
            } else {
                chan_channel = (Channeltracker_V2_Channel *) smi->second;
            }
        }
    }

    // didn't find anything
    if (freq_channel == NULL && chan_channel == NULL)
        return 1;

    if (freq_channel) {
        (*(freq_channel->get_signal_data())) += *(l1info);
        freq_channel->get_packets_rrd()->add_sample(1, 
                cv2->globalreg->timestamp.tv_sec);

        if (common != NULL) {
            freq_channel->get_data_rrd()->add_sample(common->datasize,
                    cv2->globalreg->timestamp.tv_sec);
            freq_channel->seen_device_map[common->device] = true;
        }

        // Track unique devices
        if (globalreg->timestamp.tv_sec != freq_channel->last_device_sec) {
            freq_channel->last_device_sec = globalreg->timestamp.tv_sec;
            freq_channel->seen_device_map.clear();
        }

        freq_channel->get_device_rrd()->add_sample(
                freq_channel->seen_device_map.size(),
                globalreg->timestamp.tv_sec);

    }

    if (chan_channel) {
        (*(chan_channel->get_signal_data())) += *(l1info);
        chan_channel->get_packets_rrd()->add_sample(1, 
                cv2->globalreg->timestamp.tv_sec);

        if (common != NULL) {
            chan_channel->get_data_rrd()->add_sample(common->datasize,
                    cv2->globalreg->timestamp.tv_sec);
        }

        // Track unique devices
        if (globalreg->timestamp.tv_sec != chan_channel->last_device_sec) {
            chan_channel->last_device_sec = globalreg->timestamp.tv_sec;
            chan_channel->seen_device_map.clear();
        }

        chan_channel->seen_device_map[common->device] = true;

        chan_channel->get_device_rrd()->add_sample(
                chan_channel->seen_device_map.size(),
                globalreg->timestamp.tv_sec);
    }

    return 1;
}

