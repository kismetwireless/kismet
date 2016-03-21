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

#ifndef __CHANNELTRACKER_V2_H__
#define __CHANNELTRACKER_V2_H__

#include "config.h"

#include <string>
#include <map>

#include "globalregistry.h"
#include "trackedelement.h"
#include "kis_net_microhttpd.h"
#include "devicetracker_component.h"
#include "packetchain.h"

// Can appear in the list as either a numerical frequency or a named
// channel
class Channeltracker_V2_Channel : public tracker_component {
public:
    Channeltracker_V2_Channel(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) { 
        register_fields();
        reserve_fields(NULL);

        last_device_sec = 0;
    }

    Channeltracker_V2_Channel(GlobalRegistry *in_globalreg, 
            int in_id, TrackerElement *e) : 
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);

        last_device_sec = 0;
    }

    virtual TrackerElement *clone_type() {
        return new Channeltracker_V2_Channel(globalreg, get_id());
    }

    __Proxy(channel, string, string, string, channel);
    __Proxy(frequency, uint64_t, uint64_t, uint64_t, frequency);

    typedef kis_tracked_rrd<uint64_t, TrackerUInt64> uint64_rrd;

    __ProxyTrackable(packets_rrd, uint64_rrd, packets_rrd);
    __ProxyTrackable(data_rrd, uint64_rrd, data_rrd);
    __ProxyTrackable(device_rrd,uint64_rrd, device_rrd);

    __ProxyTrackable(signal_data, kis_tracked_signal_data, signal_data);

    // C++-domain map of devices we've seen in the last second for computing if we
    // increase the RRD record
    map<mac_addr, bool> seen_device_map;
    time_t last_device_sec;


protected:

    virtual void register_fields() {
        tracker_component::register_fields();

        channel_id =
            RegisterField("kismet.channelrec.channel", TrackerString,
                    "logical channel", (void **) &channel);

        frequency_id =
            RegisterField("kismet.channelrec.frequency", TrackerUInt64,
                    "physical frequency", (void **) &frequency);

        kis_tracked_rrd<uint64_t, TrackerUInt64> *packets_rrd_builder =
            new kis_tracked_rrd<uint64_t, TrackerUInt64>(globalreg, 0);
        packets_rrd_id =
            RegisterComplexField("kismet.channelrec.packets_rrd",
                    packets_rrd_builder, "number of packets RRD");

        kis_tracked_rrd<uint64_t, TrackerUInt64> *data_rrd_builder =
            new kis_tracked_rrd<uint64_t, TrackerUInt64>(globalreg, 0);
        data_rrd_id =
            RegisterComplexField("kismet.channelrec.data_rrd",
                    data_rrd_builder, "bytes of data RRD");

        kis_tracked_rrd<uint64_t, TrackerUInt64> *device_rrd_builder =
            new kis_tracked_rrd<uint64_t, TrackerUInt64>(globalreg, 0);
        device_rrd_id =
            RegisterComplexField("kismet.channelrec.device_rrd",
                    device_rrd_builder, "number of active devices RRD");

        kis_tracked_signal_data *sig_builder =
            new kis_tracked_signal_data(globalreg, 0);
        signal_data_id =
            RegisterComplexField("kismet.channelrec.signal", sig_builder,
                "overall signal records");
    }

    virtual void reserve_fields(TrackerElement *e) {
        tracker_component::reserve_fields(e);

        if (e != NULL) {
            packets_rrd = 
                new kis_tracked_rrd<uint64_t, TrackerUInt64>(globalreg, 
                        packets_rrd_id, e->get_map_value(packets_rrd_id));
            data_rrd = 
                new kis_tracked_rrd<uint64_t, TrackerUInt64>(globalreg, 
                        data_rrd_id, e->get_map_value(data_rrd_id));
            device_rrd = 
                new kis_tracked_rrd<uint64_t, TrackerUInt64>(globalreg, 
                        device_rrd_id, e->get_map_value(device_rrd_id));

            signal_data =
                new kis_tracked_signal_data(globalreg, signal_data_id,
                        e->get_map_value(signal_data_id));
        } else {
            packets_rrd =
                new kis_tracked_rrd<uint64_t, TrackerUInt64>(globalreg, packets_rrd_id);
            add_map(packets_rrd);

            data_rrd =
                new kis_tracked_rrd<uint64_t, TrackerUInt64>(globalreg, data_rrd_id);
            add_map(data_rrd);

            device_rrd =
                new kis_tracked_rrd<uint64_t, TrackerUInt64>(globalreg, device_rrd_id);
            add_map(device_rrd);

            signal_data =
                new kis_tracked_signal_data(globalreg, signal_data_id);
            add_map(signal_data);
        }

    }

    // Channel, as string - Logical channels
    int channel_id;
    TrackerElement *channel;

    // Frequency, for collating
    int frequency_id;
    TrackerElement *frequency;

    // Packets per second RRD
    int packets_rrd_id;
    kis_tracked_rrd<uint64_t, TrackerUInt64> *packets_rrd;

    // Data in bytes per second RRD
    int data_rrd_id;
    kis_tracked_rrd<uint64_t, TrackerUInt64> *data_rrd;

    // Devices active per second RRD
    int device_rrd_id;
    kis_tracked_rrd<uint64_t, TrackerUInt64> *device_rrd;

    // Overall signal data.  This could in theory be populated by spectrum
    // analyzers in the future as well.
    int signal_data_id;
    kis_tracked_signal_data *signal_data;

};

class Channeltracker_V2 : public tracker_component, public Kis_Net_Httpd_Stream_Handler {
public:
    Channeltracker_V2(GlobalRegistry *in_globalreg);
    ~Channeltracker_V2();

    // HTTP API
    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            struct MHD_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

protected:
    Kis_Net_Httpd *httpd;

    // Packetchain callback
    static int PacketChainHandler(CHAINCALL_PARMS);

    // Tracker component
    virtual void register_fields();

    // Seen channels as string-named channels, so logical channel allocation
    // per phy
    int channel_map_id;
    TrackerElement *channel_map;

    // Collapsed frequency information, multi-phy, spec-an, etc
    int freq_map_id;
    TrackerElement *frequency_map;

    // Channel/freq content
    int channel_entry_id;

    int pack_comp_l1data, pack_comp_devinfo, pack_comp_common, pack_comp_device;

};

#endif

