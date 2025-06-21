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

#include <map>
#include <string>

#include "globalregistry.h"
#include "kis_mutex.h"
#include "trackedelement.h"
#include "kis_net_beast_httpd.h"
#include "devicetracker_component.h"
#include "packetchain.h"
#include "timetracker.h"

// Can appear in the list as either a numerical frequency or a named
// channel
class channel_tracker_v2_channel : public tracker_component, public shared_global_data {
public:
    channel_tracker_v2_channel() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    channel_tracker_v2_channel(int in_id) :
        tracker_component(in_id) { 
        register_fields();
        reserve_fields(NULL);

        // last_device_sec = 0;
    }

    channel_tracker_v2_channel(int in_id, std::shared_ptr<tracker_element_map> e) : 
        tracker_component(in_id) {

        register_fields();
        reserve_fields(e);

        // last_device_sec = 0;
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("channel_tracker_v2_channel");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(channel, std::string, std::string, std::string, channel);
    __Proxy(frequency, double, double, double, frequency);

    typedef kis_tracked_rrd<> uint64_rrd;

    __ProxyTrackable(packets_rrd, uint64_rrd, packets_rrd);
    __ProxyTrackable(data_rrd, uint64_rrd, data_rrd);
    __ProxyTrackable(device_rrd,uint64_rrd, device_rrd);

    __ProxyTrackable(signal_data, kis_tracked_signal_data, signal_data);

    /*
    // C++-domain map of devices we've seen in the last second for computing if we
    // increase the RRD record
    map<mac_addr, bool> seen_device_map;
    time_t last_device_sec;
    */

protected:
    // Timer for updating the device list
    int timer_id;

    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("kismet.channelrec.channel", "logical channel", &channel);
        register_field("kismet.channelrec.frequency", "physical frequency", &frequency);
        register_field("kismet.channelrec.packets_rrd", "packet count RRD", &packets_rrd);
        register_field("kismet.channelrec.data_rrd", "byte count RRD", &data_rrd);
        register_field("kismet.channelrec.device_rrd", "active devices RRD", &device_rrd);
        register_field("kismet.channelrec.signal", "signal records", &signal_data);
    }

    virtual void reserve_fields(std::shared_ptr<tracker_element_map> e) override {
        tracker_component::reserve_fields(e);

        // Don't fast-forward the device RRD
        device_rrd->update_before_serialize(false);
    }

    // Channel, as string - Logical channels
    std::shared_ptr<tracker_element_string> channel;

    // Frequency, for collating
    std::shared_ptr<tracker_element_double> frequency;

    // Packets per second RRD
    std::shared_ptr<kis_tracked_rrd<> > packets_rrd;

    // Data in bytes per second RRD
    std::shared_ptr<kis_tracked_rrd<> > data_rrd;

    // Devices active per second RRD
    std::shared_ptr<kis_tracked_rrd<> > device_rrd;

    // Overall signal data.  This could in theory be populated by spectrum
    // analyzers in the future as well.
    std::shared_ptr<kis_tracked_signal_data> signal_data;

};

class channel_tracker_v2 : public lifetime_global, public deferred_startup {
public:
    static std::string global_name() { return "CHANNEL_TRACKER"; }

    static std::shared_ptr<channel_tracker_v2> create_channeltracker() {
        std::shared_ptr<channel_tracker_v2> mon(new channel_tracker_v2());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        Globalreg::globalreg->register_deferred_global(mon);
        return mon;
    }

private:
    channel_tracker_v2();

public:
    virtual ~channel_tracker_v2();

    virtual void trigger_deferred_startup() override;

    // Update device counts - kept public so that the worker can access it
    int device_decay;
    void update_device_counts(std::unordered_map<double, unsigned int> in_counts, time_t in_ts);

protected:
    kis_mutex lock;

    std::shared_ptr<device_tracker> devicetracker;
    std::shared_ptr<time_tracker> timetracker;
    std::shared_ptr<entry_tracker> entrytracker;

    // packetchain callback
    static int packet_chain_handler(CHAINCALL_PARMS);

    // Seen channels as string-named channels, aggregated across all the phys
    std::shared_ptr<tracker_element_string_map> channel_map;

    // Collapsed frequency information, multi-phy, spec-an, etc
    std::shared_ptr<tracker_element_double_map> frequency_map;

    // Channel/freq content
    int channel_entry_id;

    int pack_comp_l1data, pack_comp_devinfo, pack_comp_common, pack_comp_device;

    int timer_id;
    int gather_devices_event(int event_id);


};

#endif

