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

#ifndef __DOT11_FINGERPRINT_H__
#define __DOT11_FINGERPRINT_H__

#include "config.h"

#include "kis_mutex.h"
#include "trackedelement.h"
#include "trackedcomponent.h"
#include "kis_net_microhttpd.h"

class tracked_dot11_fingerprint : public tracker_component {
public:
    tracked_dot11_fingerprint() :
        tracker_component{} {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_dot11_fingerprint(int in_id) :
        tracker_component{in_id} {
        register_fields();
        reserve_fields(nullptr);
    }

    tracked_dot11_fingerprint(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component{in_id} {
        register_fields();
        reserve_fields(e);
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    virtual ~tracked_dot11_fingerprint() { }

    __Proxy(device_addr, mac_addr, mac_addr, mac_addr, device_addr);
    __Proxy(beacon_hash, uint32_t, uint32_t, uint32_t, beacon_hash);
    __Proxy(response_hash, uint32_t, uint32_t, uint32_t, response_hash);
    __Proxy(probe_hash, uint32_t, uint32_t, uint32_t, probe_hash);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        RegisterField("kismet.dot11.fingerprint.macaddr", "Fingerprint target", &device_addr);
        RegisterField("kismet.dot11.fingerprint.beacon_hash", "Beacon hash", &beacon_hash);
        RegisterField("kismet.dot11.fingerprint.response_hash", "Response hash", &response_hash);
        RegisterField("ksimet.dot11.fingerprint.probe_hash", "Probe hash", &probe_hash);
    }

    std::shared_ptr<TrackerElementMacAddr> device_addr;
    std::shared_ptr<TrackerElementUInt32> beacon_hash;
    std::shared_ptr<TrackerElementUInt32> response_hash;
    std::shared_ptr<TrackerElementUInt32> probe_hash;
};

class Dot11FingerprintTracker : public LifetimeGlobal {
public:
    static std::string global_name() { return "DOT11FINGERPRINTTRACKER"; }

    static std::shared_ptr<Dot11FingerprintTracker> create_dot11fingerprinttracker() {
        std::shared_ptr<Dot11FingerprintTracker> mon(new Dot11FingerprintTracker());
        Globalreg::globalreg->RegisterLifetimeGlobal(mon);
        Globalreg::globalreg->InsertGlobal(global_name(), mon);
        return mon;
    }

private:
    Dot11FingerprintTracker();

public:
    virtual ~Dot11FingerprintTracker();

protected:
    std::shared_ptr<TrackerElementMacMap> fingerprint_map;
    std::shared_ptr<Kis_Net_Httpd_Simple_Tracked_Endpoint> fingerprint_endp;
    std::shared_ptr<Kis_Net_Httpd_Simple_Post_Endpoint> edit_endp;

};

#endif

