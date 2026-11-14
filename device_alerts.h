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

#ifndef __DEVICE_ALERTS_H__
#define __DEVICE_ALERTS_H__

#include "config.h"

#include <memory>
#include <string>
#include <vector>

#include "alertracker.h"
#include "devicetracker.h"
#include "eventbus.h"
#include "globalregistry.h"
#include "trackedcomponent.h"

// Alerts linked to the devices they name.  An alert names up to four MACs; the
// transmitter (the source, or the BSSID when there's no source) is the device that
// sent it, and the rest are only named by it.  Rules and baseline filters read
// these, such as to take a device that sends exploit alerts out of the baseline.
// The record is only on devices some alert has named.
class device_alert_state : public tracker_component {
public:
    // Distinct alert names and classes kept per device
    static constexpr size_t max_names = 32;

    device_alert_state() :
        tracker_component(0) {
        register_fields();
        reserve_fields(nullptr);
    }

    device_alert_state(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(nullptr);
    }

    device_alert_state(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    device_alert_state(const device_alert_state *p) :
        tracker_component{p} {
        __ImportField(sent, p);
        __ImportField(named, p);
        __ImportField(sent_severity, p);
        __ImportField(last_time, p);
        __ImportField(sent_last_time, p);
        __ImportField(headers, p);
        __ImportField(sent_headers, p);
        __ImportField(sent_classes, p);
        __ImportField(own_sent, p);
        __ImportField(own_severity, p);
        reserve_fields(nullptr);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("device_alert_state");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>(this);
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(sent, uint32_t, uint32_t, uint32_t, sent);
    __Proxy(named, uint32_t, uint32_t, uint32_t, named);
    __Proxy(sent_severity, uint8_t, uint8_t, uint8_t, sent_severity);
    __Proxy(last_time, uint64_t, uint64_t, uint64_t, last_time);
    __Proxy(sent_last_time, uint64_t, uint64_t, uint64_t, sent_last_time);
    __ProxyTrackable(headers, tracker_element_vector_string, headers);
    __ProxyTrackable(sent_headers, tracker_element_vector_string, sent_headers);
    __ProxyTrackable(sent_classes, tracker_element_vector_string, sent_classes);
    __Proxy(own_sent, uint32_t, uint32_t, uint32_t, own_sent);
    __Proxy(own_severity, uint8_t, uint8_t, uint8_t, own_severity);

    // Count one alert; own is false for a sent alert in an ignored class, such as
    // DENIAL.  The device is locked.
    void add(const tracked_alert& alert, bool as_sender, bool own, uint64_t when);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("kismet.device.alerts.sent", "alerts this device sent", &sent);
        register_field("kismet.device.alerts.named", "alerts naming this device that another device sent", &named);
        register_field("kismet.device.alerts.sent_severity", "highest severity of the alerts this device sent", &sent_severity);
        register_field("kismet.device.alerts.last_time", "time of the last alert naming this device", &last_time);
        register_field("kismet.device.alerts.sent_last_time", "time of the last alert this device sent", &sent_last_time);
        register_field("kismet.device.alerts.headers", "names of the alerts naming this device", &headers);
        register_field("kismet.device.alerts.sent_headers", "names of the alerts this device sent", &sent_headers);
        register_field("kismet.device.alerts.sent_classes", "classes of the alerts this device sent", &sent_classes);
        register_field("kismet.device.alerts.own_sent",
                "alerts this device sent outside device_rules_alert_ignore_classes", &own_sent);
        register_field("kismet.device.alerts.own_severity",
                "highest severity of the alerts this device sent outside device_rules_alert_ignore_classes",
                &own_severity);
    }

    std::shared_ptr<tracker_element_uint32> sent;
    std::shared_ptr<tracker_element_uint32> named;
    std::shared_ptr<tracker_element_uint8> sent_severity;
    std::shared_ptr<tracker_element_uint64> last_time;
    std::shared_ptr<tracker_element_uint64> sent_last_time;
    std::shared_ptr<tracker_element_vector_string> headers;
    std::shared_ptr<tracker_element_vector_string> sent_headers;
    std::shared_ptr<tracker_element_vector_string> sent_classes;
    std::shared_ptr<tracker_element_uint32> own_sent;
    std::shared_ptr<tracker_element_uint8> own_severity;
};

class device_alert_linker : public lifetime_global {
public:
    static std::string global_name() { return "DEVICEALERTS"; }

    static std::shared_ptr<device_alert_linker> create_device_alert_linker() {
        std::shared_ptr<device_alert_linker> mon(new device_alert_linker());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

private:
    device_alert_linker();

public:
    virtual ~device_alert_linker();

    // Link one alert to the devices it names; called on the eventbus thread, with no
    // device locked
    void link(const std::shared_ptr<tracked_alert>& alert);

protected:
    std::shared_ptr<device_tracker> devicetracker;
    std::shared_ptr<entry_tracker> entrytracker;
    std::shared_ptr<event_bus> eventbus;

    int alert_state_id;
    unsigned long alert_evt_id;

    // Upper case alert classes that don't count toward own_sent / own_severity; set at
    // startup and only read after
    std::vector<std::string> ignore_classes;
    static constexpr size_t max_ignore_classes = 64;
    static constexpr size_t max_class_len = 64;

    bool ignored(const std::string& alertclass) const;
};

#endif
