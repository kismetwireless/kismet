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

#ifndef __DEVICE_RULES_H__
#define __DEVICE_RULES_H__

#include "config.h"

#include <atomic>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "devicerules/dr_core.h"
#include "devicetracker.h"
#include "devicetracker_view.h"
#include "globalregistry.h"
#include "kis_mutex.h"
#include "kis_net_beast_httpd.h"
#include "trackedcomponent.h"

// Server-side device rules: tag, color, collect into views, and alert on devices that
// match rules written in the device rules language (see devicerules/).  Rules are
// checked on a timer against devices changed since the last pass, and rules marked
// 'live' are also checked as packets update a device.

// Rule results on a device; only present on devices that match a rule
class device_rule_state : public tracker_component {
public:
    device_rule_state() :
        tracker_component(0) {
        register_fields();
        reserve_fields(nullptr);
    }

    device_rule_state(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(nullptr);
    }

    device_rule_state(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    device_rule_state(const device_rule_state *p) :
        tracker_component{p} {
        __ImportField(matched, p);
        __ImportField(tags, p);
        __ImportField(color, p);
        reserve_fields(nullptr);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("device_rule_state");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>(this);
        r->set_id(this->get_id());
        return r;
    }

    __ProxyTrackable(matched, tracker_element_vector_string, matched);
    __ProxyTrackable(tags, tracker_element_vector_string, tags);
    __Proxy(color, std::string, std::string, std::string, color);

    // Rule set the hits are for, and which of its rules matched
    uint32_t gen = 0;
    std::vector<uint8_t> hits;

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("kismet.device.rules.matched", "names of the device rules this device matches", &matched);
        register_field("kismet.device.rules.tags", "tags from matching device rules", &tags);
        register_field("kismet.device.rules.color", "highlight color from the first matching device rule", &color);
    }

    std::shared_ptr<tracker_element_vector_string> matched;
    std::shared_ptr<tracker_element_vector_string> tags;
    std::shared_ptr<tracker_element_string> color;
};

class device_rules : public lifetime_global, public deferred_startup {
public:
    static std::string global_name() { return "DEVICERULES"; }

    static std::shared_ptr<device_rules> create_device_rules() {
        std::shared_ptr<device_rules> mon(new device_rules());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->register_deferred_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

private:
    device_rules();

public:
    virtual ~device_rules();

    virtual void trigger_deferred_startup() override;
    virtual void trigger_deferred_shutdown() override;

    // Replace the active rules; throws parse_error, leaving the old rules in place
    void set_rules(const std::string& text);

    // Order devices by a sort from the active rules; false with the reason when there's
    // no such sort
    bool sort_devices(const std::string& sort, std::shared_ptr<tracker_element_vector>& devices,
            std::string& err);

    // A compiled rule set and what goes with it; replaced whole, never changed
    struct active_set {
        std::unique_ptr<devicerules::ruleset> rs;
        std::string text;
        uint32_t gen;
        bool jit;
        std::string jit_error;

        std::vector<uint8_t> live_want;
        bool any_live;

        // Index into rs of each rule by name
        std::map<std::string, size_t> by_name;
        std::map<std::string, size_t> sorts_by_name;
        // View per rule, null for rules without one
        std::vector<std::shared_ptr<device_tracker_view>> views;
        // Views of rules no longer in the set, or no longer with a view, by name
        std::map<std::string, std::shared_ptr<device_tracker_view>> retired;
    };

    struct pending_change {
        std::shared_ptr<kis_tracked_device_base> device;
        std::shared_ptr<device_tracker_view> view;
        bool add;
        // Alert text, when this change raises one
        std::string alert;
        mac_addr mac;
    };

protected:
    kis_mutex mutex;

    std::shared_ptr<device_tracker> devicetracker;
    std::shared_ptr<entry_tracker> entrytracker;

    std::shared_ptr<active_set> current;
    std::atomic<uint32_t> next_gen;

    // Views are never destroyed: their routes hold the view, so a rule that goes away
    // leaves an empty view that a later rule of the same name takes over
    std::map<std::string, std::shared_ptr<device_tracker_view>> views;

    int rule_state_id;
    int alert_ref;
    int timer_id;
    int pchain_id;

    bool use_jit;
    unsigned int pass_interval;
    unsigned int full_interval;
    unsigned int pass_count;
    time_t last_pass;
    bool full_pending;

    std::atomic<uint64_t> stat_passes, stat_devices, stat_last_us;

    // Alerts held back by the rate limit, raised as it allows
    kis_mutex alert_mutex;
    std::deque<std::pair<mac_addr, std::string>> alert_backlog;
    size_t alert_backlog_max;
    void raise_or_hold(const mac_addr& mac, const std::string& text);
    void drain_alerts();

    struct pass_state;
    std::unique_ptr<pass_state> pass;

    std::shared_ptr<active_set> get_current() {
        return std::atomic_load(&current);
    }

    std::shared_ptr<active_set> compile_set(const std::string& text);
    std::shared_ptr<active_set> finish_set(std::unique_ptr<devicerules::ruleset> rs, const std::string& text);
    void install_set(std::shared_ptr<active_set> as);

    // Rules from the files, directories and lines in the config
    std::shared_ptr<active_set> load_configured();

    static std::string describe(const devicerules::parse_error& e);

    void timer_pass();
    int packet_hook(const std::shared_ptr<kis_packet>& in_pack);

    // Evaluate one locked device, queueing view and alert changes for after it's unlocked
    void eval_device(active_set& as, devicerules::eval_ctx& ctx, const std::shared_ptr<kis_tracked_device_base>& dev,
            const uint8_t *want, std::vector<uint8_t>& out, std::vector<uint8_t>& prev,
            std::vector<pending_change>& changes);

    void apply_changes(std::vector<pending_change>& changes);

    std::shared_ptr<tracker_element> rules_endpoint();
    void check_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con);
    void set_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con);
    void test_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con);

    int pack_comp_device;
};

#endif
