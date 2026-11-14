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

#include "config.h"

#include <algorithm>
#include <array>
#include <cctype>

#include "device_alerts.h"

namespace {

void add_name(tracker_element_vector_string& v, const std::string& name) {
    if (name.empty() || v.size() >= device_alert_state::max_names)
        return;

    if (std::find(v.begin(), v.end(), name) != v.end())
        return;

    v.push_back(name);
}

}

void device_alert_state::add(const tracked_alert& alert, bool as_sender, bool own, uint64_t when) {
    add_name(*headers, alert.get_header());
    set_last_time(std::max(get_last_time(), when));

    if (!as_sender) {
        set_named(get_named() + 1);
        return;
    }

    set_sent(get_sent() + 1);
    set_sent_severity(std::max(get_sent_severity(), alert.get_severity()));
    set_sent_last_time(std::max(get_sent_last_time(), when));
    add_name(*sent_headers, alert.get_header());
    add_name(*sent_classes, alert.get_alertclass());

    if (own) {
        set_own_sent(get_own_sent() + 1);
        set_own_severity(std::max(get_own_severity(), alert.get_severity()));
    }
}

bool device_alert_linker::ignored(const std::string& alertclass) const {
    if (alertclass.size() > max_class_len)
        return false;

    std::string up{alertclass};
    std::transform(up.begin(), up.end(), up.begin(), [](unsigned char c) { return std::toupper(c); });

    return std::find(ignore_classes.begin(), ignore_classes.end(), up) != ignore_classes.end();
}

device_alert_linker::device_alert_linker() :
    lifetime_global(),
    alert_state_id{-1},
    alert_evt_id{0} {

    devicetracker = Globalreg::fetch_mandatory_global_as<device_tracker>();
    entrytracker = Globalreg::fetch_mandatory_global_as<entry_tracker>();
    eventbus = Globalreg::fetch_mandatory_global_as<event_bus>();

    // Denial of service alerts name the address they claim to come from, which can be
    // their victim's, and system alerts aren't about a device
    auto ign = Globalreg::globalreg->kismet_config->fetch_opt_dfl("device_rules_alert_ignore_classes",
            "DENIAL,SYSTEM");
    for (auto c : str_tokenize(ign, ",")) {
        c.erase(0, c.find_first_not_of(" \t"));
        c.erase(c.find_last_not_of(" \t") + 1);
        if (c.empty())
            continue;
        if (c.size() > max_class_len || ignore_classes.size() >= max_ignore_classes) {
            _MSG_ERROR("device_rules_alert_ignore_classes: skipping '{}'; classes are up to {} characters, "
                    "and up to {} of them", c.substr(0, max_class_len), max_class_len, max_ignore_classes);
            continue;
        }
        std::transform(c.begin(), c.end(), c.begin(), [](unsigned char ch) { return std::toupper(ch); });
        if (std::find(ignore_classes.begin(), ignore_classes.end(), c) == ignore_classes.end())
            ignore_classes.push_back(c);
    }

    alert_state_id =
        entrytracker->register_field("kismet.device.base.alerts",
                tracker_element_factory<device_alert_state>(),
                "alerts naming this device");

    // The eventbus calls listeners on its own thread, outside any packet handler that
    // might hold a device lock
    alert_evt_id =
        eventbus->register_listener(alert_tracker::alert_event(),
                [this](std::shared_ptr<eventbus_event> evt) {
                    auto alert_k = evt->get_event_content()->find(alert_tracker::alert_event());
                    if (alert_k == evt->get_event_content()->end())
                        return;

                    link(std::static_pointer_cast<tracked_alert>(alert_k->second));
                });
}

device_alert_linker::~device_alert_linker() {
    if (eventbus != nullptr && alert_evt_id != 0)
        eventbus->remove_listener(alert_evt_id);

    Globalreg::globalreg->remove_global(global_name());
}

void device_alert_linker::link(const std::shared_ptr<tracked_alert>& alert) {
    if (alert == nullptr)
        return;

    // The sender is the source, or the BSSID when the alert has no source
    auto sender = alert->get_source_mac();
    if (sender.state.error || sender.longmac == 0)
        sender = alert->get_transmitter_mac();

    const std::array<mac_addr, 4> macs{alert->get_transmitter_mac(), alert->get_source_mac(),
        alert->get_dest_mac(), alert->get_other_mac()};

    const auto phy = static_cast<int>(alert->get_phy());
    const auto when = static_cast<uint64_t>(alert->get_timestamp());
    const bool own = !ignored(alert->get_alertclass());

    for (size_t i = 0; i < macs.size(); i++) {
        const auto& m = macs[i];

        if (m.state.error || m.longmac == 0 || m.longmac == 0xFFFFFFFFFFFFULL)
            continue;

        // A MAC named twice counts once
        bool dup = false;
        for (size_t j = 0; j < i; j++) {
            if (macs[j] == m) {
                dup = true;
                break;
            }
        }
        if (dup)
            continue;

        const bool as_sender = (m == sender);

        for (const auto& dev : devicetracker->fetch_devices(m)) {
            if (phy >= 0 && dev->get_phyid() != phy)
                continue;

            kis_device_lock lk(dev, false);

            auto state = dev->get_sub_as<device_alert_state>(alert_state_id);
            if (state == nullptr) {
                state = entrytracker->get_shared_instance_as<device_alert_state>(alert_state_id);
                dev->insert(state);
            }

            state->add(*alert, as_sender, own, when);
            dev->set_num_alerts(dev->get_num_alerts() + 1);

            // Rules passes and last-time clients pick up changed devices
            dev->update_modtime();
        }
    }
}
