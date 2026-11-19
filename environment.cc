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
#include <cctype>
#include <cerrno>
#include <cmath>

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "entrytracker.h"
#include "environment.h"
#include "fmt.h"
#include "globalregistry.h"
#include "util.h"

void tracked_env_battery::register_fields() {
    register_field("kismet.system.environment.battery.state",
            "battery state: charging, discharging, full, not_charging or unknown", &state);
    register_field("kismet.system.environment.battery.external_power",
            "on external power: 1 yes, 0 no, -1 unknown", &external_power);
    register_field("kismet.system.environment.battery.voltage", "battery voltage, 0 when unknown", &voltage);
    register_field("kismet.system.environment.battery.remaining",
            "seconds remaining at the present rate, 0 when unknown", &remaining);
}

void tracked_env_sensor::register_fields() {
    register_field("kismet.system.environment.sensor.id", "sensor id, the key of the sensor map", &sensor_id);
    register_field("kismet.system.environment.sensor.label", "what the sensor measures", &label);
    register_field("kismet.system.environment.sensor.kind", "sensor kind: thermal, fan or battery", &kind);
    register_field("kismet.system.environment.sensor.units", "units of the value: C, RPM or %", &units);
    register_field("kismet.system.environment.sensor.value", "last value", &sensor_value);
    register_field("kismet.system.environment.sensor.last_time", "time of the last value", &last_time);
    register_field("kismet.system.environment.sensor.origin",
            "where the sensor is: host or datasource", &origin);
    register_field("kismet.system.environment.sensor.source_uuid",
            "data source reporting the sensor, 0 for the host", &source_uuid);
    register_field("kismet.system.environment.sensor.source_name",
            "name of the data source reporting the sensor", &source_name);
    rrd_id =
        register_dynamic_field("kismet.system.environment.sensor.rrd", "value history", &rrd);
    battery_id =
        register_dynamic_field("kismet.system.environment.sensor.battery", "battery details", &battery);
}

void tracked_env_reading::register_fields() {
    register_field("kismet.system.environment.sensor.label", "what the sensor measures", &label);
    register_field("kismet.system.environment.sensor.kind", "sensor kind: thermal, fan or battery", &kind);
    register_field("kismet.system.environment.sensor.value", "last value", &sensor_value);
    register_field("kismet.system.environment.sensor.last_time", "time of the last value", &last_time);
    register_field("kismet.system.environment.sensor.source_uuid",
            "data source reporting the sensor, 0 for the host", &source_uuid);
    register_field("kismet.system.environment.sensor.source_name",
            "name of the data source reporting the sensor", &source_name);
}

void tracked_env_status::register_fields() {
    register_field("kismet.system.environment.history", "sensor history is kept", &history);
    register_field("kismet.system.environment.dropped_reports",
            "data source reports dropped: malformed, or sent too often", &dropped_reports);
    register_field("kismet.system.environment.dropped_sensors",
            "data source sensors left out by the sensor limits", &dropped_sensors);
    register_field("kismet.system.environment.source_report_sec",
            "seconds between data source reports, 0 when data source reports are off", &source_report_sec);
    register_field("kismet.system.environment.source_stale_sec",
            "data source sensors not updated for this many seconds are removed", &source_stale_sec);
    register_field("kismet.system.environment.sensors", "sensors, by id", &sensors);
}

namespace {
    constexpr unsigned int env_max_zones = 64;
    constexpr size_t env_max_hwmon = 64;
    constexpr size_t env_max_hwmon_inputs = 32;

    // A small sysfs file's first line, without the newline
    bool env_read_line(const std::string& path, char *buf, size_t sz) {
        FILE *f = fopen(path.c_str(), "r");

        if (f == nullptr)
            return false;

        bool ok = fgets(buf, (int) sz, f) != nullptr;
        fclose(f);

        if (!ok)
            return false;

        buf[strcspn(buf, "\r\n")] = 0;
        return true;
    }

    bool env_read_long(const std::string& path, long& out) {
        char buf[32];

        if (!env_read_line(path, buf, sizeof(buf)) || buf[0] == 0)
            return false;

        errno = 0;
        char *end = nullptr;
        long v = strtol(buf, &end, 10);

        if (errno != 0 || end == buf || (*end != 0 && !isspace(static_cast<unsigned char>(*end))))
            return false;

        out = v;
        return true;
    }

    // hwmon names go into ids; keep them to the id charset
    std::string env_id_part(const char *s, size_t max) {
        std::string r;

        for (size_t i = 0; s[i] != 0 && r.length() < max; i++) {
            const auto c = static_cast<unsigned char>(s[i]);
            r += (isalnum(c) || c == '_' || c == '.' || c == '-') ? (char) c : '_';
        }

        return r;
    }

    // N of a name like <prefix>N<suffix>, or -1
    long env_name_index(const char *name, const char *prefix, const char *suffix) {
        const size_t pl = strlen(prefix), sl = strlen(suffix), nl = strlen(name);

        if (nl <= pl + sl || strncmp(name, prefix, pl) != 0 || strcmp(name + nl - sl, suffix) != 0)
            return -1;

        long v = 0;
        for (size_t i = pl; i < nl - sl; i++) {
            if (!isdigit(static_cast<unsigned char>(name[i])) || v > 100000)
                return -1;
            v = v * 10 + (name[i] - '0');
        }

        return v;
    }
}

void env_read_thermal_zones(const std::string& root, std::vector<env_host_reading>& out) {
    // Thermal zones of newer kernels, in millidegrees; zone 0 keeps its old name
    // of system-thermal-0
    for (unsigned int z = 0; z < env_max_zones; z++) {
        auto zone = fmt::format("{}/thermal_zone{}", root, z);
        long mdeg;

        if (!env_read_long(zone + "/temp", mdeg)) {
            if (access(zone.c_str(), F_OK) != 0)
                break;
            // Zones that can't be read right now (a sleeping device) fail the read
            continue;
        }

        env_host_reading r;
        r.id = fmt::format("system-thermal-{}", z);
        r.label = fmt::format("thermal zone {}", z);
        r.kind = env_kind::thermal;
        r.value = mdeg / 1000.0;

        char type[64];
        if (env_read_line(zone + "/type", type, sizeof(type)) && type[0] != 0)
            r.label = munge_to_printable(type);

        out.push_back(r);
    }
}

void env_read_hwmon(const std::string& root, std::vector<env_host_reading>& out) {
    DIR *d = opendir(root.c_str());

    if (d == nullptr)
        return;

    std::vector<long> devs;
    struct dirent *ent;

    while ((ent = readdir(d)) != nullptr && devs.size() < env_max_hwmon) {
        auto n = env_name_index(ent->d_name, "hwmon", "");
        if (n >= 0)
            devs.push_back(n);
    }

    closedir(d);

    std::sort(devs.begin(), devs.end());

    // hwmonN numbering changes across boots, so ids come from the driver name, and
    // from the device the hwmon belongs to when several share a name
    struct hwmon_dev {
        long index;
        std::string dir, name_id, name_label, dev_path, dev_id, prefix;
    };

    std::vector<hwmon_dev> hdevs;

    for (auto dev : devs) {
        hwmon_dev h;
        h.index = dev;
        h.dir = fmt::format("{}/hwmon{}", root, dev);

        char name[64];
        if (!env_read_line(h.dir + "/name", name, sizeof(name)) || name[0] == 0)
            snprintf(name, sizeof(name), "hwmon");

        h.name_id = env_id_part(name, 24);
        h.name_label = munge_to_printable(name);

        char *rp = realpath((h.dir + "/device").c_str(), nullptr);
        if (rp != nullptr) {
            h.dev_path = rp;
            const char *base = strrchr(rp, '/');
            h.dev_id = env_id_part(base != nullptr ? base + 1 : rp, 24);
            free(rp);
        }

        hdevs.push_back(h);
    }

    // Duplicates in device path order; the hwmon number only breaks ties
    std::stable_sort(hdevs.begin(), hdevs.end(), [](const hwmon_dev& a, const hwmon_dev& b) {
        if (a.name_id != b.name_id)
            return a.name_id < b.name_id;
        if (a.dev_path.empty() != b.dev_path.empty())
            return b.dev_path.empty();
        if (a.dev_path != b.dev_path)
            return a.dev_path < b.dev_path;
        return a.index < b.index;
    });

    for (size_t i = 0; i < hdevs.size(); ) {
        size_t j = i;
        while (j < hdevs.size() && hdevs[j].name_id == hdevs[i].name_id)
            j++;

        if (j - i == 1) {
            hdevs[i].prefix = hdevs[i].name_id;
        } else {
            // The device name when every one has a distinct one, else the position
            std::unordered_set<std::string> seen;
            bool by_dev = true;

            for (size_t k = i; k < j; k++)
                if (hdevs[k].dev_id.empty() || !seen.insert(hdevs[k].dev_id).second)
                    by_dev = false;

            for (size_t k = i; k < j; k++)
                hdevs[k].prefix = by_dev ? fmt::format("{}-{}", hdevs[k].name_id, hdevs[k].dev_id) :
                    fmt::format("{}-{}", hdevs[k].name_id, k - i);
        }

        i = j;
    }

    std::sort(hdevs.begin(), hdevs.end(), [](const hwmon_dev& a, const hwmon_dev& b) {
        return a.index < b.index;
    });

    for (const auto& hdev : hdevs) {
        const auto& dir = hdev.dir;
        const auto& name_label = hdev.name_label;

        DIR *hd = opendir(dir.c_str());
        if (hd == nullptr)
            continue;

        // (kind, index), sorted so the order doesn't follow the directory
        std::vector<std::pair<int, long>> inputs;

        while ((ent = readdir(hd)) != nullptr && inputs.size() < env_max_hwmon_inputs) {
            long t = env_name_index(ent->d_name, "temp", "_input");
            long f = env_name_index(ent->d_name, "fan", "_input");

            if (t >= 0)
                inputs.push_back({0, t});
            else if (f >= 0)
                inputs.push_back({1, f});
        }

        closedir(hd);

        std::sort(inputs.begin(), inputs.end());

        for (const auto& in : inputs) {
            const char *pfx = in.first == 0 ? "temp" : "fan";
            long v;

            if (!env_read_long(fmt::format("{}/{}{}_input", dir, pfx, in.second), v))
                continue;

            env_host_reading r;
            r.id = fmt::format("{}-{}{}", hdev.prefix, pfx, in.second);
            r.kind = in.first == 0 ? env_kind::thermal : env_kind::fan;
            r.value = in.first == 0 ? v / 1000.0 : (double) v;

            char label[64];
            std::string label_s;
            if (env_read_line(fmt::format("{}/{}{}_label", dir, pfx, in.second), label, sizeof(label)) &&
                    label[0] != 0)
                label_s = munge_to_printable(label);
            else
                label_s = fmt::format("{}{}", pfx, in.second);

            r.label = fmt::format("{} ({})", label_s, name_label);

            out.push_back(r);
        }
    }
}

void env_battery_readings(const std::vector<kis_battery_reading>& batteries, int ext_online,
        std::vector<env_host_reading>& out) {
    for (const auto& b : batteries) {
        // A battery with no charge reading has no value to record
        if (b.percentage < 0)
            continue;

        env_host_reading r;
        r.id = fmt::format("system-battery-{}", b.name);
        r.label = b.name;
        r.kind = env_kind::battery;
        r.value = b.percentage;
        r.batt_state = b.state;

        if (ext_online >= 0)
            r.ext_power = ext_online > 0 || b.state == kis_battery_state::charging ? 1 : 0;
        else if (b.state == kis_battery_state::discharging)
            r.ext_power = 0;
        else if (b.state != kis_battery_state::unknown)
            r.ext_power = 1;

        r.voltage = b.voltage > 0 && b.voltage <= 100 ? b.voltage : 0;
        r.remaining_s = (uint32_t) std::clamp<int64_t>(b.remaining_sec, 0, env_max_remaining_s);

        out.push_back(r);
    }
}

environment_store::environment_store(const env_store_config& in_config) :
    config{in_config},
    source_total_count{0} {

    host_counts.fill(0);

    status_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.system.environment",
                tracker_element_factory<tracked_env_status>(), "environmental sensors");
    sensor_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.system.environment.sensor",
                tracker_element_factory<tracked_env_sensor>(), "environmental sensor");
    reading_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.system.environment.reading",
                tracker_element_factory<tracked_env_reading>(), "environmental sensor value");

    status = std::make_shared<tracked_env_status>(status_id);
    status->set_history(config.history);
    status->set_source_report_sec(config.source_max_sensors == 0 ? 0 : config.report_ms / 1000);
    status->set_source_stale_sec(static_cast<uint32_t>(stale_sec()));
}

std::shared_ptr<tracked_env_sensor> environment_store::new_sensor(const std::string& in_key, env_kind in_kind) {
    auto sensor = std::make_shared<tracked_env_sensor>(sensor_id);
    sensor->set_sensor_id(in_key);
    sensor->set_kind(env_kind_str(in_kind));
    sensor->set_units(env_kind_units(in_kind));
    status->get_sensors()->insert(in_key, sensor);
    return sensor;
}

void environment_store::update_sensor(const std::shared_ptr<tracked_env_sensor>& sensor, double in_value,
        time_t in_last_time, time_t in_now) {
    sensor->set_sensor_value(in_value);
    sensor->set_last_time(in_last_time);

    // The history follows the server clock, whatever time the reading carries
    if (config.history)
        sensor->get_rrd()->add_sample(in_value, in_now);
}

bool environment_store::record_host(const env_host_reading& in_reading, time_t in_now) {
    if (!std::isfinite(in_reading.value))
        return false;

    auto sensors = status->get_sensors();
    std::shared_ptr<tracked_env_sensor> sensor;
    const auto k = static_cast<size_t>(in_reading.kind) % host_counts.size();

    auto si = sensors->find(in_reading.id);
    if (si == sensors->end()) {
        // Sensors are kept once seen, so a host with many is capped
        if (host_counts[k] >= config.host_max_sensors)
            return false;

        host_counts[k]++;
        sensor = new_sensor(in_reading.id, in_reading.kind);
        sensor->set_label(in_reading.label);
        sensor->set_origin("host");
    } else {
        sensor = std::static_pointer_cast<tracked_env_sensor>(si->second);
    }

    update_sensor(sensor, in_reading.value, in_now, in_now);

    if (in_reading.kind == env_kind::battery) {
        auto b = sensor->get_battery();
        b->set_state(kis_battery_state_str(in_reading.batt_state));
        b->set_external_power(in_reading.ext_power);
        b->set_voltage(in_reading.voltage);
        b->set_remaining(in_reading.remaining_s);
    }

    return true;
}

bool environment_store::record_source(const uuid& in_uuid, const std::string& in_name,
        const env_report& in_report, time_t in_now, uint64_t in_mono_ms) {
    if (config.source_max_sensors == 0 || config.report_ms == 0) {
        status->inc_dropped_reports();
        return false;
    }

    auto& src = sources[in_uuid];

    if (src.reported && in_mono_ms - src.last_report_ms < config.report_ms / 2) {
        status->inc_dropped_reports();
        return false;
    }

    src.reported = true;
    src.last_report_ms = in_mono_ms;

    // The source's own clock only when it agrees with ours
    time_t last_time = in_now;
    if (in_report.has_ts && in_report.ts_s <= (uint64_t) in_now + 60 && in_report.ts_s + 60 >= (uint64_t) in_now)
        last_time = (time_t) in_report.ts_s;

    auto sensors = status->get_sensors();

    for (const auto& r : in_report.readings) {
        const auto key = source_key(in_uuid, r.id);
        std::shared_ptr<tracked_env_sensor> sensor;

        auto si = sensors->find(key);
        if (si == sensors->end()) {
            if (src.count >= config.source_max_sensors || source_total_count >= config.source_total_max) {
                status->inc_dropped_sensors();
                continue;
            }

            src.count++;
            source_total_count++;

            sensor = new_sensor(key, r.kind);
            sensor->set_origin("datasource");
            sensor->set_source_uuid(in_uuid);
        } else {
            sensor = std::static_pointer_cast<tracked_env_sensor>(si->second);

            // A sensor keeps its kind, so its history keeps one unit
            if (sensor->get_kind() != env_kind_str(r.kind)) {
                status->inc_dropped_sensors();
                continue;
            }
        }

        sensor->set_label(r.label.length() ? r.label : r.id);
        sensor->set_source_name(in_name);

        update_sensor(sensor, r.value, last_time, in_now);

        if (r.kind == env_kind::battery) {
            auto b = sensor->get_battery();
            b->set_state(kis_battery_state_str(static_cast<kis_battery_state>(r.batt_state)));
            b->set_external_power(r.ext_power);
            b->set_voltage(r.voltage);
            b->set_remaining(r.remaining_s);
        }
    }

    return true;
}

size_t environment_store::sweep(const std::unordered_set<uuid>& in_live, time_t in_now) {
    auto sensors = status->get_sensors();
    size_t removed = 0;
    const time_t stale = stale_sec();

    for (auto i = sensors->begin(); i != sensors->end(); ) {
        auto sensor = std::static_pointer_cast<tracked_env_sensor>(i->second);

        if (sensor->get_origin() != "datasource") {
            ++i;
            continue;
        }

        const auto src_uuid = sensor->get_source_uuid();

        if (in_live.find(src_uuid) != in_live.end()) {
            const time_t last = static_cast<time_t>(sensor->get_last_time());

            if (last >= in_now || in_now - last <= stale) {
                ++i;
                continue;
            }

            // Stale sensor of a source still listed; free its share of the caps
            auto s = sources.find(src_uuid);
            if (s != sources.end() && s->second.count > 0) {
                s->second.count--;
                if (source_total_count > 0)
                    source_total_count--;
            }
        }

        i = sensors->erase(i);
        removed++;
    }

    for (auto s = sources.begin(); s != sources.end(); ) {
        if (in_live.find(s->first) != in_live.end()) {
            ++s;
            continue;
        }

        source_total_count -= std::min(source_total_count, s->second.count);
        s = sources.erase(s);
    }

    return removed;
}

std::shared_ptr<tracked_env_status> environment_store::thermal_view() {
    auto view = copy_header();

    auto vs = view->get_sensors();
    const std::string thermal = env_kind_str(env_kind::thermal);

    for (const auto& s : *status->get_sensors()) {
        auto sensor = std::static_pointer_cast<tracked_env_sensor>(s.second);
        if (sensor->get_kind() == thermal)
            vs->insert(s.first, s.second);
    }

    return view;
}

std::shared_ptr<tracked_env_status> environment_store::copy_header() {
    auto view = std::make_shared<tracked_env_status>(status_id);
    view->set_history(status->get_history());
    view->set_dropped_reports(status->get_dropped_reports());
    view->set_dropped_sensors(status->get_dropped_sensors());
    view->set_source_report_sec(status->get_source_report_sec());
    view->set_source_stale_sec(status->get_source_stale_sec());
    return view;
}

std::shared_ptr<tracked_env_status> environment_store::current() {
    auto view = copy_header();
    auto vs = view->get_sensors();

    for (const auto& s : *status->get_sensors()) {
        auto sensor = std::static_pointer_cast<tracked_env_sensor>(s.second);
        auto c = std::make_shared<tracked_env_sensor>(sensor_id);

        c->set_sensor_id(sensor->get_sensor_id());
        c->set_label(sensor->get_label());
        c->set_kind(sensor->get_kind());
        c->set_units(sensor->get_units());
        c->set_sensor_value(sensor->get_sensor_value());
        c->set_last_time(sensor->get_last_time());
        c->set_origin(sensor->get_origin());
        c->set_source_uuid(sensor->get_source_uuid());
        c->set_source_name(sensor->get_source_name());

        if (sensor->has_battery()) {
            auto b = sensor->get_tracker_battery();
            auto cb = c->get_battery();
            cb->set_state(b->get_state());
            cb->set_external_power(b->get_external_power());
            cb->set_voltage(b->get_voltage());
            cb->set_remaining(b->get_remaining());
        }

        vs->insert(s.first, c);
    }

    return view;
}

std::shared_ptr<tracker_element_string_map> environment_store::readings() {
    auto r = std::make_shared<tracker_element_string_map>(status->get_sensors()->get_id());

    for (const auto& s : *status->get_sensors()) {
        auto sensor = std::static_pointer_cast<tracked_env_sensor>(s.second);
        auto v = std::make_shared<tracked_env_reading>(reading_id);

        v->set_label(sensor->get_label());
        v->set_kind(sensor->get_kind());
        v->set_sensor_value(sensor->get_sensor_value());
        v->set_last_time(sensor->get_last_time());
        v->set_source_uuid(sensor->get_source_uuid());
        v->set_source_name(sensor->get_source_name());

        r->insert(s.first, v);
    }

    return r;
}

size_t environment_store::source_sensor_count(const uuid& in_uuid) const {
    auto s = sources.find(in_uuid);
    return s == sources.end() ? 0 : s->second.count;
}
