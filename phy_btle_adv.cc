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

#include "phy_btle_adv.h"
#include "bluetooth_ids.h"
#include "fmt.h"

namespace {

constexpr size_t max_uuid16 = 32;
constexpr size_t max_service_names = 32;
constexpr size_t max_name = 64;

constexpr uint8_t ad_uuid16_incomplete = 0x02;
constexpr uint8_t ad_uuid16_complete = 0x03;
constexpr uint8_t ad_name_short = 0x08;
constexpr uint8_t ad_name_complete = 0x09;
constexpr uint8_t ad_device_id = 0x10;
constexpr uint8_t ad_service_data16 = 0x16;
constexpr uint8_t ad_manuf_data = 0xFF;

constexpr uint16_t le16(const uint8_t *p) {
    return (uint16_t) (p[0] | (p[1] << 8));
}

void add_uuid16(std::vector<uint16_t>& v, uint16_t u) {
    if (v.size() >= max_uuid16)
        return;

    for (auto e : v)
        if (e == u)
            return;

    v.push_back(u);
}

}

void bt_adv_decode::ad(uint8_t type, const uint8_t *data, size_t len) {
    namespace at = btle_adtypes;

    if (data == nullptr && len != 0)
        return;

    switch (type) {
        case ad_uuid16_incomplete:
        case ad_uuid16_complete:
            for (size_t off = 0; off + 2 <= len; off += 2)
                add_uuid16(uuid16, le16(data + off));
            break;

        case ad_name_short:
        case ad_name_complete:
            if (name.empty() || type == ad_name_complete)
                name.assign((const char *) data, std::min(len, max_name));
            break;

        case ad_device_id:
            // Only EIR uses 0x10 for the Device ID; on LE it's the 16-byte TK value
            if (len == 8) {
                auto src = le16(data);
                if (src == 1 || src == 2) {
                    has_device_id = true;
                    did_source = src;
                    did_vendor = le16(data + 2);
                    did_product = le16(data + 4);
                    did_version = le16(data + 6);
                }
            }
            break;

        case ad_service_data16:
            if (len < 2)
                break;

            add_uuid16(uuid16, le16(data));

            if (!has_fastpair)
                has_fastpair = btle_vendor::decode_fastpair(data, len, fastpair);
            if (!has_matter)
                has_matter = btle_vendor::decode_matter(data, len, matter);
            if (!has_digital_key)
                has_digital_key = btle_vendor::decode_ccc_digital_key(data, len);
            if (!has_sensor)
                has_sensor = btle_sensor::decode_service_data(data, len, sensor);

            switch (le16(data)) {
                case at::uuid_mesh_proxy:
                    has_mesh_proxy = at::decode_mesh_proxy(data, len, mesh_proxy);
                    break;
                case at::uuid_mesh_provisioning:
                    has_mesh_prov = at::decode_mesh_provisioning(data, len, mesh_prov);
                    break;
                case at::uuid_broadcast_audio:
                    has_broadcast = at::decode_broadcast_audio(data, len, broadcast);
                    break;
                case at::uuid_public_broadcast:
                    has_public_broadcast = at::decode_public_broadcast(data, len, public_broadcast);
                    break;
                case at::uuid_ascs:
                case at::uuid_cas:
                    // ASCS carries the contexts, so it wins over CAS
                    if (!has_unicast || unicast.service != at::uuid_ascs)
                        has_unicast = at::decode_unicast_announcement(data, len, unicast);
                    break;
            }
            break;

        case ad_manuf_data:
            if (len < 2)
                break;

            if (company_id < 0)
                company_id = le16(data);

            if (!has_microsoft)
                has_microsoft = btle_vendor::decode_microsoft(data, len, microsoft);
            if (!has_sensor)
                has_sensor = btle_sensor::decode_manuf_data(data, len, sensor);
            if (!has_continuity)
                has_continuity = btle_continuity::decode_manuf_data(data, len, continuity);
            break;

        case at::ad_mesh_beacon:
            if (!has_mesh_beacon)
                has_mesh_beacon = at::decode_mesh_beacon(data, len, mesh_beacon);
            break;

        case at::ad_mesh_message:
        case at::ad_pb_adv:
            has_mesh_message = true;
            break;

        case at::ad_broadcast_name:
            if (broadcast_name.empty())
                at::decode_broadcast_name(data, len, broadcast_name);
            break;

        case at::ad_resolvable_set_id:
            if (coordinated_set.empty())
                at::decode_resolvable_set_id(data, len, coordinated_set);
            break;

        case at::ad_indoor_positioning:
            if (!has_indoor)
                has_indoor = at::decode_indoor_positioning(data, len, indoor);
            break;

        case at::ad_uri:
            if (uri.empty())
                at::decode_uri(data, len, uri);
            break;

        case at::ad_adv_interval:
        case at::ad_adv_interval_long:
            {
                uint64_t us;
                bool ok = type == at::ad_adv_interval ?
                    at::decode_adv_interval(data, len, us) :
                    at::decode_adv_interval_long(data, len, us);
                if (ok)
                    adv_interval_us = us;
            }
            break;

        case at::ad_le_role:
            has_le_role = at::decode_le_role(data, len, role);
            break;

        case at::ad_peripheral_conn_interval:
            has_conn_interval = at::decode_conn_interval_range(data, len, conn_interval);
            break;

        case at::ad_le_supported_features:
            if (le_features.empty())
                at::decode_le_features(data, len, le_features);
            break;

        case at::ad_transport_discovery:
            if (!has_tds)
                has_tds = at::decode_transport_discovery(data, len, tds);
            break;
    }
}

void bt_adv_decode::block(const uint8_t *data, size_t len) {
    if (data == nullptr)
        return;

    size_t off = 0;

    while (off < len) {
        size_t l = data[off];

        // A zero length ends the significant part of EIR
        if (l == 0 || l > len - off - 1)
            break;

        ad(data[off + 1], data + off + 2, l - 1);
        off += l + 1;
    }
}

bool bt_adv_decode::any() const {
    // A name only matters here when it names a vehicle
    return company_id >= 0 || !uuid16.empty() ||
        (!name.empty() && btle_vendor::vehicle_from_name(name) != nullptr) || has_device_id ||
        has_microsoft || has_fastpair || has_matter || has_digital_key || has_sensor ||
        has_continuity || has_mesh_beacon || has_mesh_proxy || has_mesh_prov ||
        has_mesh_message || !broadcast_name.empty() || has_broadcast || has_public_broadcast ||
        has_unicast || !coordinated_set.empty() || has_indoor || !uri.empty() || adv_interval_us != 0 ||
        has_le_role || has_conn_interval || !le_features.empty() || has_tds;
}

namespace {

void apply_continuity(bt_tracked_continuity& c, const btle_continuity::info& i, time_t now) {
    namespace bc = btle_continuity;

    auto seen = c.get_seen_types() | i.seen_types;
    if (seen != c.get_seen_types()) {
        c.set_seen_types(seen);
        c.set_messages(bc::types_str(seen));
    }

    if (i.nearby_info.present) {
        c.set_activity(bc::activity_str(i.nearby_info.activity));
        c.set_airdrop_receiving(i.nearby_info.airdrop_receiving);
        if (i.nearby_info.has_data_flags)
            c.set_wifi_on(i.nearby_info.wifi_on);
    }

    if (i.nearby_action.present) {
        c.set_nearby_action(bc::action_type_str(i.nearby_action.type));
        if (i.nearby_action.device_class != 0)
            c.set_setup_device(bc::device_class_str(i.nearby_action.device_class));
    }

    if (i.homekit.present) {
        c.set_homekit_category(bc::homekit_category_str(i.homekit.category));
        c.set_homekit_id(i.homekit.device_id);
        c.set_homekit_paired(i.homekit.paired);
        c.set_homekit_config(i.homekit.config_number);
    }

    if (i.airplay_target.present && !i.airplay_target.ipv4.empty())
        c.set_airplay_ipv4(i.airplay_target.ipv4);

    if (i.airprint.present && !i.airprint.address.empty())
        c.set_airprint_address(i.airprint.address);

    if (i.tethering_source.present) {
        if (i.tethering_source.battery_known)
            c.set_hotspot_battery(i.tethering_source.battery);
        c.set_hotspot_network(bc::cell_service_str(i.tethering_source.cell));
        c.set_hotspot_bars(i.tethering_source.signal_bars);
    }

    c.set_last_time(now);
}

void apply_mesh(bt_tracked_mesh& m, const bt_adv_decode& d) {
    namespace at = btle_adtypes;

    if (d.has_mesh_beacon) {
        const auto& b = d.mesh_beacon;
        m.set_beacon(at::mesh_beacon_type_str(b.type));

        if (b.type == at::mesh_beacon_type::unprovisioned) {
            m.set_device_uuid(b.device_uuid);
            m.set_oob_info(at::mesh_oob_info_str(b.oob_info));
        } else if (b.type == at::mesh_beacon_type::secure_network) {
            m.set_network_id(b.network_id);
            m.set_iv_index(b.iv_index);
            m.set_key_refresh(b.key_refresh);
            m.set_iv_update(b.iv_update);
        }
    }

    if (d.has_mesh_proxy) {
        m.set_proxy(at::mesh_proxy_id_str(d.mesh_proxy.id_type));
        if (d.mesh_proxy.id_type == at::mesh_proxy_id::network_id)
            m.set_network_id(d.mesh_proxy.network_id);
    }

    if (d.has_mesh_prov) {
        m.set_device_uuid(d.mesh_prov.device_uuid);
        m.set_oob_info(at::mesh_oob_info_str(d.mesh_prov.oob_info));
    }

    if (d.has_mesh_message)
        m.set_message(1);
}

void apply_audio(bt_tracked_audio& a, const bt_adv_decode& d) {
    namespace at = btle_adtypes;

    if (!d.broadcast_name.empty())
        a.set_broadcast_name(d.broadcast_name);

    if (d.has_broadcast)
        a.set_broadcast_id(d.broadcast.broadcast_id_hex);

    if (d.has_public_broadcast) {
        const auto& p = d.public_broadcast;
        a.set_encrypted(p.encrypted);
        if (p.standard_quality && p.high_quality)
            a.set_quality("standard, high");
        else if (p.high_quality)
            a.set_quality("high");
        else if (p.standard_quality)
            a.set_quality("standard");
        if (!p.program_info.empty())
            a.set_program_info(p.program_info);
        if (!p.language.empty())
            a.set_language(p.language);
    }

    if (d.has_unicast) {
        const auto& u = d.unicast;
        a.set_unicast(fmt::format("{} {}", u.service == at::uuid_ascs ? "ASCS" : "CAS",
                    at::announcement_type_str(u.type)));
        if (u.has_contexts) {
            a.set_sink_contexts(at::audio_context_str(u.sink_contexts));
            a.set_source_contexts(at::audio_context_str(u.source_contexts));
        }
    }

    if (!d.coordinated_set.empty())
        a.set_coordinated_set(d.coordinated_set);
}

void apply_indoor(bt_tracked_indoor& n, const btle_adtypes::indoor_positioning& p) {
    if (p.has_coordinates && p.coordinates_set) {
        if (p.local_coordinates) {
            n.set_north_dm(p.north_dm);
            n.set_east_dm(p.east_dm);
        } else {
            n.set_latitude(p.latitude);
            n.set_longitude(p.longitude);
        }
    }

    if (p.has_tx_power)
        n.set_tx_power(p.tx_power);
    if (p.has_floor)
        n.set_floor(p.floor);
    if (p.has_altitude)
        n.set_altitude_dm(p.altitude_dm);
    if (p.has_uncertainty) {
        n.set_mobile(p.mobile);
        n.set_precision(p.precision_code);
    }
}

}

void apply_adv(bt_tracked_adv& adv, const bt_adv_decode& d, kis_bt_manuf *btmanuf,
        kis_bt_oid *btoid, time_t now) {
    namespace at = btle_adtypes;

    if (btmanuf != nullptr && d.company_id >= 0) {
        auto cn = btmanuf->lookup_manuf(d.company_id);
        if (cn != nullptr && !btmanuf->is_unknown_manuf(cn) && cn != adv.get_company_name())
            adv.set_company_name(cn);
    }

    if (btoid != nullptr && !d.uuid16.empty()) {
        for (auto u : d.uuid16) {
            auto on = btoid->lookup_oid(u);
            if (on == nullptr || btoid->is_unknown_oid(on))
                continue;

            auto names = adv.get_service_names();
            if (names->size() >= max_service_names)
                break;

            bool found = false;
            for (const auto& e : *names) {
                if (e == on) {
                    found = true;
                    break;
                }
            }

            if (!found)
                names->push_back(on);
        }
    }

    for (auto u : d.uuid16) {
        auto h = btle_vendor::service_class_hint(u);
        if (h != nullptr) {
            adv.set_service_class(h);
            break;
        }
    }

    {
        const char *v = nullptr;

        if (!d.name.empty())
            v = btle_vendor::vehicle_from_name(d.name);

        for (auto u : d.uuid16) {
            if (v != nullptr)
                break;
            v = btle_vendor::digital_key_hint(u);
        }

        if (v == nullptr && d.has_digital_key)
            v = "Digital Key";

        if (v != nullptr)
            adv.set_vehicle(v);
    }

    if (d.has_device_id) {
        auto did = adv.get_device_id();
        did->set_vendor_source(d.did_source == 1 ? "Bluetooth SIG" : "USB-IF");
        did->set_vendor(d.did_vendor);
        did->set_product(d.did_product);
        did->set_version(fmt::format("{:x}.{:x}.{:x}", d.did_version >> 8,
                    (d.did_version >> 4) & 0xF, d.did_version & 0xF));

        if (d.did_source == 1 && btmanuf != nullptr) {
            auto vn = btmanuf->lookup_manuf(d.did_vendor);
            if (vn != nullptr && !btmanuf->is_unknown_manuf(vn) && vn != did->get_vendor_name())
                did->set_vendor_name(vn);
        }
    }

    if (d.has_microsoft) {
        const auto& m = d.microsoft;
        if (m.type == btle_vendor::microsoft_type::cdp) {
            adv.set_microsoft_device(btle_vendor::cdp_device_type_str(m.cdp_device_type));
        } else if (m.type == btle_vendor::microsoft_type::swift_pair) {
            adv.set_microsoft_device(fmt::format("Swift Pair ({})",
                        btle_vendor::swift_pair_mode_str(m.sp_mode)));
            if (!m.sp_name.empty())
                adv.set_swift_pair_name(m.sp_name);
        }
    }

    if (d.has_fastpair)
        adv.set_fast_pair_model(d.fastpair.model_id_hex);

    if (d.has_matter) {
        auto mt = adv.get_matter();
        mt->set_discriminator(d.matter.discriminator);
        mt->set_vendor_id(d.matter.vendor_id);
        mt->set_product_id(d.matter.product_id);
        mt->set_adv_version(d.matter.adv_version);
        mt->set_extended_announcement(d.matter.extended_announcement);
        auto vn = btle_vendor::matter_vendor_name(d.matter.vendor_id);
        if (vn != nullptr)
            mt->set_vendor_name(vn);
    }

    if (d.has_sensor) {
        auto s = adv.get_sensor();
        s->set_source(btle_sensor::source_str(d.sensor.src));
        if (d.sensor.has_temperature)
            s->set_temperature(d.sensor.temperature_c);
        if (d.sensor.has_humidity)
            s->set_humidity(d.sensor.humidity_pct);
        if (d.sensor.has_pressure)
            s->set_pressure(d.sensor.pressure_hpa);
        if (d.sensor.has_battery_mv)
            s->set_battery_mv(d.sensor.battery_mv);
        s->set_last_time(now);
    }

    if (d.has_continuity)
        apply_continuity(*adv.get_continuity(), d.continuity, now);

    if (d.has_mesh_beacon || d.has_mesh_proxy || d.has_mesh_prov || d.has_mesh_message)
        apply_mesh(*adv.get_mesh(), d);

    if (!d.broadcast_name.empty() || d.has_broadcast || d.has_public_broadcast ||
            d.has_unicast || !d.coordinated_set.empty())
        apply_audio(*adv.get_audio(), d);

    if (d.has_indoor)
        apply_indoor(*adv.get_indoor(), d.indoor);

    if (!d.uri.empty())
        adv.set_uri(d.uri);

    if (d.adv_interval_us != 0)
        adv.set_adv_interval_us(d.adv_interval_us);

    if (d.has_le_role)
        adv.set_le_role(at::le_role_str(d.role));

    if (d.has_conn_interval) {
        if (d.conn_interval.min_specified)
            adv.set_conn_interval_min_us(d.conn_interval.min_usec);
        if (d.conn_interval.max_specified)
            adv.set_conn_interval_max_us(d.conn_interval.max_usec);
    }

    if (!d.le_features.empty())
        adv.set_le_features(d.le_features);

    if (d.has_tds && !d.tds.blocks.empty()) {
        std::string t;
        for (const auto& b : d.tds.blocks) {
            if (!t.empty())
                t += "; ";
            if (b.org_name != nullptr)
                t += b.org_name;
            else
                t += fmt::format("org 0x{:02x}", b.org_id);
            t += fmt::format(" ({}, {})", at::tds_role_str(b.role), at::tds_state_str(b.state));
        }
        adv.set_transports(t);
    }

    adv.set_last_time(now);
}
