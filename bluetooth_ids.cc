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

#include "bluetooth_ids.h"

#include <algorithm>

#include "configfile.h"
#include "entrytracker.h"
#include "kis_net_beast_httpd.h"
#include "messagebus.h"

size_t kis_bt_id_table::load(gzFile file) {
    char buf[1024];
    uint32_t last_id = 0;
    bool sorted = true;

    // Lines are 'XXXX<tab>Name'
    while (gzgets(file, buf, sizeof(buf)) != nullptr) {
        auto len = strlen(buf);

        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
            len--;

        const auto tab = static_cast<const char *>(memchr(buf, '\t', len));
        if (tab == nullptr || tab == buf)
            continue;

        char *end = nullptr;
        const auto id = strtoul(buf, &end, 16);
        if (end != tab || id > UINT32_MAX)
            continue;

        const size_t name_len = len - (tab + 1 - buf);
        if (name_len == 0 || name_len > UINT16_MAX)
            continue;

        if (id < last_id)
            sorted = false;
        last_id = id;

        records.push_back({(uint32_t) id, (uint32_t) names.size(), (uint16_t) name_len});
        names.append(tab + 1, name_len);
    }

    gzclose(file);

    // Stable so the first record for a duplicated id still wins
    if (!sorted)
        std::stable_sort(records.begin(), records.end(),
                [](const record& a, const record& b) { return a.id < b.id; });

    records.shrink_to_fit();
    names.shrink_to_fit();

    return records.size();
}

bool kis_bt_id_table::find(uint32_t id, std::string_view& name) const {
    auto ri = std::lower_bound(records.begin(), records.end(), id,
            [](const record& r, uint32_t i) { return r.id < i; });

    if (ri == records.end() || ri->id != id)
        return false;

    name = std::string_view(names.data() + ri->name_offset, ri->name_len);
    return true;
}

kis_bt_oid::kis_bt_oid() {
    mutex.set_name("kis_bt_oid");

    auto entrytracker = Globalreg::fetch_mandatory_global_as<entry_tracker>();

    oid_id =
        entrytracker->register_field("bluetooth.uuid_name",
                tracker_element_factory<tracker_element_string>(), "Bluetooth UUID name");

    unknown_oid = std::make_shared<tracker_element_string>(oid_id);
    unknown_oid->set("Unknown");

    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();
    httpd->register_route("/phy/bluetooth/uuid_names", {"POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    return uuid_names_endpoint(con);
                }));

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("btoid_lookup", true) == false) {
        _MSG_INFO("Disabling Bluetooth OID name lookup");
        return;
    }

    for (auto o : Globalreg::globalreg->kismet_config->fetch_opt_vec("btoid")) {
        auto o_pair = str_tokenize(o, ",");
        unsigned int oid;

        if (o_pair.size() != 2) {
            _MSG_ERROR("Expected 'btoid=AABB,Name' for a config file OID record.");
            continue;
        }

        try {
            oid = string_to_n<unsigned int>(o_pair[0], 16);
        } catch (const std::runtime_error& e) {
            _MSG_ERROR("Expected 'btoid=AABB,Name' for a config file OID record.");
            continue;
        }

        oid_data od;
        od.oid = oid;
        od.data = std::make_shared<tracker_element_string>(oid_id, o_pair[1]);
        oid_map[oid] = od;
    }

    auto fname = 
        Globalreg::globalreg->kismet_config->fetch_opt_dfl("btoidfile", "%S/kismet/kismet_bluetooth_ids.txt.gz");

    auto expanded = Globalreg::globalreg->kismet_config->expand_log_path(fname, "", "", 0, 1);

    if ((zofile = gzopen(expanded.c_str(), "r")) == nullptr) {
        _MSG_ERROR("BTOID file {} was not found, will not resolve Bluetooth service names.",
                expanded);
        return;
    }

    index_bt_oids();
}

kis_bt_oid::~kis_bt_oid() {
    Globalreg::globalreg->remove_global(global_name());

    if (zofile != nullptr)
        gzclose(zofile);
}

void kis_bt_oid::index_bt_oids() {
    if (zofile == nullptr)
        return;

    _MSG_INFO("Loading Bluetooth OID list");

    // load() closes the file
    const auto n = oid_table.load(zofile);
    zofile = nullptr;

    _MSG_INFO("Loaded Bluetooth OID database, {} records", n);
}

std::shared_ptr<tracker_element_string> kis_bt_oid::lookup_oid(uint32_t in_oid) {
    // Config file records and previously resolved OIDs
    {
        kis_lock_guard<kis_mutex> lk(mutex, "kis_bt_oid lookup_oid");

        auto ci = oid_map.find(in_oid);
        if (ci != oid_map.end())
            return ci->second.data;
    }

    // Unknown OIDs aren't cached; the table search is cheap
    std::string_view name;
    if (!oid_table.find(in_oid, name))
        return unknown_oid;

    auto data = std::make_shared<tracker_element_string>(oid_id,
            munge_to_printable(name.data(), name.size()));

    // Another thread may have resolved it first; keep one shared record per OID
    kis_lock_guard<kis_mutex> lk(mutex, "kis_bt_oid lookup_oid insert");
    return oid_map.try_emplace(in_oid, oid_data{in_oid, data}).first->second.data;
}

bool kis_bt_oid::is_unknown_oid(std::shared_ptr<tracker_element_string> in_oid) {
    return in_oid == unknown_oid;
}

namespace {

constexpr size_t max_uuid_names = 64;

constexpr bool all_hex(const char *s, size_t len) {
    for (size_t i = 0; i < len; i++) {
        const char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return len > 0;
}

// The assigned 16-bit number of a lowercase UUID: 'feaf', '0000feaf', or the 128-bit
// Bluetooth base form '0000feaf-0000-1000-8000-00805f9b34fb'
bool assigned_uuid16(const std::string& u, uint32_t& out) {
    static constexpr char base_suffix[] = "-0000-1000-8000-00805f9b34fb";
    std::string hex;

    if (u.size() == 4 && all_hex(u.data(), 4))
        hex = u;
    else if (u.size() == 8 && all_hex(u.data(), 8) && u.compare(0, 4, "0000") == 0)
        hex = u.substr(4);
    else if (u.size() == 36 && all_hex(u.data(), 8) && u.compare(0, 4, "0000") == 0 &&
            u.compare(8, std::string::npos, base_suffix) == 0)
        hex = u.substr(4, 4);
    else
        return false;

    out = std::stoul(hex, nullptr, 16);
    return true;
}

}

std::shared_ptr<tracker_element> kis_bt_oid::uuid_names_endpoint(
        std::shared_ptr<kis_net_beast_httpd_connection> con) {
    auto ret = std::make_shared<tracker_element_string_map>();

    const auto& j = con->json();
    const auto ju = j.is_object() ? j.find("uuids") : j.end();
    if (ju == j.end() || !ju->is_array() || ju->size() > max_uuid_names) {
        con->set_status(400);
        return ret;
    }

    for (const auto& e : *ju) {
        if (!e.is_string())
            continue;

        auto u = e.get<std::string>();
        if (u.size() > 36)
            continue;
        std::transform(u.begin(), u.end(), u.begin(), [](unsigned char c) { return std::tolower(c); });

        uint32_t id;
        if (!assigned_uuid16(u, id))
            continue;

        auto name = lookup_oid(id);
        if (name != nullptr && !is_unknown_oid(name))
            ret->replace(u, name);
    }

    return ret;
}


kis_bt_manuf::kis_bt_manuf() {
    mutex.set_name("kis_bt_manuf");

    auto entrytracker = Globalreg::fetch_mandatory_global_as<entry_tracker>();

    manuf_id =
        entrytracker->register_field("bluetooth.company_name",
                tracker_element_factory<tracker_element_string>(), "Bluetooth company name");

    device_manuf_id =
        entrytracker->register_field("kismet.device.base.manuf",
                tracker_element_factory<tracker_element_string>(), "manufacturer name");

    unknown_manuf = std::make_shared<tracker_element_string>(manuf_id);
    unknown_manuf->set("Unknown");

    if (Globalreg::globalreg->kismet_config->fetch_opt_bool("btmanuf_lookup", true) == false) {
        _MSG_INFO("Disabling Bluetooth manufacturer name lookup");
        return;
    }

    for (auto m : Globalreg::globalreg->kismet_config->fetch_opt_vec("btmanuf")) {
        auto m_pair = str_tokenize(m, ",");
        unsigned int id;

        if (m_pair.size() != 2) {
            _MSG_ERROR("Expected 'btmanuf=AABB,Name' for a config file manufacturer record.");
            continue;
        }

        try {
            id = string_to_n<unsigned int>(m_pair[0], 16);
        } catch (const std::runtime_error& e) {
            _MSG_ERROR("Expected 'btmanuf=AABB,Name' for a config file manufacturer record.");
            continue;
        }

        manuf_data md;
        md.id = id;
        md.manuf = std::make_shared<tracker_element_string>(manuf_id, m_pair[1]);
        manuf_map[id] = md;
    }

    auto fname = 
        Globalreg::globalreg->kismet_config->fetch_opt_dfl("btmanuffile", "%S/kismet/kismet_bluetooth_manuf.txt.gz");

    auto expanded = Globalreg::globalreg->kismet_config->expand_log_path(fname, "", "", 0, 1);

    if ((zmfile = gzopen(expanded.c_str(), "r")) == nullptr) {
        _MSG_ERROR("BTMANUF file {} was not found, will not resolve Bluetooth service names.",
                expanded);
        return;
    }

    index_bt_manufs();
}

kis_bt_manuf::~kis_bt_manuf() {
    Globalreg::globalreg->remove_global(global_name());

    if (zmfile != nullptr)
        gzclose(zmfile);
}

void kis_bt_manuf::index_bt_manufs() {
    if (zmfile == nullptr)
        return;

    _MSG_INFO("Loading Bluetooth manufacturer list");

    // load() closes the file
    const auto n = manuf_table.load(zmfile);
    zmfile = nullptr;

    _MSG_INFO("Loaded Bluetooth manufacturer database, {} records", n);
}

std::shared_ptr<tracker_element_string> kis_bt_manuf::lookup_manuf(uint32_t in_id) {
    // Config file records and previously resolved IDs
    {
        kis_lock_guard<kis_mutex> lk(mutex, "kis_bt_manuf lookup_manuf");

        auto ci = manuf_map.find(in_id);
        if (ci != manuf_map.end())
            return ci->second.manuf;
    }

    // Unknown IDs aren't cached; the table search is cheap
    std::string_view name;
    if (!manuf_table.find(in_id, name))
        return unknown_manuf;

    auto manuf = std::make_shared<tracker_element_string>(manuf_id,
            munge_to_printable(name.data(), name.size()));

    // Another thread may have resolved it first; keep one shared record per ID
    kis_lock_guard<kis_mutex> lk(mutex, "kis_bt_manuf lookup_manuf insert");
    return manuf_map.try_emplace(in_id, manuf_data{in_id, manuf}).first->second.manuf;
}

std::shared_ptr<tracker_element_string> kis_bt_manuf::lookup_device_manuf(uint32_t in_manuf) {
    auto name = lookup_manuf(in_manuf);

    if (name == unknown_manuf)
        return nullptr;

    // One record per company, shared by every device
    kis_lock_guard<kis_mutex> lk(mutex, "kis_bt_manuf lookup_device_manuf");

    auto di = device_manuf_map.find(in_manuf);
    if (di != device_manuf_map.end())
        return di->second;

    auto m = std::make_shared<tracker_element_string>(device_manuf_id, name->get());
    device_manuf_map.emplace(in_manuf, m);

    return m;
}

bool kis_bt_manuf::is_unknown_manuf(std::shared_ptr<tracker_element_string> in_manuf) {
    return in_manuf == unknown_manuf;
}
