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

#include <vector>
#include <stdexcept>

#include "util.h"

#include "trackedelement.h"
#include "globalregistry.h"
#include "entrytracker.h"

#include "endian_magic.h"

#include "alphanum.hpp"

device_key::device_key() {
    spkey = 0;
    dkey = 0;
    error = true;
}

device_key::device_key(const device_key& k) {
    spkey = k.spkey;
    dkey = k.dkey;
    error = k.error;
}

device_key::device_key(uint32_t in_pkey, uint64_t in_dkey) {
    spkey = in_pkey & 0xFFFFFFFF;
    dkey = in_dkey;
    error = false;
}

device_key::device_key(uint32_t in_pkey, mac_addr in_device) {
    spkey = in_pkey & 0xFFFFFFFF;
    dkey = in_device.longmac;
    error = false;
}

device_key::device_key(std::string in_keystr) {
    unsigned long long int k1, k2;

    if (sscanf(in_keystr.c_str(), "%llx_%llx", &k1, &k2) != 2) {
        error = true;
        spkey = 0;
        dkey = 0;
        return;
    }

    // Convert from big endian exported format
    spkey = (uint64_t) kis_ntoh64(k1);
    dkey = (uint64_t) kis_ntoh64(k2);
    error = false;
}

std::string device_key::as_string() const {
    std::stringstream ss;
    ss << *this;
    return ss.str();
}

uint32_t device_key::gen_pkey(std::string phy) {
    return Adler32Checksum(phy.c_str(), phy.length());
}

uint64_t device_key::gen_spkey(uuid s_uuid, std::string phy) {
    uint64_t uuid32 = Adler32Checksum((const char *) s_uuid.uuid_block, 16);
    uint64_t phy32 = gen_pkey(phy);

    return (uuid32 << 32) | phy32;
}

bool operator <(const device_key& x, const device_key& y) {
    if (x.spkey == y.spkey)
        return x.dkey < y.dkey;

    return x.spkey < y.spkey;
}

bool operator ==(const device_key& x, const device_key& y) {
    return (x.spkey == y.spkey && x.dkey == y.dkey);
}

std::ostream& operator<<(std::ostream& os, const device_key& k) {
    std::ios::fmtflags fflags;

    fflags = os.flags();
    os << std::uppercase << std::setfill('0') << std::setw(2) <<
        std::hex << kis_hton64(k.spkey) << "_" << kis_hton64(k.dkey);
    os.flags(fflags);
    return os;
}

std::istream& operator>>(std::istream& is, device_key& k) {
    std::string sline;
    std::getline(is, sline);

    k = device_key(sline);

    if (k.error)
        is.setstate(std::ios::failbit);

    return is;
}

// New

void tracker_element_string::coercive_set(const std::string& in_str) {
    value = in_str;
}

void tracker_element_string::coercive_set(double in_num) {
    value = fmt::format("{}", in_num);
}

void tracker_element_string::coercive_set(const shared_tracker_element& e) {
    switch (e->get_type()) {
        case TrackerType::TrackerInt8:
        case TrackerType::TrackerUInt8:
        case TrackerType::TrackerInt16:
        case TrackerType::TrackerUInt16:
        case TrackerType::TrackerInt32:
        case TrackerType::TrackerUInt32:
        case TrackerType::TrackerInt64:
        case TrackerType::TrackerUInt64:
        case TrackerType::TrackerFloat:
        case TrackerType::TrackerDouble:
            coercive_set(std::static_pointer_cast<tracker_element_core_scalar>(e)->get());
            break;
        case TrackerType::TrackerString:
            coercive_set(std::static_pointer_cast<tracker_element_string>(e)->get());
            break;
        case TrackerType::TrackerUuid:
            coercive_set(std::static_pointer_cast<tracker_element_uuid>(e)->get().UUID2String());
            break;
        case TrackerType::TrackerMac:
            coercive_set(std::static_pointer_cast<tracker_element_mac_addr>(e)->get().Mac2String());
            break;
        default:
            throw std::runtime_error(fmt::format("Could not coerce {} to {}",
                        e->get_type_as_string(), get_type_as_string()));
    }
}

bool tracker_element_string::less_than(const tracker_element_string& rhs) const {
    return doj::alphanum_comp(value, rhs.value) < 0;
}

void tracker_element_uuid::coercive_set(const std::string& in_str) {
    uuid u(in_str);

    if (u.error)
        throw std::runtime_error("Could not coerce string to UUID");

    value = u;
}

void tracker_element_uuid::coercive_set(double in_num) {
    throw std::runtime_error("Cannot coerce UUID from number");
}

void tracker_element_uuid::coercive_set(const shared_tracker_element& e) {
    switch (e->get_type()) {
        case TrackerType::TrackerUuid:
            coercive_set(std::static_pointer_cast<tracker_element_uuid>(e)->get().UUID2String());
            break;
        default:
            throw std::runtime_error(fmt::format("Could not coerce {} to {}",
                        e->get_type_as_string(), get_type_as_string()));
    }
}

void tracker_element_mac_addr::coercive_set(const std::string& in_str) {
    mac_addr m(in_str);

    if (m.error)
        throw std::runtime_error("Could not coerce string to macaddr");

    value = m;
}

void tracker_element_mac_addr::coercive_set(double in_num) {
    throw std::runtime_error("Cannot coerce macaddr from number");
}

void tracker_element_mac_addr::coercive_set(const shared_tracker_element& e) {
    switch (e->get_type()) {
        case TrackerType::TrackerMac:
            coercive_set(std::static_pointer_cast<tracker_element_mac_addr>(e)->get().Mac2String());
            break;
        default:
            throw std::runtime_error(fmt::format("Could not coerce {} to {}",
                        e->get_type_as_string(), get_type_as_string()));
    }
}

std::string tracker_element::type_to_string(TrackerType t) {
    switch (t) {
        case TrackerType::TrackerString:
            return "string";
        case TrackerType::TrackerInt8:
            return "int8_t";
        case TrackerType::TrackerUInt8:
            return "uint8_t";
        case TrackerType::TrackerInt16:
            return "int16_t";
        case TrackerType::TrackerUInt16:
            return "uint16_t";
        case TrackerType::TrackerInt32:
            return "int32_t";
        case TrackerType::TrackerUInt32:
            return "uint32_t";
        case TrackerType::TrackerInt64:
            return "int64_t";
        case TrackerType::TrackerUInt64:
            return "uint64_t";
        case TrackerType::TrackerFloat:
            return "float";
        case TrackerType::TrackerDouble:
            return "double";
        case TrackerType::TrackerMac:
            return "mac_addr";
        case TrackerType::TrackerVector:
            return "vector[x]";
        case TrackerType::TrackerMap:
            return "map[field, x]";
        case TrackerType::TrackerIntMap:
            return "map[int, x]";
        case TrackerType::TrackerUuid:
            return "uuid";
        case TrackerType::TrackerKey:
            return "devicekey";
        case TrackerType::TrackerMacMap:
            return "map[macaddr, x]";
        case TrackerType::TrackerStringMap:
            return "map[string, x]";
        case TrackerType::TrackerDoubleMap:
            return "map[double, x]";
        case TrackerType::TrackerKeyMap:
            return "map[key, x]";
        case TrackerType::TrackerByteArray:
            return "bytearray";
        case TrackerType::TrackerVectorDouble:
            return "vector[double]";
        case TrackerType::TrackerDoubleMapDouble:
            return "map[double,double]";
        case TrackerType::TrackerVectorString:
            return "vector[string]";
        case TrackerType::TrackerHashkeyMap:
            return "vector[size_t]";
    }

    return "unknown";
}

std::string tracker_element::type_to_typestring(TrackerType t) {
    switch (t) {
        case TrackerType::TrackerString:
            return "TrackerString";
        case TrackerType::TrackerInt8:
            return "TrackerInt8";
        case TrackerType::TrackerUInt8:
            return "TrackerUInt8";
        case TrackerType::TrackerInt16:
            return "TrackerInt16";
        case TrackerType::TrackerUInt16:
            return "TrackerUInt16";
        case TrackerType::TrackerInt32:
            return "TrackerInt32";
        case TrackerType::TrackerUInt32:
            return "TrackerUInt32";
        case TrackerType::TrackerInt64:
            return "TrackerInt64";
        case TrackerType::TrackerUInt64:
            return "TrackerUInt64";
        case TrackerType::TrackerFloat:
            return "TrackerFloat";
        case TrackerType::TrackerDouble:
            return "TrackerDouble";
        case TrackerType::TrackerMac:
            return "TrackerMac";
        case TrackerType::TrackerVector:
            return "TrackerVector";
        case TrackerType::TrackerMap:
            return "TrackerMap";
        case TrackerType::TrackerIntMap:
            return "TrackerIntMap";
        case TrackerType::TrackerUuid:
            return "TrackerUuid";
        case TrackerType::TrackerKey:
            return "TrackerKey";
        case TrackerType::TrackerMacMap:
            return "TrackerMacMap";
        case TrackerType::TrackerStringMap:
            return "TrackerStringMap";
        case TrackerType::TrackerDoubleMap:
            return "TrackerDoubleMap";
        case TrackerType::TrackerByteArray:
            return "TrackerByteArray";
        case TrackerType::TrackerKeyMap:
            return "TrackerKeyMap";
        case TrackerType::TrackerVectorDouble:
            return "TrackerVectorDouble";
        case TrackerType::TrackerDoubleMapDouble:
            return "TrackerDoubleMapDouble";
        case TrackerType::TrackerVectorString:
            return "TrackerVectorString";
        case TrackerType::TrackerHashkeyMap:
            return "TrackerHashkeyMap";
    }

    return "TrackerUnknown";
}

TrackerType tracker_element::typestring_to_type(const std::string& s) {
    if (s == "TrackerString")
        return TrackerType::TrackerString;
    if (s == "TrackerInt8")
        return TrackerType::TrackerInt8;
    if (s == "TrackerUInt8")
        return TrackerType::TrackerUInt8;
    if (s == "TrackerInt16")
        return TrackerType::TrackerInt16;
    if (s == "TrackerUInt16")
        return TrackerType::TrackerUInt16;
    if (s == "TrackerInt32")
        return TrackerType::TrackerInt32;
    if (s == "TrackerUInt32")
        return TrackerType::TrackerUInt32;
    if (s == "TrackerInt64")
        return TrackerType::TrackerInt64;
    if (s == "TrackerUInt64")
        return TrackerType::TrackerUInt64;
    if (s == "TrackerFloat")
        return TrackerType::TrackerFloat;
    if (s == "TrackerDouble")
        return TrackerType::TrackerDouble;
    if (s == "TrackerMac")
        return TrackerType::TrackerMac;
    if (s == "TrackerVector")
        return TrackerType::TrackerVector;
    if (s == "TrackerMap")
        return TrackerType::TrackerMap;
    if (s == "TrackerIntMap")
        return TrackerType::TrackerIntMap;
    if (s == "TrackerUuid")
        return TrackerType::TrackerUuid;
    if (s == "TrackerKey")
        return TrackerType::TrackerKey;
    if (s == "TrackerMacMap")
        return TrackerType::TrackerMacMap;
    if (s == "TrackerStringMap")
        return TrackerType::TrackerStringMap;
    if (s == "TrackerDoubleMap")
        return TrackerType::TrackerDoubleMap;
    if (s == "TrackerByteArray")
        return TrackerType::TrackerByteArray;
    if (s == "TrackerKeyMap")
        return TrackerType::TrackerKeyMap;
    if (s == "TrackerVectorDouble")
        return TrackerType::TrackerVectorDouble;
    if (s == "TrackerDoubleMapDouble")
        return TrackerType::TrackerDoubleMapDouble;
    if (s == "TrackerVectorString")
        return TrackerType::TrackerVectorString;
    if (s == "TrackerHashkeyMap")
        return TrackerType::TrackerHashkeyMap;

    throw std::runtime_error("Unable to interpret tracker type " + s);
}

template<> std::string GetTrackerValue(const shared_tracker_element& e) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerString);
#endif
    return std::static_pointer_cast<tracker_element_string>(e)->get();
}

template<> uint8_t GetTrackerValue(const shared_tracker_element& e) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerUInt8);
#endif
    return std::static_pointer_cast<tracker_element_uint8>(e)->get();
}

template<> int8_t GetTrackerValue(const shared_tracker_element& e) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerInt8);
#endif
    return std::static_pointer_cast<tracker_element_int8>(e)->get();
}

template<> uint16_t GetTrackerValue(const shared_tracker_element& e) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerUInt16);
#endif
    return std::static_pointer_cast<tracker_element_uint16>(e)->get();
}

template<> int16_t GetTrackerValue(const shared_tracker_element& e) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerInt16);
#endif
    return std::static_pointer_cast<tracker_element_int16>(e)->get();
}

template<> uint32_t GetTrackerValue(const shared_tracker_element& e) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerUInt32);
#endif
    return std::static_pointer_cast<tracker_element_uint32>(e)->get();
}

template<> int32_t GetTrackerValue(const shared_tracker_element& e) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerInt32);
#endif
    return std::static_pointer_cast<tracker_element_int32>(e)->get();
}

template<> uint64_t GetTrackerValue(const shared_tracker_element& e) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerUInt64);
#endif
    return std::static_pointer_cast<tracker_element_uint64>(e)->get();
}

template<> int64_t GetTrackerValue(const shared_tracker_element& e) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerInt64);
#endif
    return std::static_pointer_cast<tracker_element_int64>(e)->get();
}

template<> float GetTrackerValue(const shared_tracker_element& e) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerFloat);
#endif
    return std::static_pointer_cast<tracker_element_float>(e)->get();
}

template<> double GetTrackerValue(const shared_tracker_element& e) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerDouble);
#endif
    return std::static_pointer_cast<tracker_element_double>(e)->get();
}

template<> mac_addr GetTrackerValue(const shared_tracker_element& e) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerMac);
#endif
    return std::static_pointer_cast<tracker_element_mac_addr>(e)->get();
}

template<> uuid GetTrackerValue(const shared_tracker_element& e) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerUuid);
#endif
    return std::static_pointer_cast<tracker_element_uuid>(e)->get();
}

template<> device_key GetTrackerValue(const shared_tracker_element& e) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerKey);
#endif
    return std::static_pointer_cast<tracker_element_device_key>(e)->get();
}

template<> void SetTrackerValue(const shared_tracker_element& e, const std::string& v) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerString, TrackerType::TrackerByteArray);
#endif
    std::static_pointer_cast<tracker_element_string>(e)->set(v);
}

template<> void SetTrackerValue(const shared_tracker_element& e, const uint8_t& v) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerUInt8);
#endif
    std::static_pointer_cast<tracker_element_uint8>(e)->set(v);
}

template<> void SetTrackerValue(const shared_tracker_element& e, const int8_t& v) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerInt8);
#endif
    std::static_pointer_cast<tracker_element_int8>(e)->set(v);
}

template<> void SetTrackerValue(const shared_tracker_element& e, const uint16_t& v) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerUInt16);
#endif
    std::static_pointer_cast<tracker_element_uint16>(e)->set(v);
}

template<> void SetTrackerValue(const shared_tracker_element& e, const int16_t& v) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerInt16);
#endif
    std::static_pointer_cast<tracker_element_int16>(e)->set(v);
}

template<> void SetTrackerValue(const shared_tracker_element& e, const uint32_t& v) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerUInt32);
#endif
    std::static_pointer_cast<tracker_element_uint32>(e)->set(v);
}

template<> void SetTrackerValue(const shared_tracker_element& e, const int32_t& v) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerInt32);
#endif
    std::static_pointer_cast<tracker_element_int32>(e)->set(v);
}

template<> void SetTrackerValue(const shared_tracker_element& e, const uint64_t& v) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerUInt64);
#endif
    std::static_pointer_cast<tracker_element_uint64>(e)->set(v);
}

template<> void SetTrackerValue(const shared_tracker_element& e, const int64_t& v) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerInt64);
#endif
    std::static_pointer_cast<tracker_element_int64>(e)->set(v);
}

template<> void SetTrackerValue(const shared_tracker_element& e, const float& v) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerFloat);
#endif
    std::static_pointer_cast<tracker_element_float>(e)->set(v);
}

template<> void SetTrackerValue(const shared_tracker_element& e, const double& v) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerDouble);
#endif
    std::static_pointer_cast<tracker_element_double>(e)->set(v);
}

template<> void SetTrackerValue(const shared_tracker_element& e, const mac_addr& v) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerMac);
#endif
    std::static_pointer_cast<tracker_element_mac_addr>(e)->set(v);
}

template<> void SetTrackerValue(const shared_tracker_element& e, const uuid& v) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerUuid);
#endif
    std::static_pointer_cast<tracker_element_uuid>(e)->set(v);
}

template<> void SetTrackerValue(const shared_tracker_element& e, const device_key& v) {
#if TE_TYPE_SAFETY == 1
    e->enforce_type(TrackerType::TrackerKey);
#endif
    std::static_pointer_cast<tracker_element_device_key>(e)->set(v);
}

void tracker_element_serializer::pre_serialize_path(const SharedElementSummary& in_summary) {

    // Iterate through the path on this object, calling pre-serialize as
    // necessary on each object in the summary path

    shared_tracker_element inter = in_summary->parent_element;

    if (inter == nullptr)
        return;

    try {
        for (auto p : in_summary->resolved_path) {
#if TE_TYPE_SAFETY == 1
            inter->enforce_type(TrackerType::TrackerMap);
#endif

            inter = std::static_pointer_cast<tracker_element_map>(inter)->get_sub(p);

            if (inter == nullptr)
                return;

            inter->pre_serialize();
        }
    } catch (std::runtime_error& c) {
        // Do nothing if we hit a map error
        return;
    }
}

void tracker_element_serializer::post_serialize_path(const SharedElementSummary& in_summary) {

    // Iterate through the path on this object, calling pre-serialize as
    // necessary on each object in the summary path

    shared_tracker_element inter = in_summary->parent_element;

    if (inter == nullptr)
        return;

    try {
        for (auto p : in_summary->resolved_path) {
#if TE_TYPE_SAFETY == 1
            inter->enforce_type(TrackerType::TrackerMap);
#endif

            inter = std::static_pointer_cast<tracker_element_map>(inter)->get_sub(p);

            if (inter == nullptr)
                return;

            inter->post_serialize();
        }
    } catch (std::runtime_error& c) {
        // Do nothing if we hit a map error
        return;
    }
}

tracker_element_summary::tracker_element_summary(const SharedElementSummary& in_c) {
    parent_element = in_c->parent_element;
    resolved_path = in_c->resolved_path;
    rename = in_c->rename;
}

tracker_element_summary::tracker_element_summary(const std::string& in_path, 
        const std::string& in_rename) {
    parse_path(StrTokenize(in_path, "/"), in_rename);
}

tracker_element_summary::tracker_element_summary(const std::vector<std::string>& in_path,
        const std::string& in_rename) {
    parse_path(in_path, in_rename);
}

tracker_element_summary::tracker_element_summary(const std::string& in_path) {
    parse_path(StrTokenize(in_path, "/"), "");
}

tracker_element_summary::tracker_element_summary(const std::vector<std::string>& in_path) {
    parse_path(in_path, "");
}

tracker_element_summary::tracker_element_summary(const std::vector<int>& in_path,
        const std::string& in_rename) {
    resolved_path = in_path;
    rename = in_rename;
}

tracker_element_summary::tracker_element_summary(const std::vector<int>& in_path) {
    resolved_path = in_path;
}

void tracker_element_summary::parse_path(const std::vector<std::string>& in_path, 
        const std::string& in_rename) {

    if (in_path.size() == 0) {
        return;
    }

    bool path_full = true;

    for (auto pe : in_path) {
        if (pe.length() == 0)
            continue;

        auto id = Globalreg::globalreg->entrytracker->GetFieldId(pe);

        if (id < 0)
            path_full = false;

        resolved_path.push_back(id);
    }

    if (!path_full) {
        rename = in_path[in_path.size() - 1];
    } else {
        rename = in_rename;
    }
}

shared_tracker_element Gettracker_elementPath(const std::string& in_path, 
        shared_tracker_element elem) {
    return Gettracker_elementPath(StrTokenize(in_path, "/"), elem);
}

shared_tracker_element Gettracker_elementPath(const std::vector<std::string>& in_path, 
        shared_tracker_element elem) {

    if (in_path.size() < 1)
        return nullptr;

    if (elem == nullptr)
        return nullptr;

    shared_tracker_element next_elem;

    for (auto pe : in_path) {
        // Skip empty
        if (pe.length() == 0)
            continue;

        auto id = Globalreg::globalreg->entrytracker->GetFieldId(pe);

        if (id < 0)
            return nullptr;

        if (next_elem == nullptr) {
#if TE_TYPE_SAFETY == 1
            elem->enforce_type(TrackerType::TrackerMap);
#endif
            next_elem = std::static_pointer_cast<tracker_element_map>(elem)->get_sub(id);
        } else {
#if TE_TYPE_SAFETY == 1
            next_elem->enforce_type(TrackerType::TrackerMap);
#endif
            next_elem = std::static_pointer_cast<tracker_element_map>(next_elem)->get_sub(id);
        }

        if (next_elem == nullptr)
            return nullptr;

    }

    return next_elem;
}

shared_tracker_element Gettracker_elementPath(const std::vector<int>& in_path, 
        shared_tracker_element elem) {

    if (in_path.size() < 1)
        return nullptr;

    if (elem == nullptr)
        return nullptr;

    shared_tracker_element next_elem;

    for (auto pe : in_path) {
        if (pe < 0)
            return nullptr;

        if (next_elem == nullptr) {
#if TE_TYPE_SAFETY == 1
            elem->enforce_type(TrackerType::TrackerMap);
#endif
            next_elem = std::static_pointer_cast<tracker_element_map>(elem)->get_sub(pe);
        } else {
            next_elem->enforce_type(TrackerType::TrackerMap);
            next_elem = std::static_pointer_cast<tracker_element_map>(next_elem)->get_sub(pe);
        }

        if (next_elem == nullptr)
            return nullptr;

    }

    return next_elem;
}

std::vector<shared_tracker_element> Gettracker_elementMultiPath(const std::string& in_path, 
        shared_tracker_element elem) {
    return Gettracker_elementMultiPath(StrTokenize(in_path, "/"), elem);
}

std::vector<shared_tracker_element> Gettracker_elementMultiPath(const std::vector<std::string>& in_path, 
        shared_tracker_element elem) {

    std::vector<shared_tracker_element> ret;

    if (in_path.size() < 1)
        return ret;

    shared_tracker_element next_elem = NULL;

    bool complex_fulfilled = false;

    for (auto x = in_path.begin(); x != in_path.end(); ++x) {
        // Skip empty path element
        if (x->length() == 0)
            continue;

        auto id = Globalreg::globalreg->entrytracker->GetFieldId(*x);

        if (id < 0) {
            return ret;
        }

        if (next_elem == nullptr) {
#if TE_TYPE_SAFETY == 1
            elem->enforce_type(TrackerType::TrackerMap);
#endif
            next_elem = std::static_pointer_cast<tracker_element_map>(elem)->get_sub(id);
        } else {
#if TE_TYPE_SAFETY == 1
            next_elem->enforce_type(TrackerType::TrackerMap);
#endif
            next_elem = std::static_pointer_cast<tracker_element_map>(next_elem)->get_sub(id);
        }

        if (next_elem == nullptr) {
            return ret;
        }

        // If we're at the termination of the path, we just return the
        // object.  If we're in the middle of a path, we iterate over the 
        // contents of the container, and find the rest of the path in it
        if (x != std::next(in_path.end(), -1)) {
            auto type = next_elem->get_type();

            if (type == TrackerType::TrackerVector) {
                std::vector<std::string> sub_path(std::next(x, 1), in_path.end());

                auto cn = std::static_pointer_cast<tracker_element_vector>(next_elem);

                for (auto i : *cn) {
                    std::vector<shared_tracker_element> subret =
                        Gettracker_elementMultiPath(sub_path, i);

                    ret.insert(ret.end(), subret.begin(), subret.end());
                }

                complex_fulfilled = true;
                break;
            } else if (type == TrackerType::TrackerIntMap) {
                std::vector<std::string> sub_path(std::next(x, 1), in_path.end());

                auto cn = std::static_pointer_cast<tracker_element_int_map>(next_elem);

                for (auto i : *cn) {
                    std::vector<shared_tracker_element> subret =
                        Gettracker_elementMultiPath(sub_path, i.second);

                    ret.insert(ret.end(), subret.begin(), subret.end());
                }

                complex_fulfilled = true;
                break;
            } else if (type == TrackerType::TrackerStringMap) {
                std::vector<std::string> sub_path(std::next(x, 1), in_path.end());

                auto cn = std::static_pointer_cast<tracker_element_string_map>(next_elem);

                for (auto i : *cn) {
                    std::vector<shared_tracker_element> subret =
                        Gettracker_elementMultiPath(sub_path, i.second);

                    ret.insert(ret.end(), subret.begin(), subret.end());
                }

                complex_fulfilled = true;
                break;
            } else if (type == TrackerType::TrackerMacMap) {
                std::vector<std::string> sub_path(std::next(x, 1), in_path.end());

                auto cn = std::static_pointer_cast<tracker_element_mac_map>(next_elem);

                for (auto i : *cn) {
                    std::vector<shared_tracker_element> subret =
                        Gettracker_elementMultiPath(sub_path, i.second);

                    ret.insert(ret.end(), subret.begin(), subret.end());
                }

                complex_fulfilled = true;
                break;
            } else if (type == TrackerType::TrackerDoubleMap) {
                std::vector<std::string> sub_path(std::next(x, 1), in_path.end());

                auto cn = std::static_pointer_cast<tracker_element_double_map>(next_elem);

                for (auto i : *cn) {
                    std::vector<shared_tracker_element> subret =
                        Gettracker_elementMultiPath(sub_path, i.second);

                    ret.insert(ret.end(), subret.begin(), subret.end());
                }

                complex_fulfilled = true;
                break;
            }
        }
    }

    if (!complex_fulfilled)
        ret.push_back(next_elem);

    return ret;
}

std::vector<shared_tracker_element> Gettracker_elementMultiPath(const std::vector<int>& in_path, 
        shared_tracker_element elem) {

    std::vector<shared_tracker_element> ret;

    if (in_path.size() < 1)
        return ret;

    shared_tracker_element next_elem = nullptr;

    bool complex_fulfilled = false;
    for (auto x = in_path.begin(); x != in_path.end(); ++x) {
        int id = *x;

        if (id < 0) {
            return ret;
        }

        if (next_elem == nullptr) {
#if TE_TYPE_SAFETY == 1
            elem->enforce_type(TrackerType::TrackerMap);
#endif
            next_elem = std::static_pointer_cast<tracker_element_map>(elem)->get_sub(id);
        } else {
#if TE_TYPE_SAFETY == 1
            next_elem->enforce_type(TrackerType::TrackerMap);
#endif
            next_elem = std::static_pointer_cast<tracker_element_map>(next_elem)->get_sub(id);
        }

        if (next_elem == nullptr) {
            return ret;
        }

        // If we're at the termination of the path, we just return the
        // object.  If we're in the middle of a path, we iterate over the 
        // contents of the container, and find the rest of the path in it
        if (x != std::next(in_path.end(), -1)) {
            auto type = next_elem->get_type();

            if (type == TrackerType::TrackerVector) {
                std::vector<int> sub_path(std::next(x, 1), in_path.end());

                auto cn = std::static_pointer_cast<tracker_element_vector>(next_elem);

                for (auto i : *cn) {
                    std::vector<shared_tracker_element> subret =
                        Gettracker_elementMultiPath(sub_path, i);

                    ret.insert(ret.end(), subret.begin(), subret.end());
                }

                complex_fulfilled = true;
                break;
            } else if (type == TrackerType::TrackerIntMap) {
                std::vector<int> sub_path(std::next(x, 1), in_path.end());

                auto cn = std::static_pointer_cast<tracker_element_int_map>(next_elem);

                for (auto i : *cn) {
                    std::vector<shared_tracker_element> subret =
                        Gettracker_elementMultiPath(sub_path, i.second);

                    ret.insert(ret.end(), subret.begin(), subret.end());
                }

                complex_fulfilled = true;
                break;
            } else if (type == TrackerType::TrackerStringMap) {
                std::vector<int> sub_path(std::next(x, 1), in_path.end());

                auto cn = std::static_pointer_cast<tracker_element_string_map>(next_elem);

                for (auto i : *cn) {
                    std::vector<shared_tracker_element> subret =
                        Gettracker_elementMultiPath(sub_path, i.second);

                    ret.insert(ret.end(), subret.begin(), subret.end());
                }

                complex_fulfilled = true;
                break;
            } else if (type == TrackerType::TrackerMacMap) {
                std::vector<int> sub_path(std::next(x, 1), in_path.end());

                auto cn = std::static_pointer_cast<tracker_element_mac_map>(next_elem);

                for (auto i : *cn) {
                    std::vector<shared_tracker_element> subret =
                        Gettracker_elementMultiPath(sub_path, i.second);

                    ret.insert(ret.end(), subret.begin(), subret.end());
                }

                complex_fulfilled = true;
                break;
            } else if (type == TrackerType::TrackerDoubleMap) {
                std::vector<int> sub_path(std::next(x, 1), in_path.end());

                auto cn = std::static_pointer_cast<tracker_element_double_map>(next_elem);

                for (auto i : *cn) {
                    std::vector<shared_tracker_element> subret =
                        Gettracker_elementMultiPath(sub_path, i.second);

                    ret.insert(ret.end(), subret.begin(), subret.end());
                }

                complex_fulfilled = true;
                break;
            }
        }
    }

    if (!complex_fulfilled)
        ret.push_back(next_elem);

    return ret;
}

std::shared_ptr<tracker_element> Summarizetracker_element(shared_tracker_element in, 
        const std::vector<SharedElementSummary>& in_summarization, 
        std::shared_ptr<tracker_element_serializer::rename_map> rename_map) {

    if (in->get_type() == TrackerType::TrackerVector) {
        auto ret = std::make_shared<tracker_element_vector>();
        auto inv = std::static_pointer_cast<tracker_element_vector>(in);

        for (auto i : *inv) 
            ret->push_back(SummarizeSingletracker_element(i, in_summarization, rename_map));

        return ret;
    }

    return SummarizeSingletracker_element(in, in_summarization, rename_map);
}

std::shared_ptr<tracker_element> SummarizeSingletracker_element(shared_tracker_element in, 
        const std::vector<SharedElementSummary>& in_summarization, 
        std::shared_ptr<tracker_element_serializer::rename_map> rename_map) {

    auto ret_elem = std::make_shared<tracker_element_map>();

    if (in == nullptr)
        return ret_elem;

    // Poke the pre-serialization function to update anything that needs updating before
    // we create the new meta-object
    in->pre_serialize();

    if (in_summarization.size() == 0) {
        in->post_serialize();
        return in;
    }

    unsigned int fn = 0;

    for (auto si = in_summarization.begin(); si != in_summarization.end(); ++si) {
        fn++;

        if ((*si)->resolved_path.size() == 0)
            continue;

        shared_tracker_element f =
            Gettracker_elementPath((*si)->resolved_path, in);

        if (f == NULL) {
            f = Globalreg::globalreg->entrytracker->RegisterAndGetField("unknown" + IntToString(fn),
                    tracker_element_factory<tracker_element_int8>(),
                    "unallocated field");

            std::static_pointer_cast<tracker_element_int8>(f)->set(0);
        
            if ((*si)->rename.length() != 0) {
                f->set_local_name((*si)->rename);
            } else {
                // Get the last name of the field in the path, if we can...
                int lastid = (*si)->resolved_path[(*si)->resolved_path.size() - 1];

                if (lastid < 0)
                    f->set_local_name("unknown" + IntToString(fn));
                else
                    f->set_local_name(Globalreg::globalreg->entrytracker->GetFieldName(lastid));
            }
        } 

       
        // If we're renaming it or we're a path, we put the record in.  We need
        // to duplicate the summary object and make a reference to our parent
        // object so that when we serialize we can descend the path calling
        // the proper pre-serialization methods
        if ((*si)->rename.length() != 0 || (*si)->resolved_path.size() > 1) {
            auto sum = std::make_shared<tracker_element_summary>(*si);
            sum->parent_element = in;
            (*rename_map)[f] = sum;
        }

        std::static_pointer_cast<tracker_element_map>(ret_elem)->insert(f);
    }

    in->post_serialize();

    return ret_elem;
}

bool Sorttracker_elementLess(const std::shared_ptr<tracker_element> lhs, 
        const std::shared_ptr<tracker_element> rhs) {

    // Only allow equal compares
    if (lhs->get_type() != rhs->get_type())
        throw std::runtime_error(fmt::format("Attempted to compare two non-equal field types, "
                    "{} < {}", lhs->get_type_as_string(), rhs->get_type_as_string()));

    switch (lhs->get_type()) {
        case TrackerType::TrackerString:
            return tracker_element::safe_cast_as<tracker_element_string>(lhs)->less_than(*tracker_element::safe_cast_as<tracker_element_string>(rhs));
        case TrackerType::TrackerInt8:
            return tracker_element::safe_cast_as<tracker_element_int8>(lhs)->less_than(*tracker_element::safe_cast_as<tracker_element_int8>(rhs));
        case TrackerType::TrackerUInt8:
            return tracker_element::safe_cast_as<tracker_element_uint8>(lhs)->less_than(*tracker_element::safe_cast_as<tracker_element_uint8>(rhs));
        case TrackerType::TrackerInt16:
            return tracker_element::safe_cast_as<tracker_element_int16>(lhs)->less_than(*tracker_element::safe_cast_as<tracker_element_int16>(rhs));
        case TrackerType::TrackerUInt16:
            return tracker_element::safe_cast_as<tracker_element_uint16>(lhs)->less_than(*tracker_element::safe_cast_as<tracker_element_uint16>(rhs));
        case TrackerType::TrackerInt32:
            return tracker_element::safe_cast_as<tracker_element_int32>(lhs)->less_than(*tracker_element::safe_cast_as<tracker_element_int32>(rhs));
        case TrackerType::TrackerUInt32:
            return tracker_element::safe_cast_as<tracker_element_uint32>(lhs)->less_than(*tracker_element::safe_cast_as<tracker_element_uint32>(rhs));
        case TrackerType::TrackerInt64:
            return tracker_element::safe_cast_as<tracker_element_int64>(lhs)->less_than(*tracker_element::safe_cast_as<tracker_element_int64>(rhs));
        case TrackerType::TrackerUInt64:
            return tracker_element::safe_cast_as<tracker_element_uint64>(lhs)->less_than(*tracker_element::safe_cast_as<tracker_element_uint64>(rhs));
        case TrackerType::TrackerFloat:
            return tracker_element::safe_cast_as<tracker_element_float>(lhs)->less_than(*tracker_element::safe_cast_as<tracker_element_float>(rhs));
        case TrackerType::TrackerDouble:
            return tracker_element::safe_cast_as<tracker_element_double>(lhs)->less_than(*tracker_element::safe_cast_as<tracker_element_double>(rhs));
        case TrackerType::TrackerMac:
            return tracker_element::safe_cast_as<tracker_element_mac_addr>(lhs)->less_than(*tracker_element::safe_cast_as<tracker_element_mac_addr>(rhs));
        case TrackerType::TrackerUuid:
            return tracker_element::safe_cast_as<tracker_element_uuid>(lhs)->less_than(*tracker_element::safe_cast_as<tracker_element_uuid>(rhs));
        case TrackerType::TrackerByteArray:
            return tracker_element::safe_cast_as<tracker_element_byte_array>(lhs)->less_than(*tracker_element::safe_cast_as<tracker_element_byte_array>(rhs));
        case TrackerType::TrackerKey:
        case TrackerType::TrackerVector:
        case TrackerType::TrackerMap:
        case TrackerType::TrackerIntMap:
        case TrackerType::TrackerMacMap:
        case TrackerType::TrackerStringMap:
        case TrackerType::TrackerDoubleMap:
        case TrackerType::TrackerKeyMap:
        case TrackerType::TrackerVectorDouble:
        case TrackerType::TrackerDoubleMapDouble:
        case TrackerType::TrackerVectorString:
        case TrackerType::TrackerHashkeyMap:
            throw std::runtime_error(fmt::format("Attempted to compare a complex field type, {}",
                        lhs->get_type_as_string()));
    }

    return false;
}

bool FastSorttracker_elementLess(const std::shared_ptr<tracker_element> lhs, 
        const std::shared_ptr<tracker_element> rhs) noexcept {

    switch (lhs->get_type()) {
        case TrackerType::TrackerString:
            return std::static_pointer_cast<tracker_element_string>(lhs)->less_than(*std::static_pointer_cast<tracker_element_string>(rhs));
        case TrackerType::TrackerInt8:
            return std::static_pointer_cast<tracker_element_int8>(lhs)->less_than(*std::static_pointer_cast<tracker_element_int8>(rhs));
        case TrackerType::TrackerUInt8:
            return std::static_pointer_cast<tracker_element_uint8>(lhs)->less_than(*std::static_pointer_cast<tracker_element_uint8>(rhs));
        case TrackerType::TrackerInt16:
            return std::static_pointer_cast<tracker_element_int16>(lhs)->less_than(*std::static_pointer_cast<tracker_element_int16>(rhs));
        case TrackerType::TrackerUInt16:
            return std::static_pointer_cast<tracker_element_uint16>(lhs)->less_than(*std::static_pointer_cast<tracker_element_uint16>(rhs));
        case TrackerType::TrackerInt32:
            return std::static_pointer_cast<tracker_element_int32>(lhs)->less_than(*std::static_pointer_cast<tracker_element_int32>(rhs));
        case TrackerType::TrackerUInt32:
            return std::static_pointer_cast<tracker_element_uint32>(lhs)->less_than(*std::static_pointer_cast<tracker_element_uint32>(rhs));
        case TrackerType::TrackerInt64:
            return std::static_pointer_cast<tracker_element_int64>(lhs)->less_than(*std::static_pointer_cast<tracker_element_int64>(rhs));
        case TrackerType::TrackerUInt64:
            return std::static_pointer_cast<tracker_element_uint64>(lhs)->less_than(*std::static_pointer_cast<tracker_element_uint64>(rhs));
        case TrackerType::TrackerFloat:
            return std::static_pointer_cast<tracker_element_float>(lhs)->less_than(*std::static_pointer_cast<tracker_element_float>(rhs));
        case TrackerType::TrackerDouble:
            return std::static_pointer_cast<tracker_element_double>(lhs)->less_than(*std::static_pointer_cast<tracker_element_double>(rhs));
        case TrackerType::TrackerMac:
            return std::static_pointer_cast<tracker_element_mac_addr>(lhs)->less_than(*std::static_pointer_cast<tracker_element_mac_addr>(rhs));
        case TrackerType::TrackerUuid:
            return std::static_pointer_cast<tracker_element_uuid>(lhs)->less_than(*std::static_pointer_cast<tracker_element_uuid>(rhs));
        case TrackerType::TrackerByteArray:
            return std::static_pointer_cast<tracker_element_byte_array>(lhs)->less_than(*std::static_pointer_cast<tracker_element_byte_array>(rhs));
        case TrackerType::TrackerKey:
        case TrackerType::TrackerVector:
        case TrackerType::TrackerMap:
        case TrackerType::TrackerIntMap:
        case TrackerType::TrackerMacMap:
        case TrackerType::TrackerStringMap:
        case TrackerType::TrackerDoubleMap:
        case TrackerType::TrackerKeyMap:
        case TrackerType::TrackerVectorDouble:
        case TrackerType::TrackerDoubleMapDouble:
        case TrackerType::TrackerVectorString:
        case TrackerType::TrackerHashkeyMap:
            return false;
    }

    return false;
}

