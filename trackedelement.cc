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

TrackedDeviceKey::TrackedDeviceKey() {
    spkey = 0;
    dkey = 0;
    error = true;
}

TrackedDeviceKey::TrackedDeviceKey(const TrackedDeviceKey& k) {
    spkey = k.spkey;
    dkey = k.dkey;
    error = k.error;
}

TrackedDeviceKey::TrackedDeviceKey(uint64_t in_spkey, uint64_t in_dkey) {
    spkey = in_spkey;
    dkey = in_dkey;
    error = false;
}

TrackedDeviceKey::TrackedDeviceKey(uint32_t in_skey, uint32_t in_pkey, uint64_t in_dkey) {
    spkey = (((uint64_t) in_skey) << 32) | in_pkey;
    dkey = in_dkey;
    error = false;
}

TrackedDeviceKey::TrackedDeviceKey(uint32_t in_skey, uint32_t in_pkey, mac_addr in_device) {
    spkey = (((uint64_t) in_skey) << 32) | in_pkey;
    dkey = in_device.longmac;
    error = false;
}

TrackedDeviceKey::TrackedDeviceKey(uint64_t in_spkey, mac_addr in_device) {
    spkey = in_spkey;
    dkey = in_device.longmac;
    error = false;
}

TrackedDeviceKey::TrackedDeviceKey(std::string in_keystr) {
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

std::string TrackedDeviceKey::as_string() const {
    std::stringstream ss;
    ss << *this;
    return ss.str();
}

uint32_t TrackedDeviceKey::gen_pkey(std::string phy) {
    return Adler32Checksum(phy.c_str(), phy.length());
}

uint64_t TrackedDeviceKey::gen_spkey(uuid s_uuid, std::string phy) {
    uint64_t uuid32 = Adler32Checksum((const char *) s_uuid.uuid_block, 16);
    uint64_t phy32 = gen_pkey(phy);

    return (uuid32 << 32) | phy32;
}

bool operator <(const TrackedDeviceKey& x, const TrackedDeviceKey& y) {
    if (x.spkey == y.spkey)
        return x.dkey < y.dkey;

    return x.spkey < y.spkey;
}

bool operator ==(const TrackedDeviceKey& x, const TrackedDeviceKey& y) {
    return (x.spkey == y.spkey && x.dkey == y.dkey);
}

std::ostream& operator<<(std::ostream& os, const TrackedDeviceKey& k) {
    std::ios::fmtflags fflags;

    fflags = os.flags();
    os << std::uppercase << std::setfill('0') << std::setw(2) <<
        std::hex << kis_hton64(k.spkey) << "_" << kis_hton64(k.dkey);
    os.flags(fflags);
    return os;
}

// New

void TrackerElementString::coercive_set(const std::string& in_str) {
    value = in_str;
}

void TrackerElementString::coercive_set(double in_num) {
    value = fmt::format("{}", in_num);
}

void TrackerElementString::coercive_set(const SharedTrackerElement& e) {
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
            coercive_set(std::static_pointer_cast<TrackerElementCoreScalar>(e)->get_value());
            break;
        case TrackerType::TrackerString:
            coercive_set(std::static_pointer_cast<TrackerElementString>(e)->get_value());
            break;
        case TrackerType::TrackerUuid:
            coercive_set(std::static_pointer_cast<TrackerElementUUID>(e)->get_value().UUID2String());
            break;
        case TrackerType::TrackerMac:
            coercive_set(std::static_pointer_cast<TrackerElementMacAddr>(e)->get_value().Mac2String());
            break;
        default:
            throw std::runtime_error(fmt::format("Could not coerce {} to {}",
                        e->get_type_as_string(), get_type_as_string()));
    }
}


// Old

std::string TrackerElement::type_to_string(TrackerType t) {
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
        default:
            return "unknown";
    }
}

std::string TrackerElement::type_to_typestring(TrackerType t) {
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
        default:
            return "TrackerUnknown";
    }
}

TrackerType TrackerElement::typestring_to_type(const std::string& s) {
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

    throw std::runtime_error("Unable to interpret tracker type " + s);
}

tracker_component::tracker_component(GlobalRegistry *in_globalreg, int in_id) {
    globalreg = in_globalreg;

    entrytracker = 
        Globalreg::FetchMandatoryGlobalAs<EntryTracker>(in_globalreg, "ENTRY_TRACKER");

    set_type(TrackerMap);
    set_id(in_id);
}

tracker_component::tracker_component(GlobalRegistry *in_globalreg, int in_id, 
        SharedTrackerElement e __attribute__((unused))) {

    globalreg = in_globalreg;
    entrytracker = 
        Globalreg::FetchMandatoryGlobalAs<EntryTracker>(globalreg, "ENTRY_TRACKER");

    set_type(TrackerMap);
    set_id(in_id);
}

tracker_component::~tracker_component() { 
    for (unsigned int i = 0; i < registered_fields.size(); i++) {
        delete registered_fields[i];
    }
}

SharedTrackerElement tracker_component::clone_type() {
    return std::make_shared<tracker_component>(globalreg, get_id());
}

std::string tracker_component::get_name() {
    return globalreg->entrytracker->GetFieldName(get_id());
}

std::string tracker_component::get_name(int in_id) {
    return globalreg->entrytracker->GetFieldName(in_id);
}

int tracker_component::RegisterField(const std::string& in_name, TrackerType in_type, 
        const std::string& in_desc, SharedTrackerElement *in_dest) {
    int id = entrytracker->RegisterField(in_name, in_type, in_desc);

    registered_field *rf = new registered_field(id, in_dest);

    registered_fields.push_back(rf);

    return id;
}

int tracker_component::RegisterField(const std::string& in_name, TrackerType in_type, 
        const std::string& in_desc) {
    int id = entrytracker->RegisterField(in_name, in_type, in_desc);

    return id;
}

int tracker_component::RegisterField(const std::string& in_name, 
        const SharedTrackerElement& in_builder, 
        const std::string& in_desc, SharedTrackerElement *in_dest) {
    int id = entrytracker->RegisterField(in_name, in_builder, in_desc);

    registered_field *rf = new registered_field(id, in_dest);

    registered_fields.push_back(rf);

    return id;
} 

int tracker_component::RegisterComplexField(const std::string& in_name, 
        const SharedTrackerElement& in_builder, const std::string& in_desc) {
    int id = entrytracker->RegisterField(in_name, in_builder, in_desc);
    in_builder->set_id(id);
    return id;
}

void tracker_component::reserve_fields(SharedTrackerElement e) {
    for (unsigned int i = 0; i < registered_fields.size(); i++) {
        registered_field *rf = registered_fields[i];

        if (rf->assign != NULL) {
            *(rf->assign) = import_or_new(e, rf->id);
        } else {
        }
    }
}

SharedTrackerElement 
    tracker_component::import_or_new(SharedTrackerElement e, int i) {

    SharedTrackerElement r;

    // Find the value of any known fields in the importer element; only try
    // if the imported element is a map
    if (e != NULL && e->get_type() == TrackerMap) {
        r = e->get_map_value(i);

        if (r != NULL) {
            // Added directly as a trackedelement of the right type and id
            add_map(r);
            // Return existing item
            return r;
        }
    }

    r = entrytracker->GetTrackedInstance(i);
    add_map(r);

    return r;
}

SharedTrackerElement tracker_component::get_child_path(const std::string& in_path) {
    std::vector<std::string> tok = StrTokenize(in_path, "/");
    return get_child_path(tok);
}

SharedTrackerElement 
    tracker_component::get_child_path(const std::vector<std::string>& in_path) {
    if (in_path.size() < 1)
        return NULL;

    SharedTrackerElement next_elem = NULL;

    for (unsigned int x = 0; x < in_path.size(); x++) {
        // Skip empty path element
        if (in_path[x].length() == 0)
            continue;

        int id = entrytracker->GetFieldId(in_path[x]);

        if (id < 0) {
            return NULL;
        }

        if (next_elem == NULL)
            next_elem = get_map_value(id);
        else
            next_elem = 
                next_elem->get_map_value(id);

        if (next_elem == NULL) {
            return NULL;
        }

    }

    return next_elem;
}

void TrackerElementSerializer::pre_serialize_path(const SharedElementSummary& in_summary) {

    // Iterate through the path on this object, calling pre-serialize as
    // necessary on each object in the summary path

    SharedTrackerElement inter = in_summary->parent_element;

    if (inter == NULL)
        return;

    try {
        for (auto i = in_summary->resolved_path.begin(); 
                i != in_summary->resolved_path.end(); ++i) {
            inter = inter->get_map_value(*i);

            if (inter == NULL)
                return;

            inter->pre_serialize();
        }
    } catch (std::runtime_error c) {
        // Do nothing if we hit a map error
        fprintf(stderr, "debug - preser summary error: %s\n", c.what());
        return;
    }
}

void TrackerElementSerializer::post_serialize_path(const SharedElementSummary& in_summary) {

    // Iterate through the path on this object, calling pre-serialize as
    // necessary on each object in the summary path

    SharedTrackerElement inter = in_summary->parent_element;

    if (inter == NULL)
        return;

    try {
        for (auto i = in_summary->resolved_path.begin(); 
                i != in_summary->resolved_path.end(); ++i) {
            inter = inter->get_map_value(*i);

            if (inter == NULL)
                return;

            inter->post_serialize();
        }
    } catch (std::runtime_error c) {
        // Do nothing if we hit a map error
        fprintf(stderr, "debug - preser summary error: %s\n", c.what());
        return;
    }
}

TrackerElementSummary::TrackerElementSummary(const SharedElementSummary& in_c) {
    parent_element = in_c->parent_element;
    resolved_path = in_c->resolved_path;
    rename = in_c->rename;
}

TrackerElementSummary::TrackerElementSummary(const std::string& in_path, 
        const std::string& in_rename,
        std::shared_ptr<EntryTracker> entrytracker) {
    parse_path(StrTokenize(in_path, "/"), in_rename, entrytracker);
}

TrackerElementSummary::TrackerElementSummary(const std::vector<std::string>& in_path,
        const std::string& in_rename, std::shared_ptr<EntryTracker> entrytracker) {
    parse_path(in_path, in_rename, entrytracker);
}

TrackerElementSummary::TrackerElementSummary(const std::string& in_path, 
        std::shared_ptr<EntryTracker> entrytracker) {
    parse_path(StrTokenize(in_path, "/"), "", entrytracker);
}

TrackerElementSummary::TrackerElementSummary(const std::vector<std::string>& in_path, 
        std::shared_ptr<EntryTracker> entrytracker) {
    parse_path(in_path, "", entrytracker);
}

TrackerElementSummary::TrackerElementSummary(const std::vector<int>& in_path,
        const std::string& in_rename) {
    resolved_path = in_path;
    rename = in_rename;
}

TrackerElementSummary::TrackerElementSummary(const std::vector<int>& in_path) {
    resolved_path = in_path;
}

void TrackerElementSummary::parse_path(const std::vector<std::string>& in_path, 
        const std::string& in_rename,
        std::shared_ptr<EntryTracker> entrytracker) {

    if (in_path.size() == 0) {
        return;
    }

    bool path_full = true;

    for (unsigned int x = 0; x < in_path.size(); x++) {
        if (in_path[x].length() == 0)
            continue;

        int id = entrytracker->GetFieldId(in_path[x]);

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

SharedTrackerElement GetTrackerElementPath(const std::string& in_path, 
        SharedTrackerElement elem, std::shared_ptr<EntryTracker> entrytracker) {
    return GetTrackerElementPath(StrTokenize(in_path, "/"), elem, entrytracker);
}

SharedTrackerElement GetTrackerElementPath(const std::vector<std::string>& in_path, 
        SharedTrackerElement elem, std::shared_ptr<EntryTracker> entrytracker) {

    if (in_path.size() < 1)
        return NULL;

    SharedTrackerElement next_elem = NULL;

    for (unsigned int x = 0; x < in_path.size(); x++) {
        // Skip empty path element
        if (in_path[x].length() == 0)
            continue;

        int id = entrytracker->GetFieldId(in_path[x]);

        if (id < 0) {
            return NULL;
        }

        if (next_elem == NULL)
            next_elem = elem->get_map_value(id);
        else
            next_elem = 
                next_elem->get_map_value(id);

        if (next_elem == NULL) {
            return NULL;
        }
    }

    return next_elem;
}

SharedTrackerElement GetTrackerElementPath(const std::vector<int>& in_path, 
        SharedTrackerElement elem) {

    if (in_path.size() < 1)
        return NULL;

    if (elem == NULL)
        return NULL;

    SharedTrackerElement next_elem = NULL;

    for (unsigned int x = 0; x < in_path.size(); x++) {
        int id = in_path[x];

        if (id < 0) {
            return NULL;
        }

        if (next_elem == NULL)
            next_elem = elem->get_map_value(id);
        else
            next_elem = 
                next_elem->get_map_value(id);

        if (next_elem == NULL) {
            return NULL;
        }
    }

    return next_elem;
}

std::vector<SharedTrackerElement> GetTrackerElementMultiPath(const std::string& in_path, 
        SharedTrackerElement elem, std::shared_ptr<EntryTracker> entrytracker) {
    return GetTrackerElementMultiPath(StrTokenize(in_path, "/"), elem, entrytracker);
}

std::vector<SharedTrackerElement> GetTrackerElementMultiPath(const std::vector<std::string>& in_path, 
        SharedTrackerElement elem, std::shared_ptr<EntryTracker> entrytracker) {

    std::vector<SharedTrackerElement> ret;

    if (in_path.size() < 1)
        return ret;

    SharedTrackerElement next_elem = NULL;

    bool complex_fulfilled = false;
    for (auto x = in_path.begin(); x != in_path.end(); ++x) {
        // Skip empty path element
        if (x->length() == 0)
            continue;

        int id = entrytracker->GetFieldId(*x);

        if (id < 0) {
            return ret;
        }

        if (next_elem == NULL)
            next_elem = elem->get_map_value(id);
        else
            next_elem = 
                next_elem->get_map_value(id);

        if (next_elem == NULL) {
            return ret;
        }

        // If we're at the termination of the path, we just return the
        // object.  If we're in the middle of a path, we iterate over the 
        // contents of the container, and find the rest of the path in it
        if (x != std::next(in_path.end(), -1)) {
            int type = next_elem->get_type();

            if (type == TrackerVector) {
                std::vector<std::string> sub_path(std::next(x, 1), in_path.end());

                TrackerElementVector cn(next_elem);

                for (TrackerElementVector::iterator i = cn.begin(); i != cn.end(); ++i) {
                    std::vector<SharedTrackerElement> subret =
                        GetTrackerElementMultiPath(sub_path, *i, entrytracker);

                    ret.insert(ret.end(), subret.begin(), subret.end());
                }

                complex_fulfilled = true;
                break;
            } else if (type == TrackerIntMap) {
                std::vector<std::string> sub_path(std::next(x, 1), in_path.end());

                TrackerElementIntMap cn(next_elem);

                for (TrackerElementIntMap::iterator i = cn.begin();
                        i != cn.end(); ++i) {
                    std::vector<SharedTrackerElement> subret =
                        GetTrackerElementMultiPath(sub_path, i->second, entrytracker);

                    ret.insert(ret.end(), subret.begin(), subret.end());
                }

                complex_fulfilled = true;
                break;
            } else if (type == TrackerStringMap) {
                std::vector<std::string> sub_path(std::next(x, 1), in_path.end());

                TrackerElementStringMap cn(next_elem);

                for (auto i = cn.begin(); i != cn.end(); ++i) {
                    std::vector<SharedTrackerElement> subret =
                        GetTrackerElementMultiPath(sub_path, i->second, entrytracker);

                    ret.insert(ret.end(), subret.begin(), subret.end());
                }

                complex_fulfilled = true;
                break;
            } else if (type == TrackerMacMap) {
                std::vector<std::string> sub_path(std::next(x, 1), in_path.end());

                TrackerElementMacMap cn(next_elem);

                for (auto i = cn.begin(); i != cn.end(); ++i) {
                    std::vector<SharedTrackerElement> subret =
                        GetTrackerElementMultiPath(sub_path, i->second, entrytracker);

                    ret.insert(ret.end(), subret.begin(), subret.end());
                }

                complex_fulfilled = true;
                break;
            } else if (type == TrackerDoubleMap) {
                std::vector<std::string> sub_path(std::next(x, 1), in_path.end());

                TrackerElementDoubleMap cn(next_elem);

                for (auto i = cn.begin(); i != cn.end(); ++i) {
                    std::vector<SharedTrackerElement> subret =
                        GetTrackerElementMultiPath(sub_path, i->second, entrytracker);

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

std::vector<SharedTrackerElement> GetTrackerElementMultiPath(const std::vector<int>& in_path, 
        SharedTrackerElement elem) {

    std::vector<SharedTrackerElement> ret;

    if (in_path.size() < 1)
        return ret;

    SharedTrackerElement next_elem = NULL;

    bool complex_fulfilled = false;
    for (auto x = in_path.begin(); x != in_path.end(); ++x) {
        int id = *x;

        if (id < 0) {
            return ret;
        }

        if (next_elem == NULL)
            next_elem = elem->get_map_value(id);
        else
            next_elem = 
                next_elem->get_map_value(id);

        if (next_elem == NULL) {
            return ret;
        }

        // If we're at the termination of the path, we just return the
        // object.  If we're in the middle of a path, we iterate over the 
        // contents of the container, and find the rest of the path in it
        if (x != std::next(in_path.end(), -1)) {
            int type = next_elem->get_type();

            if (type == TrackerVector) {
                std::vector<int> sub_path(std::next(x, 1), in_path.end());

                TrackerElementVector cn(next_elem);

                for (auto i = cn.begin(); i != cn.end(); ++i) {
                    std::vector<SharedTrackerElement> subret =
                        GetTrackerElementMultiPath(sub_path, *i);

                    ret.insert(ret.end(), subret.begin(), subret.end());
                }

                complex_fulfilled = true;
                break;
            } else if (type == TrackerIntMap) {
                std::vector<int> sub_path(std::next(x, 1), in_path.end());

                TrackerElementIntMap cn(next_elem);

                for (auto i = cn.begin(); i != cn.end(); ++i) {
                    std::vector<SharedTrackerElement> subret =
                        GetTrackerElementMultiPath(sub_path, i->second);

                    ret.insert(ret.end(), subret.begin(), subret.end());
                }

                complex_fulfilled = true;
                break;
            } else if (type == TrackerStringMap) {
                std::vector<int> sub_path(std::next(x, 1), in_path.end());

                TrackerElementStringMap cn(next_elem);

                for (auto i = cn.begin(); i != cn.end(); ++i) {
                    std::vector<SharedTrackerElement> subret =
                        GetTrackerElementMultiPath(sub_path, i->second);

                    ret.insert(ret.end(), subret.begin(), subret.end());
                }

                complex_fulfilled = true;
                break;
            } else if (type == TrackerMacMap) {
                std::vector<int> sub_path(std::next(x, 1), in_path.end());

                TrackerElementMacMap cn(next_elem);

                for (auto i = cn.begin(); i != cn.end(); ++i) {
                    std::vector<SharedTrackerElement> subret =
                        GetTrackerElementMultiPath(sub_path, i->second);

                    ret.insert(ret.end(), subret.begin(), subret.end());
                }

                complex_fulfilled = true;
                break;
            } else if (type == TrackerDoubleMap) {
                std::vector<int> sub_path(std::next(x, 1), in_path.end());

                TrackerElementDoubleMap cn(next_elem);

                for (auto i = cn.begin(); i != cn.end(); ++i) {
                    std::vector<SharedTrackerElement> subret =
                        GetTrackerElementMultiPath(sub_path, i->second);

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

void SummarizeTrackerElement(std::shared_ptr<EntryTracker> entrytracker,
        const SharedTrackerElement& in, 
        const std::vector<SharedElementSummary>& in_summarization, 
        SharedTrackerElement &ret_elem, 
        TrackerElementSerializer::rename_map &rename_map) {

    // Poke the pre-serialization function to update anything that needs updating before
    // we create the new meta-object
    in->pre_serialize();

    unsigned int fn = 0;
    ret_elem = std::make_shared<TrackerElement>(TrackerMap);

    if (in_summarization.size() == 0)
        ret_elem = in;

    for (auto si = in_summarization.begin(); si != in_summarization.end(); ++si) {
        fn++;

        if ((*si)->resolved_path.size() == 0)
            continue;

        SharedTrackerElement f =
            GetTrackerElementPath((*si)->resolved_path, in);

        if (f == NULL) {
            f = entrytracker->RegisterAndGetField("unknown" + IntToString(fn),
                    TrackerInt8, "unallocated field");

            f = std::make_shared<TrackerElement>(TrackerUInt8);
            f->set((uint8_t) 0);
        
            if ((*si)->rename.length() != 0) {
                f->set_local_name((*si)->rename);
            } else {
                // Get the last name of the field in the path, if we can...
                int lastid = (*si)->resolved_path[(*si)->resolved_path.size() - 1];

                if (lastid < 0)
                    f->set_local_name("unknown" + IntToString(fn));
                else
                    f->set_local_name(entrytracker->GetFieldName(lastid));
            }
        } 

       
        // If we're renaming it or we're a path, we put the record in.  We need
        // to duplicate the summary object and make a reference to our parent
        // object so that when we serialize we can descend the path calling
        // the proper pre-serialization methods
        if ((*si)->rename.length() != 0 || (*si)->resolved_path.size() > 1) {
            auto sum = std::make_shared<TrackerElementSummary>(*si);
            sum->parent_element = in;
            rename_map[f] = sum;
        }

        ret_elem->add_map(f);
    }

    in->post_serialize();
}

