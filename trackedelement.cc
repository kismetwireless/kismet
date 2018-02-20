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

ostream& operator<<(ostream& os, const TrackedDeviceKey& k) {
    ios::fmtflags fflags;

    fflags = os.flags();
    os << std::uppercase << std::setfill('0') << std::setw(2) <<
        std::hex << kis_hton64(k.spkey) << "_" << kis_hton64(k.dkey);
    os.flags(fflags);
    return os;
}

void TrackerElement::Initialize() {
    this->type = TrackerUnassigned;
    reference_count = 0;

    set_id(-1);

    // Redundant I guess
    dataunion.string_value = NULL;

    dataunion.int8_value = 0;
    dataunion.uint8_value = 0;
    dataunion.int16_value = 0;
    dataunion.uint16_value = 0;
    dataunion.int32_value = 0;
    dataunion.uint32_value = 0;
    dataunion.int64_value = 0;
    dataunion.uint64_value = 0;
    dataunion.float_value = 0.0f;
    dataunion.double_value = 0.0f;

    dataunion.mac_value = NULL;
    dataunion.uuid_value = NULL;
    dataunion.key_value = NULL;

    dataunion.submap_value = NULL;
    dataunion.subintmap_value = NULL;
    dataunion.submacmap_value = NULL;
    dataunion.substringmap_value = NULL;
    dataunion.subdoublemap_value = NULL;
    dataunion.subvector_value = NULL;
    dataunion.custom_value = NULL;
    dataunion.bytearray_value = NULL;
    dataunion.subkeymap_value = NULL;

}

TrackerElement::TrackerElement(TrackerType type) {
    Initialize();
    set_type(type);
}

TrackerElement::TrackerElement(TrackerType type, int id) {
    Initialize();

    set_id(id);
    set_type(type);
}

TrackerElement::~TrackerElement() {
    // If we contain references to other things, unlink them.  This may cause them to
    // auto-delete themselves.
    if (type == TrackerVector) {
        delete(dataunion.subvector_value);
    } else if (type == TrackerMap) {
        delete dataunion.submap_value;
    } else if (type == TrackerIntMap) {
        delete dataunion.subintmap_value;
    } else if (type == TrackerMacMap) {
        delete dataunion.submacmap_value;
    } else if (type == TrackerStringMap) {
        delete dataunion.substringmap_value;
    } else if (type == TrackerDoubleMap) {
        delete dataunion.subdoublemap_value;
    } else if (type == TrackerString) {
        delete(dataunion.string_value);
    } else if (type == TrackerMac) {
        delete(dataunion.mac_value);
    } else if (type == TrackerUuid) {
        delete dataunion.uuid_value;
    } else if (type == TrackerKey) {
        delete dataunion.key_value;
    } else if (type == TrackerByteArray) {
        delete dataunion.bytearray_value;
    }
}

void TrackerElement::set_type(TrackerType in_type) {
    if (type == in_type)
        return;

    /* Purge old types if we change type */
    if (type == TrackerVector && dataunion.subvector_value != NULL) {
        delete(dataunion.subvector_value);
        dataunion.subvector_value = NULL;
    } else if (type == TrackerMap && dataunion.submap_value != NULL) {
        delete(dataunion.submap_value);
        dataunion.submap_value = NULL;
    } else if (type == TrackerIntMap && dataunion.subintmap_value != NULL) {
        delete(dataunion.subintmap_value);
        dataunion.subintmap_value = NULL;
    } else if (type == TrackerMacMap && dataunion.submacmap_value != NULL) {
        delete(dataunion.submacmap_value);
        dataunion.submacmap_value = NULL;
    } else if (type == TrackerStringMap && dataunion.substringmap_value != NULL) {
        delete(dataunion.substringmap_value);
        dataunion.substringmap_value = NULL;
    } else if (type == TrackerDoubleMap && dataunion.subdoublemap_value != NULL) {
        delete(dataunion.subdoublemap_value);
        dataunion.subdoublemap_value = NULL;
    } else if (type == TrackerMac && dataunion.mac_value != NULL) {
        delete(dataunion.mac_value);
        dataunion.mac_value = NULL;
    } else if (type == TrackerUuid && dataunion.uuid_value != NULL) {
        delete(dataunion.uuid_value);
        dataunion.uuid_value = NULL;
    } else if (type == TrackerKey && dataunion.key_value != NULL) {
        delete(dataunion.key_value);
        dataunion.key_value = NULL;
    } else if (type == TrackerString && dataunion.string_value != NULL) {
        delete(dataunion.string_value);
        dataunion.string_value = NULL;
    } else if (type == TrackerByteArray && dataunion.bytearray_value != NULL) {
        delete(dataunion.bytearray_value);
        dataunion.bytearray_value = NULL;
        bytearray_value_len = 0;
    }

    this->type = in_type;

    if (type == TrackerVector) {
        dataunion.subvector_value = new tracked_vector();
    } else if (type == TrackerMap) {
        dataunion.submap_value = new tracked_map();
    } else if (type == TrackerIntMap) {
        dataunion.subintmap_value = new tracked_int_map();
    } else if (type == TrackerMacMap) {
        dataunion.submacmap_value = new tracked_mac_map();
    } else if (type == TrackerStringMap) {
        dataunion.substringmap_value = new tracked_string_map();
    } else if (type == TrackerDoubleMap) {
        dataunion.subdoublemap_value = new tracked_double_map();
    } else if (type == TrackerMac) {
        dataunion.mac_value = new mac_addr(0);
    } else if (type == TrackerUuid) {
        dataunion.uuid_value = new uuid();
    } else if (type == TrackerKey) {
        dataunion.key_value = new TrackedDeviceKey();
    } else if (type == TrackerString) {
        dataunion.string_value = new string();
    } else if (type == TrackerByteArray) {
        dataunion.bytearray_value = new shared_ptr<uint8_t>();
        bytearray_value_len = 0;
    }
}

TrackerElement& TrackerElement::operator++(int) {
    switch (type) {
        case TrackerInt8:
            dataunion.int8_value++;
            break;
        case TrackerUInt8:
            dataunion.uint8_value++;
            break;
        case TrackerInt16:
            dataunion.int16_value++;
            break;
        case TrackerUInt16:
            dataunion.uint16_value++;
            break;
        case TrackerInt32:
            dataunion.int32_value++;
            break;
        case TrackerUInt32:
            dataunion.uint32_value++;
            break;
        case TrackerInt64:
            dataunion.int64_value++;
            break;
        case TrackerUInt64:
            dataunion.uint64_value++;
            break;
        case TrackerFloat:
            dataunion.float_value++;
            break;
        case TrackerDouble:
            dataunion.double_value++;
            break;
        default:
            throw std::runtime_error(string("can't increment " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator--(int) {
    switch (type) {
        case TrackerInt8:
            dataunion.int8_value--;
            break;
        case TrackerUInt8:
            dataunion.uint8_value--;
            break;
        case TrackerInt16:
            dataunion.int16_value--;
            break;
        case TrackerUInt16:
            dataunion.uint16_value--;
            break;
        case TrackerInt32:
            dataunion.int32_value--;
            break;
        case TrackerUInt32:
            dataunion.uint32_value--;
            break;
        case TrackerInt64:
            dataunion.int64_value--;
            break;
        case TrackerUInt64:
            dataunion.uint64_value--;
            break;
        case TrackerFloat:
            dataunion.float_value--;
            break;
        case TrackerDouble:
            dataunion.double_value--;
            break;
        default:
            throw std::runtime_error(string("can't decrement " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator+=(const float& v) {
    switch (type) {
        case TrackerFloat:
            dataunion.float_value+= v;
            break;
        case TrackerDouble:
            dataunion.double_value+= v;
            break;
        default:
            throw std::runtime_error(string("can't += float to " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator+=(const double& v) {
    switch (type) {
        case TrackerFloat:
            dataunion.float_value+= v;
            break;
        case TrackerDouble:
            dataunion.double_value+= v;
            break;
        default:
            throw std::runtime_error(string("can't += float to " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator+=(const int& v) {
    switch (type) {
        case TrackerInt8:
            dataunion.int8_value += v;
            break;
        case TrackerUInt8:
            dataunion.uint8_value += v;
            break;
        case TrackerInt16:
            dataunion.int16_value+= v;
            break;
        case TrackerUInt16:
            dataunion.uint16_value+= v;
            break;
        case TrackerInt32:
            dataunion.int32_value+= v;
            break;
        case TrackerUInt32:
            dataunion.uint32_value+= v;
            break;
        case TrackerInt64:
            dataunion.int64_value+= v;
            break;
        case TrackerUInt64:
            dataunion.uint64_value+= v;
            break;
        case TrackerFloat:
            dataunion.float_value+= v;
            break;
        case TrackerDouble:
            dataunion.double_value+= v;
            break;
        default:
            throw std::runtime_error(string("can't += to " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator+=(const unsigned int& v) {
    switch (type) {
        case TrackerInt8:
            dataunion.int8_value += v;
            break;
        case TrackerUInt8:
            dataunion.uint8_value += v;
            break;
        case TrackerInt16:
            dataunion.int16_value+= v;
            break;
        case TrackerUInt16:
            dataunion.uint16_value+= v;
            break;
        case TrackerInt32:
            dataunion.int32_value+= v;
            break;
        case TrackerUInt32:
            dataunion.uint32_value+= v;
            break;
        case TrackerInt64:
            dataunion.int64_value+= v;
            break;
        case TrackerUInt64:
            dataunion.uint64_value+= v;
            break;
        case TrackerFloat:
            dataunion.float_value+= v;
            break;
        case TrackerDouble:
            dataunion.double_value+= v;
            break;
        default:
            throw std::runtime_error(string("can't += to " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator+=(const int64_t& i) {
    except_type_mismatch(TrackerInt64);
    dataunion.int64_value += i;
    return *this;
}

TrackerElement& TrackerElement::operator+=(const uint64_t& i) {
    except_type_mismatch(TrackerUInt64);
    dataunion.uint64_value += i;
    return *this;
}

TrackerElement& TrackerElement::operator-=(const int& v) {
    switch (type) {
        case TrackerInt8:
            dataunion.int8_value -= v;
            break;
        case TrackerUInt8:
            dataunion.uint8_value -= v;
            break;
        case TrackerInt16:
            dataunion.int16_value-= v;
            break;
        case TrackerUInt16:
            dataunion.uint16_value-= v;
            break;
        case TrackerInt32:
            dataunion.int32_value-= v;
            break;
        case TrackerUInt32:
            dataunion.uint32_value-= v;
            break;
        case TrackerInt64:
            dataunion.int64_value-= v;
            break;
        case TrackerUInt64:
            dataunion.uint64_value-= v;
            break;
        case TrackerFloat:
            dataunion.float_value-= v;
            break;
        case TrackerDouble:
            dataunion.double_value-= v;
            break;
        default:
            throw std::runtime_error(string("can't -= to " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator-=(const unsigned int& v) {
    switch (type) {
        case TrackerInt8:
            dataunion.int8_value -= v;
            break;
        case TrackerUInt8:
            dataunion.uint8_value -= v;
            break;
        case TrackerInt16:
            dataunion.int16_value-= v;
            break;
        case TrackerUInt16:
            dataunion.uint16_value-= v;
            break;
        case TrackerInt32:
            dataunion.int32_value-= v;
            break;
        case TrackerUInt32:
            dataunion.uint32_value-= v;
            break;
        case TrackerInt64:
            dataunion.int64_value-= v;
            break;
        case TrackerUInt64:
            dataunion.uint64_value-= v;
            break;
        case TrackerFloat:
            dataunion.float_value-= v;
            break;
        case TrackerDouble:
            dataunion.double_value-= v;
            break;
        default:
            throw std::runtime_error(string("can't -= to " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator-=(const float& v) {
    switch (type) {
        case TrackerFloat:
            dataunion.float_value-= v;
            break;
        case TrackerDouble:
            dataunion.double_value-= v;
            break;
        default:
            throw std::runtime_error(string("can't -= float to " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator-=(const double& v) {
    switch (type) {
        case TrackerFloat:
            dataunion.float_value-= v;
            break;
        case TrackerDouble:
            dataunion.double_value-= v;
            break;
        default:
            throw std::runtime_error(string("can't -= float to " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator-=(const int64_t& i) {
    except_type_mismatch(TrackerInt64);
    dataunion.int64_value -= i;
    return *this;
}

TrackerElement& TrackerElement::operator-=(const uint64_t& i) {
    except_type_mismatch(TrackerUInt64);
    dataunion.uint64_value -= i;
    return *this;
}


TrackerElement& TrackerElement::operator|=(int8_t i) {
    except_type_mismatch(TrackerInt8);
    dataunion.int8_value |= i;
    return *this;
}

TrackerElement& TrackerElement::operator|=(uint8_t i) {
    except_type_mismatch(TrackerUInt8);
    dataunion.uint8_value |= i;
    return *this;
}

TrackerElement& TrackerElement::operator|=(int16_t i) {
    except_type_mismatch(TrackerInt16);
    dataunion.int16_value |= i;
    return *this;
}

TrackerElement& TrackerElement::operator|=(uint16_t i) {
    except_type_mismatch(TrackerUInt16);
    dataunion.uint16_value |= i;
    return *this;
}

TrackerElement& TrackerElement::operator|=(int32_t i) {
    except_type_mismatch(TrackerInt32);
    dataunion.int32_value |= i;
    return *this;
}

TrackerElement& TrackerElement::operator|=(uint32_t i) {
    except_type_mismatch(TrackerUInt32);
    dataunion.uint32_value |= i;
    return *this;
}

TrackerElement& TrackerElement::operator|=(int64_t i) {
    except_type_mismatch(TrackerInt64);
    dataunion.int64_value |= i;
    return *this;
}

TrackerElement& TrackerElement::operator|=(uint64_t i) {
    except_type_mismatch(TrackerUInt64);
    dataunion.uint64_value |= i;
    return *this;
}

TrackerElement& TrackerElement::operator&=(int8_t i) {
    except_type_mismatch(TrackerInt8);
    dataunion.int8_value &= i;
    return *this;
}

TrackerElement& TrackerElement::operator&=(uint8_t i) {
    except_type_mismatch(TrackerUInt8);
    dataunion.uint8_value &= i;
    return *this;
}

TrackerElement& TrackerElement::operator&=(int16_t i) {
    except_type_mismatch(TrackerInt16);
    dataunion.int16_value &= i;
    return *this;
}

TrackerElement& TrackerElement::operator&=(uint16_t i) {
    except_type_mismatch(TrackerUInt16);
    dataunion.uint16_value &= i;
    return *this;
}

TrackerElement& TrackerElement::operator&=(int32_t i) {
    except_type_mismatch(TrackerInt32);
    dataunion.int32_value &= i;
    return *this;
}

TrackerElement& TrackerElement::operator&=(uint32_t i) {
    except_type_mismatch(TrackerUInt32);
    dataunion.uint32_value &= i;
    return *this;
}

TrackerElement& TrackerElement::operator&=(int64_t i) {
    except_type_mismatch(TrackerInt64);
    dataunion.int64_value &= i;
    return *this;
}

TrackerElement& TrackerElement::operator&=(uint64_t i) {
    except_type_mismatch(TrackerUInt64);
    dataunion.uint64_value &= i;
    return *this;
}

TrackerElement& TrackerElement::operator^=(int8_t i) {
    except_type_mismatch(TrackerInt8);
    dataunion.int8_value ^= i;
    return *this;
}

TrackerElement& TrackerElement::operator^=(uint8_t i) {
    except_type_mismatch(TrackerUInt8);
    dataunion.uint8_value ^= i;
    return *this;
}

TrackerElement& TrackerElement::operator^=(int16_t i) {
    except_type_mismatch(TrackerInt16);
    dataunion.int16_value ^= i;
    return *this;
}

TrackerElement& TrackerElement::operator^=(uint16_t i) {
    except_type_mismatch(TrackerUInt16);
    dataunion.uint16_value ^= i;
    return *this;
}

TrackerElement& TrackerElement::operator^=(int32_t i) {
    except_type_mismatch(TrackerInt32);
    dataunion.int32_value ^= i;
    return *this;
}

TrackerElement& TrackerElement::operator^=(uint32_t i) {
    except_type_mismatch(TrackerUInt32);
    dataunion.uint32_value ^= i;
    return *this;
}

TrackerElement& TrackerElement::operator^=(int64_t i) {
    except_type_mismatch(TrackerInt64);
    dataunion.int64_value ^= i;
    return *this;
}

TrackerElement& TrackerElement::operator^=(uint64_t i) {
    except_type_mismatch(TrackerUInt64);
    dataunion.uint64_value ^= i;
    return *this;
}

TrackerElement::map_iterator TrackerElement::begin() {
    switch (type) {
        case TrackerMap:
            return dataunion.submap_value->begin();
        case TrackerIntMap:
            return dataunion.subintmap_value->begin();
        default:
            throw std::runtime_error(string("can't address " + 
                        type_to_string(type) + " as a map"));
    }
}

TrackerElement::map_iterator TrackerElement::end() {
    switch (type) {
        case TrackerMap:
            return dataunion.submap_value->end();
        case TrackerIntMap:
            return dataunion.subintmap_value->end();
        default:
            throw std::runtime_error(string("can't address " + 
                        type_to_string(type) + " as a map"));
    }
}

TrackerElement::map_iterator TrackerElement::find(int k) {
    switch (type) {
        case TrackerMap:
            return dataunion.submap_value->find(k);
        case TrackerIntMap:
            return dataunion.subintmap_value->find(k);
        default:
            throw std::runtime_error(string("can't address " + 
                        type_to_string(type) + " as a map"));
    }
}

SharedTrackerElement TrackerElement::get_macmap_value(int idx) {
    except_type_mismatch(TrackerMacMap);

    mac_map_iterator i = dataunion.submacmap_value->find(idx);

    if (i == dataunion.submacmap_value->end()) {
        return NULL;
    }

    return i->second;
}

TrackerElement::vector_iterator TrackerElement::vec_begin() {
    except_type_mismatch(TrackerVector);

    return dataunion.subvector_value->begin();
}

TrackerElement::vector_iterator TrackerElement::vec_end() {
    except_type_mismatch(TrackerVector);

    return dataunion.subvector_value->end();
}

TrackerElement::mac_map_iterator TrackerElement::mac_begin() {
    except_type_mismatch(TrackerMacMap);

    return dataunion.submacmap_value->begin();
}

TrackerElement::mac_map_iterator TrackerElement::mac_end() {
    except_type_mismatch(TrackerMacMap);

    return dataunion.submacmap_value->end();
}

TrackerElement::mac_map_iterator TrackerElement::mac_find(mac_addr k) {
    except_type_mismatch(TrackerMacMap);

    return dataunion.submacmap_value->find(k);
}

void TrackerElement::add_macmap(mac_addr i, SharedTrackerElement s) {
    except_type_mismatch(TrackerMacMap);

    (*dataunion.submacmap_value)[i] = s;
}

void TrackerElement::del_macmap(mac_addr f) {
    except_type_mismatch(TrackerMacMap);

    mac_map_iterator mi = dataunion.submacmap_value->find(f);
    if (mi != dataunion.submacmap_value->end()) {
        dataunion.submacmap_value->erase(mi);
    }
}

void TrackerElement::del_macmap(mac_map_iterator i) {
    except_type_mismatch(TrackerMacMap);

    dataunion.submacmap_value->erase(i);
}

void TrackerElement::clear_macmap() {
    except_type_mismatch(TrackerMacMap);

    dataunion.submacmap_value->clear();
}

size_t TrackerElement::size_macmap() {
    except_type_mismatch(TrackerMacMap);

    return dataunion.submacmap_value->size();
}

void TrackerElement::insert_macmap(mac_map_pair p) {
    except_type_mismatch(TrackerMacMap);

    dataunion.submacmap_value->insert(p);
}

SharedTrackerElement TrackerElement::get_stringmap_value(std::string idx) {
    except_type_mismatch(TrackerStringMap);

    string_map_iterator i = dataunion.substringmap_value->find(idx);

    if (i == dataunion.substringmap_value->end()) {
        return NULL;
    }

    return i->second;
}

TrackerElement::string_map_iterator TrackerElement::string_begin() {
    except_type_mismatch(TrackerStringMap);

    return dataunion.substringmap_value->begin();
}

TrackerElement::string_map_iterator TrackerElement::string_end() {
    except_type_mismatch(TrackerStringMap);

    return dataunion.substringmap_value->end();
}

TrackerElement::string_map_iterator TrackerElement::string_find(std::string k) {
    except_type_mismatch(TrackerStringMap);

    return dataunion.substringmap_value->find(k);
}

void TrackerElement::add_stringmap(std::string i, SharedTrackerElement s) {
    except_type_mismatch(TrackerStringMap);

    (*dataunion.substringmap_value)[i] = s;
}

void TrackerElement::del_stringmap(std::string f) {
    except_type_mismatch(TrackerStringMap);

    string_map_iterator mi = dataunion.substringmap_value->find(f);
    if (mi != dataunion.substringmap_value->end()) {
        dataunion.substringmap_value->erase(mi);
    }
}

void TrackerElement::del_stringmap(string_map_iterator i) {
    except_type_mismatch(TrackerStringMap);

    dataunion.substringmap_value->erase(i);
}

void TrackerElement::clear_stringmap() {
    except_type_mismatch(TrackerStringMap);

    dataunion.substringmap_value->clear();
}

size_t TrackerElement::size_stringmap() {
    except_type_mismatch(TrackerStringMap);

    return dataunion.substringmap_value->size();
}

void TrackerElement::insert_stringmap(string_map_pair p) {
    except_type_mismatch(TrackerStringMap);

    dataunion.substringmap_value->insert(p);
}

SharedTrackerElement TrackerElement::get_doublemap_value(double idx) {
    except_type_mismatch(TrackerDoubleMap);

    double_map_iterator i = dataunion.subdoublemap_value->find(idx);

    if (i == dataunion.subdoublemap_value->end()) {
        return NULL;
    }

    return i->second;
}

TrackerElement::double_map_iterator TrackerElement::double_begin() {
    except_type_mismatch(TrackerDoubleMap);

    return dataunion.subdoublemap_value->begin();
}

TrackerElement::double_map_iterator TrackerElement::double_end() {
    except_type_mismatch(TrackerDoubleMap);

    return dataunion.subdoublemap_value->end();
}

TrackerElement::double_map_iterator TrackerElement::double_find(double k) {
    except_type_mismatch(TrackerDoubleMap);

    return dataunion.subdoublemap_value->find(k);
}

void TrackerElement::add_doublemap(double i, SharedTrackerElement s) {
    except_type_mismatch(TrackerDoubleMap);

    (*dataunion.subdoublemap_value)[i] = s;
}

void TrackerElement::del_doublemap(double f) {
    except_type_mismatch(TrackerDoubleMap);

    double_map_iterator mi = dataunion.subdoublemap_value->find(f);
    if (mi != dataunion.subdoublemap_value->end()) {
        dataunion.subdoublemap_value->erase(mi);
    }
}

void TrackerElement::del_doublemap(double_map_iterator i) {
    except_type_mismatch(TrackerDoubleMap);

    dataunion.subdoublemap_value->erase(i);
}

void TrackerElement::clear_doublemap() {
    except_type_mismatch(TrackerDoubleMap);

    for (double_map_iterator i = dataunion.subdoublemap_value->begin();
            i != dataunion.subdoublemap_value->end(); ++i) {
    }

    dataunion.subdoublemap_value->clear();
}

void TrackerElement::insert_doublemap(double_map_pair p) {
    except_type_mismatch(TrackerDoubleMap);

    dataunion.subdoublemap_value->insert(p);
}

size_t TrackerElement::size_doublemap() {
    except_type_mismatch(TrackerDoubleMap);

    return dataunion.subdoublemap_value->size();
}

string TrackerElement::type_to_string(TrackerType t) {
    switch (t) {
        case TrackerString:
            return "string";
        case TrackerInt8:
            return "int8_t";
        case TrackerUInt8:
            return "uint8_t";
        case TrackerInt16:
            return "int16_t";
        case TrackerUInt16:
            return "uint16_t";
        case TrackerInt32:
            return "int32_t";
        case TrackerUInt32:
            return "uint32_t";
        case TrackerInt64:
            return "int64_t";
        case TrackerUInt64:
            return "uint64_t";
        case TrackerFloat:
            return "float";
        case TrackerDouble:
            return "double";
        case TrackerMac:
            return "mac_addr";
        case TrackerVector:
            return "vector[x]";
        case TrackerMap:
            return "map[field, x]";
        case TrackerIntMap:
            return "map[int, x]";
        case TrackerUuid:
            return "uuid";
        case TrackerKey:
            return "devicekey";
        case TrackerMacMap:
            return "map[macaddr, x]";
        case TrackerStringMap:
            return "map[string, x]";
        case TrackerDoubleMap:
            return "map[double, x]";
        case TrackerKeyMap:
            return "map[key, x]";
        case TrackerByteArray:
            return "bytearray";
        default:
            return "unknown";
    }
}

string TrackerElement::type_to_typestring(TrackerType t) {
    switch (t) {
        case TrackerString:
            return "TrackerString";
        case TrackerInt8:
            return "TrackerInt8";
        case TrackerUInt8:
            return "TrackerUInt8";
        case TrackerInt16:
            return "TrackerInt16";
        case TrackerUInt16:
            return "TrackerUInt16";
        case TrackerInt32:
            return "TrackerInt32";
        case TrackerUInt32:
            return "TrackerUInt32";
        case TrackerInt64:
            return "TrackerInt64";
        case TrackerUInt64:
            return "TrackerUInt64";
        case TrackerFloat:
            return "TrackerFloat";
        case TrackerDouble:
            return "TrackerDouble";
        case TrackerMac:
            return "TrackerMac";
        case TrackerVector:
            return "TrackerVector";
        case TrackerMap:
            return "TrackerMap";
        case TrackerIntMap:
            return "TrackerIntMap";
        case TrackerUuid:
            return "TrackerUuid";
        case TrackerKey:
            return "TrackerKey";
        case TrackerMacMap:
            return "TrackerMacMap";
        case TrackerStringMap:
            return "TrackerStringMap";
        case TrackerDoubleMap:
            return "TrackerDoubleMap";
        case TrackerByteArray:
            return "TrackerByteArray";
        case TrackerKeyMap:
            return "TrackerKeyMap";
        default:
            return "TrackerUnknown";
    }
}

TrackerType TrackerElement::typestring_to_type(std::string s) {
    if (s == "TrackerString")
        return TrackerString;
    if (s == "TrackerInt8")
        return TrackerInt8;
    if (s == "TrackerUInt8")
        return TrackerUInt8;
    if (s == "TrackerInt16")
        return TrackerInt16;
    if (s == "TrackerUInt16")
        return TrackerUInt16;
    if (s == "TrackerInt32")
        return TrackerInt32;
    if (s == "TrackerUInt32")
        return TrackerUInt32;
    if (s == "TrackerInt64")
        return TrackerInt64;
    if (s == "TrackerUInt64")
        return TrackerUInt64;
    if (s == "TrackerFloat")
        return TrackerFloat;
    if (s == "TrackerDouble")
        return TrackerDouble;
    if (s == "TrackerMac")
        return TrackerMac;
    if (s == "TrackerVector")
        return TrackerVector;
    if (s == "TrackerMap")
        return TrackerMap;
    if (s == "TrackerIntMap")
        return TrackerIntMap;
    if (s == "TrackerUuid")
        return TrackerUuid;
    if (s == "TrackerKey")
        return TrackerKey;
    if (s == "TrackerMacMap")
        return TrackerMacMap;
    if (s == "TrackerStringMap")
        return TrackerStringMap;
    if (s == "TrackerDoubleMap")
        return TrackerDoubleMap;
    if (s == "TrackerByteArray")
        return TrackerByteArray;
    if (s == "TrackerKeyMap")
        return TrackerKeyMap;

    throw std::runtime_error("Unable to interpret tracker type " + s);
}

void TrackerElement::coercive_set(std::string in_str) {
    mac_addr m;
    uuid u;
    TrackedDeviceKey k;

    switch (type) {
        case TrackerString:
            set(in_str);
            break;
        case TrackerMac:
            m = mac_addr(in_str);
            if (m.error)
                throw std::runtime_error("unable to coerce string value to mac address");
            set(m);
            break;
        case TrackerUuid:
            u = uuid(in_str);
            if (u.error)
                throw std::runtime_error("unable to coerce string value to uuid");
            set(u);
            break;
        case TrackerKey:
            k = TrackedDeviceKey(in_str);
            if (k.get_error())
                throw std::runtime_error("unable to coerce string value to key");
            set(k);
            break;
        case TrackerByteArray:
            set_bytearray(in_str);
            break;
        default:
            throw std::runtime_error("unable to coerce string value to " + 
                    type_to_string(type));
            break;
    }
}

void TrackerElement::coercive_set(double in_num) {
    switch (type) {
        case TrackerInt8:
            if (in_num < -128 || in_num > 127)
                throw std::runtime_error("unable to coerce number to int8, out of range");
            set((int8_t) in_num);
            break;
        case TrackerUInt8:
            if (in_num < 0 || in_num > 255)
                throw std::runtime_error("unable to coerce number to uint8, out of range");
            set((uint8_t) in_num);
            break;
        case TrackerInt16:
            if (in_num < -32768 || in_num > 32767)
                throw std::runtime_error("unable to coerce number to int16, out of range");
            set((int16_t) in_num);
            break;
        case TrackerUInt16:
            if (in_num < 0 || in_num > 65535)
                throw std::runtime_error("unable to coerce number to uint16, out of range");
            set((uint16_t) in_num);
            break;
        case TrackerInt32:
            if (in_num < -2147483648 || in_num > 2147483647)
                throw std::runtime_error("unable to coerce number to int32, out of range");
            set((int32_t) in_num);
            break;
        case TrackerUInt32:
            if (in_num < 0 || in_num > 4294967295)
                throw std::runtime_error("unable to coerce number to uint32, out of range");
            set((uint32_t) in_num);
            break;
        case TrackerInt64:
            // Double should fit
            set((int64_t) in_num);
            break;
        case TrackerUInt64:
            set((uint64_t) in_num);
            break;
        case TrackerFloat:
            set((float) in_num);
            break;
        case TrackerDouble:
            set((double) in_num);
            break;
        default: 
            throw std::runtime_error("unable to coerce numerical value to " + 
                    type_to_string(type));
            break;
    }
}

void TrackerElement::coercive_set(SharedTrackerElement in_elem) {
    // Extract the base type then do a coercive set
    std::string basic_string;
    double basic_num;
    bool c_string = false;

    switch (in_elem->type) {
        case TrackerInt8:
            basic_num = GetTrackerValue<int8_t>(in_elem);
            break;
        case TrackerUInt8:
            basic_num = GetTrackerValue<uint8_t>(in_elem);
            break;
        case TrackerInt16:
            basic_num = GetTrackerValue<int16_t>(in_elem);
            break;
        case TrackerUInt16:
            basic_num = GetTrackerValue<uint16_t>(in_elem);
            break;
        case TrackerInt32:
            basic_num = GetTrackerValue<int32_t>(in_elem);
            break;
        case TrackerUInt32:
            basic_num = GetTrackerValue<uint32_t>(in_elem);
            break;
        case TrackerInt64:
            basic_num = GetTrackerValue<int64_t>(in_elem);
            break;
        case TrackerFloat:
            basic_num = GetTrackerValue<float>(in_elem);
            break;
        case TrackerDouble:
            basic_num = GetTrackerValue<double>(in_elem);
            break;

        case TrackerString:
            basic_string = GetTrackerValue<std::string>(in_elem);
            c_string = true;
            break;
        case TrackerMac:
            basic_string = GetTrackerValue<mac_addr>(in_elem).Mac2String();
            c_string = true;
            break;
        case TrackerUuid:
            basic_string = GetTrackerValue<uuid>(in_elem).UUID2String();
            c_string = true;
            break;
        case TrackerKey:
            basic_string = GetTrackerValue<TrackedDeviceKey>(in_elem).as_string();
            c_string = true;
            break;

        default:
            throw std::runtime_error("could not coerce " +
                    in_elem->type_to_string(in_elem->type) + " to " + 
                    type_to_string(type));
            break;
    }

    if (c_string)
        coercive_set(basic_string);
    else
        coercive_set(basic_num);
}

void TrackerElement::add_map(int f, SharedTrackerElement s) {
    except_type_mismatch(TrackerMap);
    
    auto o = dataunion.submap_value->find(f);
    if (o != dataunion.submap_value->end())
        dataunion.submap_value->erase(o);

    dataunion.submap_value->emplace(f, s);
}

void TrackerElement::add_map(SharedTrackerElement s) {
    except_type_mismatch(TrackerMap);

    if (s == NULL)
        return;

    auto o = dataunion.submap_value->find(s->get_id());
    if (o != dataunion.submap_value->end())
        dataunion.submap_value->erase(o);

    dataunion.submap_value->emplace(s->get_id(), s);
}

void TrackerElement::del_map(int f) {
    except_type_mismatch(TrackerMap);

    map_iterator i = dataunion.submap_value->find(f);
    if (i != dataunion.submap_value->end()) {
        dataunion.submap_value->erase(i);
    }
}

void TrackerElement::del_map(SharedTrackerElement e) {
    except_type_mismatch(TrackerMap);

    if (e == NULL)
        return;

    del_map(e->get_id());
}

void TrackerElement::del_map(map_iterator i) {
    except_type_mismatch(TrackerMap);
    dataunion.submap_value->erase(i);
}

void TrackerElement::insert_map(tracked_pair p) {
    except_type_mismatch(TrackerMap);

    dataunion.submap_value->insert(p);
}

void TrackerElement::clear_map() {
    except_type_mismatch(TrackerMap);
    
    dataunion.submap_value->clear();
}

size_t TrackerElement::size_map() {
    except_type_mismatch(TrackerMap);

    return dataunion.submap_value->size();
}

SharedTrackerElement TrackerElement::get_intmap_value(int idx) {
    except_type_mismatch(TrackerIntMap);

    int_map_iterator i = dataunion.subintmap_value->find(idx);

    if (i == dataunion.submap_value->end()) {
        return NULL;
    }

    return i->second;
}

TrackerElement::int_map_iterator TrackerElement::int_begin() {
    except_type_mismatch(TrackerIntMap);

    return dataunion.subintmap_value->begin();
}

TrackerElement::int_map_iterator TrackerElement::int_end() {
    except_type_mismatch(TrackerIntMap);

    return dataunion.subintmap_value->end();
}

TrackerElement::int_map_iterator TrackerElement::int_find(int k) {
    except_type_mismatch(TrackerIntMap);

    return dataunion.subintmap_value->find(k);
}

void TrackerElement::clear_intmap() {
    except_type_mismatch(TrackerIntMap);

    dataunion.subintmap_value->clear();
}

size_t TrackerElement::size_intmap() {
    except_type_mismatch(TrackerIntMap);

    return dataunion.subintmap_value->size();
}

void TrackerElement::insert_intmap(int_map_pair p) {
    except_type_mismatch(TrackerIntMap);

    dataunion.subintmap_value->insert(p);
}

void TrackerElement::add_intmap(int i, SharedTrackerElement s) {
    except_type_mismatch(TrackerIntMap);

    (*dataunion.subintmap_value)[i] = s;
}

void TrackerElement::del_intmap(int i) {
    except_type_mismatch(TrackerIntMap);

    int_map_iterator itr = dataunion.subintmap_value->find(i);
    if (itr != dataunion.subintmap_value->end()) {
        dataunion.subintmap_value->erase(i);
    }
}

void TrackerElement::del_intmap(int_map_iterator i) {
    except_type_mismatch(TrackerIntMap);

    dataunion.subintmap_value->erase(i);
}

void TrackerElement::add_vector(SharedTrackerElement s) {
    except_type_mismatch(TrackerVector);

    dataunion.subvector_value->push_back(s);
}

void TrackerElement::del_vector(unsigned int p) {
    except_type_mismatch(TrackerVector);

    if (p >= dataunion.subvector_value->size()) {
        std::string w = "del_vector out of range (" + IntToString(p) + ", vector " + 
            IntToString(dataunion.submap_value->size()) + ")";
        throw std::runtime_error(w);
    }

    vector_iterator i = dataunion.subvector_value->begin() + p;
    dataunion.subvector_value->erase(i);

}

void TrackerElement::del_vector(vector_iterator i) {
    except_type_mismatch(TrackerVector);

    dataunion.subvector_value->erase(i);
}

void TrackerElement::clear_vector() {
    except_type_mismatch(TrackerVector);

    dataunion.subvector_value->clear();
}

size_t TrackerElement::size_vector() {
    except_type_mismatch(TrackerVector);

    return dataunion.subvector_value->size();
}

void TrackerElement::set_bytearray(uint8_t *d, size_t len) {
    except_type_mismatch(TrackerByteArray);

    dataunion.bytearray_value->reset(new uint8_t[len], std::default_delete<uint8_t[]>());
    memcpy(dataunion.bytearray_value->get(), d, len);
    bytearray_value_len = len;
}

void TrackerElement::set_bytearray(shared_ptr<uint8_t> d, size_t len) {
    except_type_mismatch(TrackerByteArray);

    *(dataunion.bytearray_value) = d;
    bytearray_value_len = len;
}

void TrackerElement::set_bytearray(std::string s) {
    set_bytearray((uint8_t *) s.data(), s.length());
}

size_t TrackerElement::get_bytearray_size() {
    except_type_mismatch(TrackerByteArray);

    return bytearray_value_len;
}

std::shared_ptr<uint8_t> TrackerElement::get_bytearray() {
    except_type_mismatch(TrackerByteArray);

    return *(dataunion.bytearray_value);
}

std::string TrackerElement::get_bytearray_str() {
    except_type_mismatch(TrackerByteArray);

    uint8_t *ba = dataunion.bytearray_value->get();

    return std::string((const char *) ba, bytearray_value_len);
}

size_t TrackerElement::size() {
    switch (type) {
        case TrackerVector:
            return dataunion.subvector_value->size();
        case TrackerMap:
            return dataunion.submap_value->size();
        case TrackerIntMap:
            return dataunion.subintmap_value->size();
        case TrackerMacMap:
            return dataunion.submacmap_value->size();
        case TrackerStringMap:
            return dataunion.substringmap_value->size();
        case TrackerDoubleMap:
            return dataunion.subdoublemap_value->size();
        default:
            throw std::runtime_error(string("can't get size of a " + type_to_string(type)));
    }
}

template<> std::string GetTrackerValue(SharedTrackerElement e) {
    return e->get_string();
}

template<> int8_t GetTrackerValue(SharedTrackerElement e) {
    return e->get_int8();
}

template<> uint8_t GetTrackerValue(SharedTrackerElement e) {
    return e->get_uint8();
}

template<> int16_t GetTrackerValue(SharedTrackerElement e) {
    return e->get_int16();
}

template<> uint16_t GetTrackerValue(SharedTrackerElement e) {
    return e->get_uint16();
}

template<> int32_t GetTrackerValue(SharedTrackerElement e) {
    return e->get_int32();
}

template<> uint32_t GetTrackerValue(SharedTrackerElement e) {
    return e->get_uint32();
}

template<> int64_t GetTrackerValue(SharedTrackerElement e) {
    return e->get_int64();
}

template<> uint64_t GetTrackerValue(SharedTrackerElement e) {
    return e->get_uint64();
}

template<> float GetTrackerValue(SharedTrackerElement e) {
    return e->get_float();
}

template<> double GetTrackerValue(SharedTrackerElement e) {
    return e->get_double();
}

template<> mac_addr GetTrackerValue(SharedTrackerElement e) {
    return e->get_mac();
}

template<> TrackerElement::tracked_map *GetTrackerValue(SharedTrackerElement e) {
    return e->get_map();
}

template<> TrackerElement::tracked_vector 
    *GetTrackerValue(SharedTrackerElement e) {
    return e->get_vector();
}

template<> uuid GetTrackerValue(SharedTrackerElement e) {
    return e->get_uuid();
}

template<> TrackedDeviceKey GetTrackerValue(SharedTrackerElement e) {
    return e->get_key();
}

bool operator==(TrackerElement &te1, int8_t i) {
    return te1.get_int8() == i;
}

bool operator==(TrackerElement &te1, uint8_t i) {
    return te1.get_uint8() == i;
}

bool operator==(TrackerElement &te1, int16_t i) {
    return te1.get_int16() == i;
}

bool operator==(TrackerElement &te1, uint16_t i) {
    return te1.get_uint16() == i;
}

bool operator==(TrackerElement &te1, int32_t i) {
    return te1.get_int32() == i;
}

bool operator==(TrackerElement &te1, uint32_t i) {
    return te1.get_uint32() == i;
}

bool operator==(TrackerElement &te1, int64_t i) {
    return te1.get_int64() == i;
}

bool operator==(TrackerElement &te1, uint64_t i) {
    return te1.get_uint64() == i;
}

bool operator==(TrackerElement &te1, float f) {
    return te1.get_float() == f;
}

bool operator==(TrackerElement &te1, double d) {
    return te1.get_double() == d;
}

bool operator==(TrackerElement &te1, mac_addr m) {
    return te1.get_mac() == m;
}

bool operator==(TrackerElement &te1, uuid u) {
    return te1.get_uuid() == u;
}


bool operator<(TrackerElement &te1, int8_t i) {
    return te1.get_int8() < i;
}

bool operator<(TrackerElement &te1, uint8_t i) {
    return te1.get_uint8() < i;
}

bool operator<(TrackerElement &te1, int16_t i) {
    return te1.get_int16() < i;
}

bool operator<(TrackerElement &te1, uint16_t i) {
    return te1.get_uint16() < i;
}

bool operator<(TrackerElement &te1, int32_t i) {
    return te1.get_int32() < i;
}

bool operator<(TrackerElement &te1, uint32_t i) {
    return te1.get_uint32() < i;
}

bool operator<(TrackerElement &te1, int64_t i) {
    return te1.get_int64() < i;
}

bool operator<(TrackerElement &te1, uint64_t i) {
    return te1.get_uint64() < i;
}

bool operator<(TrackerElement &te1, float f) {
    return te1.get_float() < f;
}

bool operator<(TrackerElement &te1, double d) {
    return te1.get_double() < d;
}

bool operator<(TrackerElement &te1, mac_addr m) {
    return te1.get_mac() < m;
}

bool operator<(TrackerElement &te1, uuid u) {
    return te1.get_uuid() < u;
}

bool operator<(TrackerElement &te1, TrackerElement &te2) {
    if (te1.get_type() != te2.get_type())
        return false;

    switch (te1.get_type()) {
        case TrackerInt8:
            return te1.get_int8() < te2.get_int8();
            break;
        case TrackerUInt8:
            return te1.get_uint8() < te2.get_uint8();
            break;
        case TrackerInt16:
            return te1.get_int16() < te2.get_int16();
            break;
        case TrackerUInt16:
            return te1.get_uint16() < te2.get_uint16();
            break;
        case TrackerInt32:
            return te1.get_int32() < te2.get_int32();
            break;
        case TrackerUInt32:
            return te1.get_uint32() < te2.get_uint32();
            break;
        case TrackerInt64:
            return te1.get_int64() < te2.get_int64();
            break;
        case TrackerUInt64:
            return te1.get_uint64() < te2.get_uint64();
            break;
        case TrackerFloat:
            return te1.get_float() < te2.get_float();
            break;
        case TrackerDouble:
            return te1.get_double() < te2.get_double();
            break;
        case TrackerString:
            return doj::alphanum_comp(te1.get_string(), te2.get_string()) < 0;
        case TrackerMac:
            return te1.get_mac() < te2.get_mac();
        default:
            return false;
    }
}

bool operator<(SharedTrackerElement te1, SharedTrackerElement te2) {
    if (te1 == NULL)
        return false;

    if (te2 == NULL)
        return true;

    if (te1->get_type() != te2->get_type())
        return false;

    switch (te1->get_type()) {
        case TrackerInt8:
            return te1->get_int8() < te2->get_int8();
            break;
        case TrackerUInt8:
            return te1->get_uint8() < te2->get_uint8();
            break;
        case TrackerInt16:
            return te1->get_int16() < te2->get_int16();
            break;
        case TrackerUInt16:
            return te1->get_uint16() < te2->get_uint16();
            break;
        case TrackerInt32:
            return te1->get_int32() < te2->get_int32();
            break;
        case TrackerUInt32:
            return te1->get_uint32() < te2->get_uint32();
            break;
        case TrackerInt64:
            return te1->get_int64() < te2->get_int64();
            break;
        case TrackerUInt64:
            return te1->get_uint64() < te2->get_uint64();
            break;
        case TrackerFloat:
            return te1->get_float() < te2->get_float();
            break;
        case TrackerDouble:
            return te1->get_double() < te2->get_double();
            break;
        case TrackerString:
            return doj::alphanum_comp(te1->get_string(), te2->get_string()) < 0;
        case TrackerMac:
            return te1->get_mac() < te2->get_mac();
        default:
            return false;
    }
}


bool operator>(TrackerElement &te1, int8_t i) {
    return te1.get_int8() > i;
}

bool operator>(TrackerElement &te1, uint8_t i) {
    return te1.get_uint8() > i;
}

bool operator>(TrackerElement &te1, int16_t i) {
    return te1.get_int16() > i;
}

bool operator>(TrackerElement &te1, uint16_t i) {
    return te1.get_uint16() > i;
}

bool operator>(TrackerElement &te1, int32_t i) {
    return te1.get_int32() > i;
}

bool operator>(TrackerElement &te1, uint32_t i) {
    return te1.get_uint32() > i;
}

bool operator>(TrackerElement &te1, int64_t i) {
    return te1.get_int64() > i;
}

bool operator>(TrackerElement &te1, uint64_t i) {
    return te1.get_uint64() > i;
}

bool operator>(TrackerElement &te1, float f) {
    return te1.get_float() > f;
}

bool operator>(TrackerElement &te1, double d) {
    return te1.get_double() > d;
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
    return shared_ptr<TrackerElement>(new tracker_component(globalreg, get_id()));
}

string tracker_component::get_name() {
    return globalreg->entrytracker->GetFieldName(get_id());
}

string tracker_component::get_name(int in_id) {
    return globalreg->entrytracker->GetFieldName(in_id);
}

int tracker_component::RegisterField(std::string in_name, TrackerType in_type, 
        std::string in_desc, SharedTrackerElement *in_dest) {
    int id = entrytracker->RegisterField(in_name, in_type, in_desc);

    registered_field *rf = new registered_field(id, in_dest);

    registered_fields.push_back(rf);

    return id;
}

int tracker_component::RegisterField(std::string in_name, TrackerType in_type, 
        std::string in_desc) {
    int id = entrytracker->RegisterField(in_name, in_type, in_desc);

    return id;
}

int tracker_component::RegisterField(std::string in_name, SharedTrackerElement in_builder, 
        std::string in_desc, SharedTrackerElement *in_dest) {
    int id = entrytracker->RegisterField(in_name, in_builder, in_desc);

    registered_field *rf = new registered_field(id, in_dest);

    registered_fields.push_back(rf);

    return id;
} 

int tracker_component::RegisterComplexField(std::string in_name, 
        SharedTrackerElement in_builder, std::string in_desc) {
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

SharedTrackerElement tracker_component::get_child_path(std::string in_path) {
    std::vector<std::string> tok = StrTokenize(in_path, "/");
    return get_child_path(tok);
}

SharedTrackerElement 
    tracker_component::get_child_path(std::vector<string> in_path) {
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

void TrackerElementSerializer::pre_serialize_path(SharedElementSummary in_summary) {

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

void TrackerElementSerializer::post_serialize_path(SharedElementSummary in_summary) {

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

TrackerElementSummary::TrackerElementSummary(SharedElementSummary in_c) {
    parent_element = in_c->parent_element;
    resolved_path = in_c->resolved_path;
    rename = in_c->rename;
}

TrackerElementSummary::TrackerElementSummary(std::string in_path, std::string in_rename,
        std::shared_ptr<EntryTracker> entrytracker) {
    parse_path(StrTokenize(in_path, "/"), in_rename, entrytracker);
}

TrackerElementSummary::TrackerElementSummary(std::vector<std::string> in_path,
        std::string in_rename, std::shared_ptr<EntryTracker> entrytracker) {
    parse_path(in_path, in_rename, entrytracker);
}

TrackerElementSummary::TrackerElementSummary(std::string in_path, 
        std::shared_ptr<EntryTracker> entrytracker) {
    parse_path(StrTokenize(in_path, "/"), "", entrytracker);
}

TrackerElementSummary::TrackerElementSummary(std::vector<std::string> in_path, 
        std::shared_ptr<EntryTracker> entrytracker) {
    parse_path(in_path, "", entrytracker);
}

TrackerElementSummary::TrackerElementSummary(std::vector<int> in_path, std::string in_rename) {
    resolved_path = in_path;
    rename = in_rename;
}

TrackerElementSummary::TrackerElementSummary(std::vector<int> in_path) {
    resolved_path = in_path;
}

void TrackerElementSummary::parse_path(std::vector<std::string> in_path, std::string in_rename,
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

SharedTrackerElement GetTrackerElementPath(std::string in_path, 
        SharedTrackerElement elem, std::shared_ptr<EntryTracker> entrytracker) {
    return GetTrackerElementPath(StrTokenize(in_path, "/"), elem, entrytracker);
}

SharedTrackerElement GetTrackerElementPath(std::vector<std::string> in_path, 
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

SharedTrackerElement GetTrackerElementPath(std::vector<int> in_path, 
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

std::vector<SharedTrackerElement> GetTrackerElementMultiPath(std::string in_path, 
        SharedTrackerElement elem, std::shared_ptr<EntryTracker> entrytracker) {
    return GetTrackerElementMultiPath(StrTokenize(in_path, "/"), elem, entrytracker);
}

std::vector<SharedTrackerElement> GetTrackerElementMultiPath(std::vector<std::string> in_path, 
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

std::vector<SharedTrackerElement> GetTrackerElementMultiPath(std::vector<int> in_path, 
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
                    vector<SharedTrackerElement> subret =
                        GetTrackerElementMultiPath(sub_path, i->second);

                    ret.insert(ret.end(), subret.begin(), subret.end());
                }

                complex_fulfilled = true;
                break;
            } else if (type == TrackerMacMap) {
                std::vector<int> sub_path(std::next(x, 1), in_path.end());

                TrackerElementMacMap cn(next_elem);

                for (auto i = cn.begin(); i != cn.end(); ++i) {
                    vector<SharedTrackerElement> subret =
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
        SharedTrackerElement in, std::vector<SharedElementSummary> in_summarization, 
        SharedTrackerElement &ret_elem, 
        TrackerElementSerializer::rename_map &rename_map) {

    // Poke the pre-serialization function to update anything that needs updating before
    // we create the new meta-object
    in->pre_serialize();

    unsigned int fn = 0;
    ret_elem.reset(new TrackerElement(TrackerMap));

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

            f = SharedTrackerElement(new TrackerElement(TrackerUInt8));
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
            SharedElementSummary sum(new TrackerElementSummary(*si));
            sum->parent_element = in;
            rename_map[f] = sum;
        }

        ret_elem->add_map(f);
    }

    in->post_serialize();
}

