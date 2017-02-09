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

    dataunion.submap_value = NULL;
    dataunion.subintmap_value = NULL;
    dataunion.submacmap_value = NULL;
    dataunion.substringmap_value = NULL;
    dataunion.subdoublemap_value = NULL;
    dataunion.subvector_value = NULL;
    dataunion.custom_value = NULL;
    dataunion.bytearray_value = NULL;

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

shared_ptr<TrackerElement> TrackerElement::get_macmap_value(int idx) {
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

void TrackerElement::add_macmap(mac_addr i, shared_ptr<TrackerElement> s) {
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

shared_ptr<TrackerElement> TrackerElement::get_stringmap_value(string idx) {
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

TrackerElement::string_map_iterator TrackerElement::string_find(string k) {
    except_type_mismatch(TrackerStringMap);

    return dataunion.substringmap_value->find(k);
}

void TrackerElement::add_stringmap(string i, shared_ptr<TrackerElement> s) {
    except_type_mismatch(TrackerStringMap);

    (*dataunion.substringmap_value)[i] = s;
}

void TrackerElement::del_stringmap(string f) {
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

shared_ptr<TrackerElement> TrackerElement::get_doublemap_value(double idx) {
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

void TrackerElement::add_doublemap(double i, shared_ptr<TrackerElement> s) {
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
        case TrackerMacMap:
            return "map[macaddr, x]";
        case TrackerStringMap:
            return "map[string, x]";
        case TrackerDoubleMap:
            return "map[double, x]";
        case TrackerByteArray:
            return "bytearray";
        default:
            return "unknown";
    }
}

void TrackerElement::add_map(int f, shared_ptr<TrackerElement> s) {
    except_type_mismatch(TrackerMap);

    (*dataunion.submap_value)[f] = s;
}

void TrackerElement::add_map(shared_ptr<TrackerElement> s) {
    except_type_mismatch(TrackerMap);

    (*dataunion.submap_value)[s->get_id()] = s;
}

void TrackerElement::del_map(int f) {
    except_type_mismatch(TrackerMap);

    map_iterator i = dataunion.submap_value->find(f);
    if (i != dataunion.submap_value->end()) {
        dataunion.submap_value->erase(i);
    }
}

void TrackerElement::del_map(shared_ptr<TrackerElement> e) {
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

shared_ptr<TrackerElement> TrackerElement::get_intmap_value(int idx) {
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

void TrackerElement::add_intmap(int i, shared_ptr<TrackerElement> s) {
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

void TrackerElement::add_vector(shared_ptr<TrackerElement> s) {
    except_type_mismatch(TrackerVector);

    dataunion.subvector_value->push_back(s);
}

void TrackerElement::del_vector(unsigned int p) {
    except_type_mismatch(TrackerVector);

    if (p > dataunion.subvector_value->size()) {
        string w = "del_vector out of range (" + IntToString(p) + ", vector " + 
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

size_t TrackerElement::get_bytearray_size() {
    except_type_mismatch(TrackerByteArray);

    return bytearray_value_len;
}

shared_ptr<uint8_t> TrackerElement::get_bytearray() {
    except_type_mismatch(TrackerByteArray);

    return *(dataunion.bytearray_value);
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

template<> string GetTrackerValue(shared_ptr<TrackerElement> e) {
    return e->get_string();
}

template<> int8_t GetTrackerValue(shared_ptr<TrackerElement> e) {
    return e->get_int8();
}

template<> uint8_t GetTrackerValue(shared_ptr<TrackerElement> e) {
    return e->get_uint8();
}

template<> int16_t GetTrackerValue(shared_ptr<TrackerElement> e) {
    return e->get_int16();
}

template<> uint16_t GetTrackerValue(shared_ptr<TrackerElement> e) {
    return e->get_uint16();
}

template<> int32_t GetTrackerValue(shared_ptr<TrackerElement> e) {
    return e->get_int32();
}

template<> uint32_t GetTrackerValue(shared_ptr<TrackerElement> e) {
    return e->get_uint32();
}

template<> int64_t GetTrackerValue(shared_ptr<TrackerElement> e) {
    return e->get_int64();
}

template<> uint64_t GetTrackerValue(shared_ptr<TrackerElement> e) {
    return e->get_uint64();
}

template<> float GetTrackerValue(shared_ptr<TrackerElement> e) {
    return e->get_float();
}

template<> double GetTrackerValue(shared_ptr<TrackerElement> e) {
    return e->get_double();
}

template<> mac_addr GetTrackerValue(shared_ptr<TrackerElement> e) {
    return e->get_mac();
}

template<> TrackerElement::tracked_map *GetTrackerValue(shared_ptr<TrackerElement> e) {
    return e->get_map();
}

template<> TrackerElement::tracked_vector 
    *GetTrackerValue(shared_ptr<TrackerElement> e) {
    return e->get_vector();
}

template<> uuid GetTrackerValue(shared_ptr<TrackerElement> e) {
    return e->get_uuid();
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
    tracker = in_globalreg->entrytracker;

    set_type(TrackerMap);
    set_id(in_id);
}

tracker_component::tracker_component(GlobalRegistry *in_globalreg, int in_id, 
        shared_ptr<TrackerElement> e __attribute__((unused))) {

    globalreg = in_globalreg;
    tracker = in_globalreg->entrytracker;

    set_type(TrackerMap);
    set_id(in_id);
}

tracker_component::~tracker_component() { 
    for (unsigned int i = 0; i < registered_fields.size(); i++) {
        delete registered_fields[i];
    }
}

shared_ptr<TrackerElement> tracker_component::clone_type() {
    return shared_ptr<TrackerElement>(new tracker_component(globalreg, get_id()));
}

string tracker_component::get_name() {
    return globalreg->entrytracker->GetFieldName(get_id());
}

string tracker_component::get_name(int in_id) {
    return globalreg->entrytracker->GetFieldName(in_id);
}

int tracker_component::RegisterField(string in_name, TrackerType in_type, 
        string in_desc, shared_ptr<TrackerElement> *in_dest) {
    int id = tracker->RegisterField(in_name, in_type, in_desc);

    registered_field *rf = new registered_field(id, in_dest);

    registered_fields.push_back(rf);

    return id;
}

int tracker_component::RegisterField(string in_name, TrackerType in_type, 
        string in_desc) {
    int id = tracker->RegisterField(in_name, in_type, in_desc);

    return id;
}

int tracker_component::RegisterField(string in_name, 
        shared_ptr<TrackerElement> in_builder, 
        string in_desc, shared_ptr<TrackerElement> *in_dest) {
    int id = tracker->RegisterField(in_name, in_builder, in_desc);

    registered_field *rf = new registered_field(id, in_dest);

    registered_fields.push_back(rf);

    return id;
} 

int tracker_component::RegisterComplexField(string in_name, 
        shared_ptr<TrackerElement> in_builder, 
        string in_desc) {
    int id = tracker->RegisterField(in_name, in_builder, in_desc);
    return id;
}

void tracker_component::reserve_fields(shared_ptr<TrackerElement> e) {
    for (unsigned int i = 0; i < registered_fields.size(); i++) {
        registered_field *rf = registered_fields[i];

        if (rf->assign != NULL) {
            *(rf->assign) = import_or_new(e, rf->id);
        } else {
        }
    }
}

shared_ptr<TrackerElement> 
    tracker_component::import_or_new(shared_ptr<TrackerElement> e, int i) {

    shared_ptr<TrackerElement> r;

    // Find the value in the importer element
    if (e != NULL) {
        r = e->get_map_value(i);

        if (r != NULL) {
            // printf("debug - found id %d %s, importing\n", i, globalreg->entrytracker->GetFieldName(i).c_str());
            // Added directly as a trackedelement of the right type and id
            add_map(r);
            // Return existing item
            return r;
        }
    }

    r = tracker->GetTrackedInstance(i);
    add_map(r);

    return r;
}

shared_ptr<TrackerElement> tracker_component::get_child_path(string in_path) {
    vector<string> tok = StrTokenize(in_path, "/");
    return get_child_path(tok);
}

shared_ptr<TrackerElement> 
    tracker_component::get_child_path(std::vector<string> in_path) {
    if (in_path.size() < 1)
        return NULL;

    shared_ptr<TrackerElement> next_elem = NULL;

    for (unsigned int x = 0; x < in_path.size(); x++) {
        // Skip empty path element
        if (in_path[x].length() == 0)
            continue;

        int id = globalreg->entrytracker->GetFieldId(in_path[x]);

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

TrackerElementSummary::TrackerElementSummary(string in_path, string in_rename,
        shared_ptr<EntryTracker> entrytracker) {
    parse_path(StrTokenize(in_path, "/"), in_rename, entrytracker);
}

TrackerElementSummary::TrackerElementSummary(vector<string> in_path,
        string in_rename, shared_ptr<EntryTracker> entrytracker) {
    parse_path(in_path, in_rename, entrytracker);
}

TrackerElementSummary::TrackerElementSummary(string in_path, 
        shared_ptr<EntryTracker> entrytracker) {
    parse_path(StrTokenize(in_path, "/"), "", entrytracker);
}

TrackerElementSummary::TrackerElementSummary(vector<string> in_path, 
        shared_ptr<EntryTracker> entrytracker) {
    parse_path(in_path, "", entrytracker);
}

TrackerElementSummary::TrackerElementSummary(vector<int> in_path, string in_rename) {
    resolved_path = in_path;
    rename = in_rename;
}

TrackerElementSummary::TrackerElementSummary(vector<int> in_path) {
    resolved_path = in_path;
}

void TrackerElementSummary::parse_path(vector<string> in_path, string in_rename,
        shared_ptr<EntryTracker> entrytracker) {

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

shared_ptr<TrackerElement> GetTrackerElementPath(string in_path, 
        SharedTrackerElement elem,
        shared_ptr<EntryTracker> entrytracker) {
    return GetTrackerElementPath(StrTokenize(in_path, "/"),
            elem, entrytracker);
}

shared_ptr<TrackerElement> GetTrackerElementPath(std::vector<string> in_path, 
        SharedTrackerElement elem,
        shared_ptr<EntryTracker> entrytracker) {

    if (in_path.size() < 1)
        return NULL;

    shared_ptr<TrackerElement> next_elem = NULL;

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

shared_ptr<TrackerElement> GetTrackerElementPath(std::vector<int> in_path, 
        SharedTrackerElement elem) {

    if (in_path.size() < 1)
        return NULL;

    shared_ptr<TrackerElement> next_elem = NULL;

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

void SummarizeTrackerElement(shared_ptr<EntryTracker> entrytracker,
        SharedTrackerElement in, 
        vector<TrackerElementSummary> in_summarization, 
        SharedTrackerElement &ret_elem, 
        TrackerElementSerializer::rename_map &rename_map) {

    unsigned int fn = 0;
    ret_elem.reset(new TrackerElement(TrackerMap));

    for (vector<TrackerElementSummary>::iterator si = in_summarization.begin();
            si != in_summarization.end(); ++si) {
        fn++;

        if (si->resolved_path.size() == 0)
            continue;

        SharedTrackerElement f =
            GetTrackerElementPath(si->resolved_path, in);

        if (f == NULL) {
            f = entrytracker->RegisterAndGetField("unknown" + IntToString(fn),
                    TrackerInt8, "unallocated field");

            f = SharedTrackerElement(new TrackerElement(TrackerUInt8));
            f->set((uint8_t) 0);
        
            if (si->rename.length() != 0) {
                f->set_local_name(si->rename);
            } else {
                // Get the last name of the field in the path, if we can...
                int lastid = si->resolved_path[si->resolved_path.size() - 1];

                if (lastid < 0)
                    f->set_local_name("unknown" + IntToString(fn));
                else
                    f->set_local_name(entrytracker->GetFieldName(lastid));
            }
        } 

        if (si->rename.length() != 0) {
            rename_map[f] = si->rename;
        }

        ret_elem->add_map(f);
    }
}

