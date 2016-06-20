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

TrackerElement::TrackerElement(TrackerType type) {
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

    set_type(type);
}

TrackerElement::TrackerElement(TrackerType type, int id) {
    this->type = TrackerUnassigned;

    set_id(id);

    reference_count = 0;

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

    set_type(type);
}

TrackerElement::~TrackerElement() {
    // Blow up if we're still in use and someone free'd us
    if (reference_count != 0) {
        string w = "destroying element with non-zero reference count (" + 
            IntToString(reference_count) + ")";
        throw std::runtime_error(w);
    }

    // If we contain references to other things, unlink them.  This may cause them to
    // auto-delete themselves.
    if (type == TrackerVector) {
        for (unsigned int i = 0; i < dataunion.subvector_value->size(); i++) {
            (*dataunion.subvector_value)[i]->unlink();
        }

        delete(dataunion.subvector_value);
    } else if (type == TrackerMap) {
        map<int, TrackerElement *>::iterator i;

        for (i = dataunion.submap_value->begin(); 
                i != dataunion.submap_value->end(); ++i) {
            i->second->unlink();
        }

        delete(dataunion.submap_value);
    } else if (type == TrackerIntMap) {
        map<int, TrackerElement *>::iterator i;

        for (i = dataunion.subintmap_value->begin(); 
                i != dataunion.subintmap_value->end(); ++i) {
            i->second->unlink();
        }

        delete(dataunion.subintmap_value);
    } else if (type == TrackerMacMap) {
        map<mac_addr, TrackerElement *>::iterator i;

        for (i = dataunion.submacmap_value->begin(); 
                i != dataunion.submacmap_value->end(); ++i) {
            i->second->unlink();
        }

        delete(dataunion.submacmap_value);
    } else if (type == TrackerStringMap) {
        for (string_map_iterator i = dataunion.substringmap_value->begin(); 
                i != dataunion.substringmap_value->end(); ++i) {
            i->second->unlink();
        }

        delete(dataunion.substringmap_value);
    } else if (type == TrackerDoubleMap) {
        for (double_map_iterator i = dataunion.subdoublemap_value->begin();
                i != dataunion.subdoublemap_value->end(); ++i) {
            i->second->unlink();
        }

        delete(dataunion.subdoublemap_value);
    } else if (type == TrackerString) {
        delete(dataunion.string_value);
    } else if (type == TrackerMac) {
        delete(dataunion.mac_value);
    } else if (type == TrackerUuid) {
        delete dataunion.uuid_value;
    }
}

void TrackerElement::set_type(TrackerType in_type) {
    if (type == in_type)
        return;

    /* Purge old types if we change type */
    if (type == TrackerVector && dataunion.subvector_value != NULL) {
        for (unsigned int i = 0; i < dataunion.subvector_value->size(); i++) {
            (*dataunion.subvector_value)[i]->unlink();
        }

        delete(dataunion.subvector_value);
        dataunion.subvector_value = NULL;
    } else if (type == TrackerMap && dataunion.submap_value != NULL) {
        map<int, TrackerElement *>::iterator i;

        for (i = dataunion.submap_value->begin(); 
                i != dataunion.submap_value->end(); ++i) {
            i->second->unlink();
        }

        delete(dataunion.submap_value);
        dataunion.submap_value = NULL;
    } else if (type == TrackerIntMap && dataunion.subintmap_value != NULL) {
        map<int, TrackerElement *>::iterator i;

        for (i = dataunion.subintmap_value->begin(); 
                i != dataunion.subintmap_value->end(); ++i) {
            i->second->unlink();
        }

        delete(dataunion.subintmap_value);
        dataunion.subintmap_value = NULL;
    } else if (type == TrackerMacMap && dataunion.submacmap_value != NULL) {
        map<mac_addr, TrackerElement *>::iterator i;

        for (i = dataunion.submacmap_value->begin(); 
                i != dataunion.submacmap_value->end(); ++i) {
            i->second->unlink();
        }

        delete(dataunion.submacmap_value);
        dataunion.submacmap_value = NULL;
    } else if (type == TrackerStringMap && dataunion.substringmap_value != NULL) {
        for (string_map_iterator i = dataunion.substringmap_value->begin(); 
                i != dataunion.substringmap_value->end(); ++i) {
            i->second->unlink();
        }

        delete(dataunion.substringmap_value);
        dataunion.substringmap_value = NULL;
    } else if (type == TrackerDoubleMap && dataunion.subdoublemap_value != NULL) {
        for (double_map_iterator i = dataunion.subdoublemap_value->begin();
                i != dataunion.subdoublemap_value->end(); ++i) {
            i->second->unlink();
        }

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
    }
    

    this->type = in_type;

    if (type == TrackerVector) {
        dataunion.subvector_value = new vector<TrackerElement *>();
    } else if (type == TrackerMap) {
        dataunion.submap_value = new map<int, TrackerElement *>();
    } else if (type == TrackerIntMap) {
        dataunion.subintmap_value = new map<int, TrackerElement *>();
    } else if (type == TrackerMacMap) {
        dataunion.submacmap_value = new map<mac_addr, TrackerElement *>();
    } else if (type == TrackerStringMap) {
        dataunion.substringmap_value = new map<string, TrackerElement *>();
    } else if (type == TrackerDoubleMap) {
        dataunion.subdoublemap_value = new map<double, TrackerElement *>();
    } else if (type == TrackerMac) {
        dataunion.mac_value = new mac_addr(0);
    } else if (type == TrackerUuid) {
        dataunion.uuid_value = new uuid();
    } else if (type == TrackerString) {
        dataunion.string_value = new string();
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

TrackerElement *TrackerElement::operator[](int i) {
    string w;
    map<int, TrackerElement *>::iterator itr;

    switch (type) {
        case TrackerVector:
            if (i >= 0 && (unsigned int) i < dataunion.subvector_value->size()) {
                return (*dataunion.subvector_value)[i];
            }
            break;
        case TrackerMap:
            itr = dataunion.submap_value->find(i);
            if (itr != dataunion.submap_value->end())
                return itr->second;
            return NULL;
        case TrackerIntMap:
            itr = dataunion.subintmap_value->find(i);
            if (itr != dataunion.subintmap_value->end())
                return itr->second;
            return NULL;
        default:
            throw std::runtime_error(string("can't -= float to " + 
                        type_to_string(type)));
    }

    return NULL;
}

TrackerElement *TrackerElement::operator[](mac_addr i) {
    except_type_mismatch(TrackerMacMap);

    mac_map_const_iterator itr = dataunion.submacmap_value->find(i);

    if (itr != dataunion.submacmap_value->end())
        return itr->second;

    return NULL;
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

TrackerElement *TrackerElement::get_macmap_value(int idx) {
    except_type_mismatch(TrackerMacMap);

    map<mac_addr, TrackerElement *>::iterator i = dataunion.submacmap_value->find(idx);

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

void TrackerElement::add_macmap(mac_addr i, TrackerElement *s) {
    except_type_mismatch(TrackerMacMap);

    TrackerElement *old = NULL;

    mac_map_iterator mi = dataunion.submacmap_value->find(i);

    if (mi != dataunion.submacmap_value->end()) {
        old = mi->second;
    }

    (*dataunion.submacmap_value)[i] = s;

    s->link();

    if (old != NULL)
        old->unlink();
}

void TrackerElement::del_macmap(mac_addr f) {
    except_type_mismatch(TrackerMacMap);

    mac_map_iterator mi = dataunion.submacmap_value->find(f);
    if (mi != dataunion.submacmap_value->end()) {
        dataunion.submacmap_value->erase(mi);
        mi->second->unlink();
    }
}

void TrackerElement::del_macmap(mac_map_iterator i) {
    except_type_mismatch(TrackerMacMap);

    i->second->unlink();
    dataunion.submacmap_value->erase(i);
}

void TrackerElement::clear_macmap() {
    except_type_mismatch(TrackerMacMap);

    for (mac_map_iterator i = dataunion.submacmap_value->begin();
            i != dataunion.submacmap_value->end(); ++i) {
        i->second->unlink();
    }

    dataunion.submacmap_value->clear();
}

void TrackerElement::insert_macmap(mac_map_pair p) {
    except_type_mismatch(TrackerMacMap);

    std::pair<mac_map_iterator, bool> ret = dataunion.submacmap_value->insert(p);

    if (ret.second) {
        ret.first->second->link();
    }
}

TrackerElement *TrackerElement::get_stringmap_value(string idx) {
    except_type_mismatch(TrackerStringMap);

    map<string, TrackerElement *>::iterator i = dataunion.substringmap_value->find(idx);

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

void TrackerElement::add_stringmap(string i, TrackerElement *s) {
    except_type_mismatch(TrackerStringMap);

    TrackerElement *old = NULL;

    string_map_iterator mi = dataunion.substringmap_value->find(i);

    if (mi != dataunion.substringmap_value->end()) {
        old = mi->second;
    }

    (*dataunion.substringmap_value)[i] = s;

    s->link();

    if (old != NULL)
        old->unlink();
}

void TrackerElement::del_stringmap(string f) {
    except_type_mismatch(TrackerStringMap);

    string_map_iterator mi = dataunion.substringmap_value->find(f);
    if (mi != dataunion.substringmap_value->end()) {
        dataunion.substringmap_value->erase(mi);
        mi->second->unlink();
    }
}

void TrackerElement::del_stringmap(string_map_iterator i) {
    except_type_mismatch(TrackerStringMap);

    i->second->unlink();

    dataunion.substringmap_value->erase(i);
}

void TrackerElement::clear_stringmap() {
    except_type_mismatch(TrackerStringMap);

    for (string_map_iterator i = dataunion.substringmap_value->begin();
            i != dataunion.substringmap_value->end(); ++i) {
        i->second->unlink();
    }

    dataunion.substringmap_value->clear();
}

void TrackerElement::insert_stringmap(string_map_pair p) {
    except_type_mismatch(TrackerStringMap);

    std::pair<string_map_iterator, bool> ret = dataunion.substringmap_value->insert(p);

    if (ret.second) {
        ret.first->second->link();
    }
}

TrackerElement *TrackerElement::get_doublemap_value(double idx) {
    except_type_mismatch(TrackerDoubleMap);

    map<double, TrackerElement *>::iterator i = dataunion.subdoublemap_value->find(idx);

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

void TrackerElement::add_doublemap(double i, TrackerElement *s) {
    except_type_mismatch(TrackerDoubleMap);

    TrackerElement *old = NULL;

    double_map_iterator mi = dataunion.subdoublemap_value->find(i);

    if (mi != dataunion.subdoublemap_value->end()) {
        old = mi->second;
    }

    (*dataunion.subdoublemap_value)[i] = s;

    s->link();

    if (old != NULL)
        old->unlink();
}

void TrackerElement::del_doublemap(double f) {
    except_type_mismatch(TrackerDoubleMap);

    double_map_iterator mi = dataunion.subdoublemap_value->find(f);
    if (mi != dataunion.subdoublemap_value->end()) {
        dataunion.subdoublemap_value->erase(mi);
        mi->second->unlink();
    }
}

void TrackerElement::del_doublemap(double_map_iterator i) {
    except_type_mismatch(TrackerDoubleMap);

    i->second->unlink();
    dataunion.subdoublemap_value->erase(i);
}

void TrackerElement::clear_doublemap() {
    except_type_mismatch(TrackerDoubleMap);

    for (double_map_iterator i = dataunion.subdoublemap_value->begin();
            i != dataunion.subdoublemap_value->end(); ++i) {
        i->second->unlink();
    }

    dataunion.subdoublemap_value->clear();
}

void TrackerElement::insert_doublemap(double_map_pair p) {
    except_type_mismatch(TrackerDoubleMap);

    std::pair<double_map_iterator, bool> ret = dataunion.subdoublemap_value->insert(p);

    if (ret.second) {
        ret.first->second->link();
    }
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
        default:
            return "unknown";
    }
}

void TrackerElement::add_map(int f, TrackerElement *s) {
    except_type_mismatch(TrackerMap);

    TrackerElement *old = NULL;

    map_iterator mi = dataunion.submap_value->find(f);

    if (mi != dataunion.submap_value->end()) {
        old = mi->second;
    }

    (*dataunion.submap_value)[f] = s;

    s->link();

    if (old != NULL)
        old->unlink();
}

void TrackerElement::add_map(TrackerElement *s) {
    except_type_mismatch(TrackerMap);


    TrackerElement *old = NULL;

    map_iterator mi = dataunion.submap_value->find(s->get_id());

    if (mi != dataunion.submap_value->end()) {
        old = mi->second;
    }

    (*dataunion.submap_value)[s->get_id()] = s;

    s->link();

    if (old != NULL)
        old->unlink();
}

void TrackerElement::del_map(int f) {
    except_type_mismatch(TrackerMap);

    map<int, TrackerElement *>::iterator i = dataunion.submap_value->find(f);
    if (i != dataunion.submap_value->end()) {
        dataunion.submap_value->erase(i);
        i->second->unlink();
    }
}

void TrackerElement::del_map(TrackerElement *e) {
    del_map(e->get_id());
}

void TrackerElement::del_map(map_iterator i) {
    except_type_mismatch(TrackerMap);
    i->second->unlink();
    dataunion.submap_value->erase(i);
}

void TrackerElement::insert_map(tracked_pair p) {
    except_type_mismatch(TrackerMap);

    std::pair<map_iterator, bool> ret = dataunion.submap_value->insert(p);

    if (ret.second) {
        ret.first->second->link();
    }
}

void TrackerElement::clear_map() {
    except_type_mismatch(TrackerMap);
    
    for (map_iterator i = dataunion.submap_value->begin();
            i != dataunion.submap_value->end(); ++i) {
        i->second->unlink();
    }

    dataunion.submap_value->clear();
}

TrackerElement *TrackerElement::get_intmap_value(int idx) {
    except_type_mismatch(TrackerIntMap);

    map<int, TrackerElement *>::iterator i = dataunion.subintmap_value->find(idx);

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

    for (int_map_iterator i = dataunion.subintmap_value->begin(); 
            i != dataunion.subintmap_value->end(); ++i) {
        i->second->unlink();
    }

    dataunion.subintmap_value->clear();
}

void TrackerElement::insert_intmap(int_map_pair p) {
    except_type_mismatch(TrackerIntMap);

    std::pair<int_map_iterator, bool> ret = dataunion.subintmap_value->insert(p);

    if (ret.second) {
        ret.first->second->link();
    }
}

void TrackerElement::add_intmap(int i, TrackerElement *s) {
    except_type_mismatch(TrackerIntMap);

    TrackerElement *old = NULL;

    int_map_iterator mi = dataunion.subintmap_value->find(i);

    if (mi != dataunion.subintmap_value->end()) {
        old = mi->second;
    }

    (*dataunion.subintmap_value)[i] = s;

    s->link();

    if (old != NULL)
        old->unlink();
}

void TrackerElement::del_intmap(int i) {
    except_type_mismatch(TrackerIntMap);

    map<int, TrackerElement *>::iterator itr = dataunion.subintmap_value->find(i);
    if (itr != dataunion.subintmap_value->end()) {
        dataunion.subintmap_value->erase(i);
        itr->second->unlink();
    }
}

void TrackerElement::del_intmap(int_map_iterator i) {
    except_type_mismatch(TrackerIntMap);

    i->second->unlink();
    dataunion.subintmap_value->erase(i);
}

void TrackerElement::add_vector(TrackerElement *s) {
    except_type_mismatch(TrackerVector);

    dataunion.subvector_value->push_back(s);
    s->link();
}

void TrackerElement::del_vector(unsigned int p) {
    except_type_mismatch(TrackerVector);

    if (p > dataunion.subvector_value->size()) {
        string w = "del_vector out of range (" + IntToString(p) + ", vector " + 
            IntToString(dataunion.submap_value->size()) + ")";
        throw std::runtime_error(w);
    }

    TrackerElement *e = (*dataunion.subvector_value)[p];
    vector<TrackerElement *>::iterator i = dataunion.subvector_value->begin() + p;
    dataunion.subvector_value->erase(i);

    e->unlink();
}

void TrackerElement::del_vector(vector_iterator i) {
    except_type_mismatch(TrackerVector);

    (*i)->unlink();

    dataunion.subvector_value->erase(i);
}

void TrackerElement::clear_vector() {
    except_type_mismatch(TrackerVector);

    for (unsigned int i = 0; i < dataunion.subvector_value->size(); i++) {
        (*dataunion.subvector_value)[i]->unlink();
    }

    dataunion.subvector_value->clear();
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
        default:
            throw std::runtime_error(string("can't get size of a " + type_to_string(type)));
    }
}

template<> string GetTrackerValue(TrackerElement *e) {
    return e->get_string();
}

template<> int8_t GetTrackerValue(TrackerElement *e) {
    return e->get_int8();
}

template<> uint8_t GetTrackerValue(TrackerElement *e) {
    return e->get_uint8();
}

template<> int16_t GetTrackerValue(TrackerElement *e) {
    return e->get_int16();
}

template<> uint16_t GetTrackerValue(TrackerElement *e) {
    return e->get_uint16();
}

template<> int32_t GetTrackerValue(TrackerElement *e) {
    return e->get_int32();
}

template<> uint32_t GetTrackerValue(TrackerElement *e) {
    return e->get_uint32();
}

template<> int64_t GetTrackerValue(TrackerElement *e) {
    return e->get_int64();
}

template<> uint64_t GetTrackerValue(TrackerElement *e) {
    return e->get_uint64();
}

template<> float GetTrackerValue(TrackerElement *e) {
    return e->get_float();
}

template<> double GetTrackerValue(TrackerElement *e) {
    return e->get_double();
}

template<> mac_addr GetTrackerValue(TrackerElement *e) {
    return e->get_mac();
}

template<> map<int, TrackerElement *> *GetTrackerValue(TrackerElement *e) {
    return e->get_map();
}

template<> vector<TrackerElement *> *GetTrackerValue(TrackerElement *e) {
    return e->get_vector();
}

template<> uuid GetTrackerValue(TrackerElement *e) {
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

    pthread_mutex_init(&pthread_lock, NULL);
}

tracker_component::tracker_component(GlobalRegistry *in_globalreg, int in_id, 
        TrackerElement *e __attribute__((unused))) {

    globalreg = in_globalreg;
    tracker = in_globalreg->entrytracker;

    set_type(TrackerMap);
    set_id(in_id);

    pthread_mutex_init(&pthread_lock, NULL);
}

tracker_component::~tracker_component() { 
    for (unsigned int i = 0; i < registered_fields.size(); i++) {
        delete registered_fields[i];
    }

    pthread_mutex_destroy(&pthread_lock);
}

TrackerElement * tracker_component::clone_type() {
    return new tracker_component(globalreg, get_id());
}

string tracker_component::get_name() {
    return globalreg->entrytracker->GetFieldName(get_id());
}

string tracker_component::get_name(int in_id) {
    return globalreg->entrytracker->GetFieldName(in_id);
}

int tracker_component::RegisterField(string in_name, TrackerType in_type, 
        string in_desc, void **in_dest) {
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

int tracker_component::RegisterField(string in_name, TrackerElement *in_builder, 
        string in_desc, void **in_dest) {
    int id = tracker->RegisterField(in_name, in_builder, in_desc);

    registered_field *rf = new registered_field(id, in_dest);

    registered_fields.push_back(rf);

    return id;
} 

int tracker_component::RegisterComplexField(string in_name, TrackerElement *in_builder, 
        string in_desc) {
    int id = tracker->RegisterField(in_name, in_builder, in_desc);
    return id;
}

void tracker_component::reserve_fields(TrackerElement *e) {
    for (unsigned int i = 0; i < registered_fields.size(); i++) {
        registered_field *rf = registered_fields[i];

        if (rf->assign != NULL) {
            *(rf->assign) = import_or_new(e, rf->id);
        } else {
        }
    }
}

TrackerElement *tracker_component::import_or_new(TrackerElement *e, int i) {
    TrackerElement *r;

    // Find the value in the importer element
    if (e != NULL) {
        r = e->get_map_value(i);

        if (r != NULL) {
            // printf("debug - found id %d, importing\n", i);
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

TrackerElement *tracker_component::get_child_path(string in_path) {
    vector<string> tok = StrTokenize(in_path, "/");
    return get_child_path(tok);
}

TrackerElement *tracker_component::get_child_path(std::vector<string> in_path) {
    if (in_path.size() < 1)
        return NULL;

    TrackerElement *cur_elem = (TrackerElement *) this;
    TrackerElement *next_elem = NULL;

    for (unsigned int x = 0; x < in_path.size(); x++) {
        // Skip empty path element
        if (in_path[x].length() == 0)
            continue;

        int id = globalreg->entrytracker->GetFieldId(in_path[x]);

        if (id < 0) {
            return NULL;
        }

        next_elem = 
            cur_elem->get_map_value(id);

        if (next_elem == NULL) {
            return NULL;
        }

        cur_elem = next_elem;
    }

    return cur_elem;
}


