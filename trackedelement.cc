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
    this->type = TrackerString;
    reference_count = 0;

    set_id(-1);

    // Redundant I guess
    primitives.int8_value = 0;
    primitives.uint8_value = 0;
    primitives.int16_value = 0;
    primitives.uint16_value = 0;
    primitives.int32_value = 0;
    primitives.uint32_value = 0;
    primitives.int64_value = 0;
    primitives.uint64_value = 0;
    primitives.float_value = 0.0f;
    primitives.double_value = 0.0f;

    mac_value = mac_addr(0);

    submap_value = NULL;
    subintmap_value = NULL;
    submacmap_value = NULL;
    substringmap_value = NULL;
    subdoublemap_value = NULL;
    subvector_value = NULL;
    custom_value = NULL;

    set_type(type);
}

TrackerElement::TrackerElement(TrackerType type, int id) {
    this->type = TrackerString;
    set_id(id);

    reference_count = 0;

    primitives.int8_value = 0;
    primitives.uint8_value = 0;
    primitives.int16_value = 0;
    primitives.uint16_value = 0;
    primitives.int32_value = 0;
    primitives.uint32_value = 0;
    primitives.int64_value = 0;
    primitives.uint64_value = 0;
    primitives.float_value = 0.0f;
    primitives.double_value = 0.0f;

    mac_value = mac_addr(0);

    submap_value = NULL;
    subintmap_value = NULL;
    submacmap_value = NULL;
    substringmap_value = NULL;
    subdoublemap_value = NULL;
    subvector_value = NULL;
    custom_value = NULL;

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
        for (unsigned int i = 0; i < subvector_value->size(); i++) {
            (*subvector_value)[i]->unlink();
        }

        delete(subvector_value);
    } else if (type == TrackerMap) {
        map<int, TrackerElement *>::iterator i;

        for (i = submap_value->begin(); i != submap_value->end(); ++i) {
            i->second->unlink();
        }

        delete(submap_value);
    } else if (type == TrackerIntMap) {
        map<int, TrackerElement *>::iterator i;

        for (i = subintmap_value->begin(); i != subintmap_value->end(); ++i) {
            i->second->unlink();
        }

        delete(subintmap_value);
    } else if (type == TrackerMacMap) {
        map<mac_addr, TrackerElement *>::iterator i;

        for (i = submacmap_value->begin(); i != submacmap_value->end(); ++i) {
            i->second->unlink();
        }

        delete(submacmap_value);
    } else if (type == TrackerStringMap) {
        for (string_map_iterator i = substringmap_value->begin(); 
                i != substringmap_value->end(); ++i) {
            i->second->unlink();
        }

        delete(substringmap_value);
    } else if (type == TrackerDoubleMap) {
        for (double_map_iterator i = subdoublemap_value->begin();
                i != subdoublemap_value->end(); ++i) {
            i->second->unlink();
        }

        delete(subdoublemap_value);
    }
}

void TrackerElement::set_type(TrackerType in_type) {
    if (type == in_type)
        return;

    /* Purge old types if we change type */
    if (type == TrackerVector && subvector_value != NULL) {
        for (unsigned int i = 0; i < subvector_value->size(); i++) {
            (*subvector_value)[i]->unlink();
        }

        delete(subvector_value);
        subvector_value = NULL;
    } else if (type == TrackerMap && submap_value != NULL) {
        map<int, TrackerElement *>::iterator i;

        for (i = submap_value->begin(); i != submap_value->end(); ++i) {
            i->second->unlink();
        }

        delete(submap_value);
        submap_value = NULL;
    } else if (type == TrackerIntMap && subintmap_value != NULL) {
        map<int, TrackerElement *>::iterator i;

        for (i = subintmap_value->begin(); i != subintmap_value->end(); ++i) {
            i->second->unlink();
        }

        delete(subintmap_value);
        subintmap_value = NULL;
    } else if (type == TrackerMacMap && submacmap_value != NULL) {
        map<mac_addr, TrackerElement *>::iterator i;

        for (i = submacmap_value->begin(); i != submacmap_value->end(); ++i) {
            i->second->unlink();
        }

        delete(submacmap_value);
        submacmap_value = NULL;
    } else if (type == TrackerStringMap && substringmap_value != NULL) {
        for (string_map_iterator i = substringmap_value->begin(); 
                i != substringmap_value->end(); ++i) {
            i->second->unlink();
        }

        delete(substringmap_value);
        substringmap_value = NULL;
    } else if (type == TrackerDoubleMap) {
        for (double_map_iterator i = subdoublemap_value->begin();
                i != subdoublemap_value->end(); ++i) {
            i->second->unlink();
        }

        delete(subdoublemap_value);
        subdoublemap_value = NULL;
    }
    

    this->type = in_type;

    if (type == TrackerVector) {
        subvector_value = new vector<TrackerElement *>();
    } else if (type == TrackerMap) {
        submap_value = new map<int, TrackerElement *>();
    } else if (type == TrackerIntMap) {
        subintmap_value = new map<int, TrackerElement *>();
    } else if (type == TrackerMacMap) {
        submacmap_value = new map<mac_addr, TrackerElement *>();
    } else if (type == TrackerStringMap) {
        substringmap_value = new map<string, TrackerElement *>();
    } else if (type == TrackerDoubleMap) {
        subdoublemap_value = new map<double, TrackerElement *>();
    }

}

TrackerElement& TrackerElement::operator++(int) {
    switch (type) {
        case TrackerInt8:
            primitives.int8_value++;
            break;
        case TrackerUInt8:
            primitives.uint8_value++;
            break;
        case TrackerInt16:
            primitives.int16_value++;
            break;
        case TrackerUInt16:
            primitives.uint16_value++;
            break;
        case TrackerInt32:
            primitives.int32_value++;
            break;
        case TrackerUInt32:
            primitives.uint32_value++;
            break;
        case TrackerInt64:
            primitives.int64_value++;
            break;
        case TrackerUInt64:
            primitives.uint64_value++;
            break;
        case TrackerFloat:
            primitives.float_value++;
            break;
        case TrackerDouble:
            primitives.double_value++;
            break;
        default:
            throw std::runtime_error(string("can't increment " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator--(int) {
    switch (type) {
        case TrackerInt8:
            primitives.int8_value--;
            break;
        case TrackerUInt8:
            primitives.uint8_value--;
            break;
        case TrackerInt16:
            primitives.int16_value--;
            break;
        case TrackerUInt16:
            primitives.uint16_value--;
            break;
        case TrackerInt32:
            primitives.int32_value--;
            break;
        case TrackerUInt32:
            primitives.uint32_value--;
            break;
        case TrackerInt64:
            primitives.int64_value--;
            break;
        case TrackerUInt64:
            primitives.uint64_value--;
            break;
        case TrackerFloat:
            primitives.float_value--;
            break;
        case TrackerDouble:
            primitives.double_value--;
            break;
        default:
            throw std::runtime_error(string("can't decrement " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator+=(const float& v) {
    switch (type) {
        case TrackerFloat:
            primitives.float_value+= v;
            break;
        case TrackerDouble:
            primitives.double_value+= v;
            break;
        default:
            throw std::runtime_error(string("can't += float to " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator+=(const double& v) {
    switch (type) {
        case TrackerFloat:
            primitives.float_value+= v;
            break;
        case TrackerDouble:
            primitives.double_value+= v;
            break;
        default:
            throw std::runtime_error(string("can't += float to " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator+=(const int& v) {
    switch (type) {
        case TrackerInt8:
            primitives.int8_value += v;
            break;
        case TrackerUInt8:
            primitives.uint8_value += v;
            break;
        case TrackerInt16:
            primitives.int16_value+= v;
            break;
        case TrackerUInt16:
            primitives.uint16_value+= v;
            break;
        case TrackerInt32:
            primitives.int32_value+= v;
            break;
        case TrackerUInt32:
            primitives.uint32_value+= v;
            break;
        case TrackerInt64:
            primitives.int64_value+= v;
            break;
        case TrackerUInt64:
            primitives.uint64_value+= v;
            break;
        case TrackerFloat:
            primitives.float_value+= v;
            break;
        case TrackerDouble:
            primitives.double_value+= v;
            break;
        default:
            throw std::runtime_error(string("can't += to " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator+=(const unsigned int& v) {
    switch (type) {
        case TrackerInt8:
            primitives.int8_value += v;
            break;
        case TrackerUInt8:
            primitives.uint8_value += v;
            break;
        case TrackerInt16:
            primitives.int16_value+= v;
            break;
        case TrackerUInt16:
            primitives.uint16_value+= v;
            break;
        case TrackerInt32:
            primitives.int32_value+= v;
            break;
        case TrackerUInt32:
            primitives.uint32_value+= v;
            break;
        case TrackerInt64:
            primitives.int64_value+= v;
            break;
        case TrackerUInt64:
            primitives.uint64_value+= v;
            break;
        case TrackerFloat:
            primitives.float_value+= v;
            break;
        case TrackerDouble:
            primitives.double_value+= v;
            break;
        default:
            throw std::runtime_error(string("can't += to " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator+=(const int64_t& i) {
    except_type_mismatch(TrackerInt64);
    primitives.int64_value += i;
    return *this;
}

TrackerElement& TrackerElement::operator+=(const uint64_t& i) {
    except_type_mismatch(TrackerUInt64);
    primitives.uint64_value += i;
    return *this;
}

TrackerElement& TrackerElement::operator-=(const int& v) {
    switch (type) {
        case TrackerInt8:
            primitives.int8_value -= v;
            break;
        case TrackerUInt8:
            primitives.uint8_value -= v;
            break;
        case TrackerInt16:
            primitives.int16_value-= v;
            break;
        case TrackerUInt16:
            primitives.uint16_value-= v;
            break;
        case TrackerInt32:
            primitives.int32_value-= v;
            break;
        case TrackerUInt32:
            primitives.uint32_value-= v;
            break;
        case TrackerInt64:
            primitives.int64_value-= v;
            break;
        case TrackerUInt64:
            primitives.uint64_value-= v;
            break;
        case TrackerFloat:
            primitives.float_value-= v;
            break;
        case TrackerDouble:
            primitives.double_value-= v;
            break;
        default:
            throw std::runtime_error(string("can't -= to " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator-=(const unsigned int& v) {
    switch (type) {
        case TrackerInt8:
            primitives.int8_value -= v;
            break;
        case TrackerUInt8:
            primitives.uint8_value -= v;
            break;
        case TrackerInt16:
            primitives.int16_value-= v;
            break;
        case TrackerUInt16:
            primitives.uint16_value-= v;
            break;
        case TrackerInt32:
            primitives.int32_value-= v;
            break;
        case TrackerUInt32:
            primitives.uint32_value-= v;
            break;
        case TrackerInt64:
            primitives.int64_value-= v;
            break;
        case TrackerUInt64:
            primitives.uint64_value-= v;
            break;
        case TrackerFloat:
            primitives.float_value-= v;
            break;
        case TrackerDouble:
            primitives.double_value-= v;
            break;
        default:
            throw std::runtime_error(string("can't -= to " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator-=(const float& v) {
    switch (type) {
        case TrackerFloat:
            primitives.float_value-= v;
            break;
        case TrackerDouble:
            primitives.double_value-= v;
            break;
        default:
            throw std::runtime_error(string("can't -= float to " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator-=(const double& v) {
    switch (type) {
        case TrackerFloat:
            primitives.float_value-= v;
            break;
        case TrackerDouble:
            primitives.double_value-= v;
            break;
        default:
            throw std::runtime_error(string("can't -= float to " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator-=(const int64_t& i) {
    except_type_mismatch(TrackerInt64);
    primitives.int64_value -= i;
    return *this;
}

TrackerElement& TrackerElement::operator-=(const uint64_t& i) {
    except_type_mismatch(TrackerUInt64);
    primitives.uint64_value -= i;
    return *this;
}


TrackerElement& TrackerElement::operator|=(int8_t i) {
    except_type_mismatch(TrackerInt8);
    primitives.int8_value |= i;
    return *this;
}

TrackerElement& TrackerElement::operator|=(uint8_t i) {
    except_type_mismatch(TrackerUInt8);
    primitives.uint8_value |= i;
    return *this;
}

TrackerElement& TrackerElement::operator|=(int16_t i) {
    except_type_mismatch(TrackerInt16);
    primitives.int16_value |= i;
    return *this;
}

TrackerElement& TrackerElement::operator|=(uint16_t i) {
    except_type_mismatch(TrackerUInt16);
    primitives.uint16_value |= i;
    return *this;
}

TrackerElement& TrackerElement::operator|=(int32_t i) {
    except_type_mismatch(TrackerInt32);
    primitives.int32_value |= i;
    return *this;
}

TrackerElement& TrackerElement::operator|=(uint32_t i) {
    except_type_mismatch(TrackerUInt32);
    primitives.uint32_value |= i;
    return *this;
}

TrackerElement& TrackerElement::operator|=(int64_t i) {
    except_type_mismatch(TrackerInt64);
    primitives.int64_value |= i;
    return *this;
}

TrackerElement& TrackerElement::operator|=(uint64_t i) {
    except_type_mismatch(TrackerUInt64);
    primitives.uint64_value |= i;
    return *this;
}

TrackerElement& TrackerElement::operator&=(int8_t i) {
    except_type_mismatch(TrackerInt8);
    primitives.int8_value &= i;
    return *this;
}

TrackerElement& TrackerElement::operator&=(uint8_t i) {
    except_type_mismatch(TrackerUInt8);
    primitives.uint8_value &= i;
    return *this;
}

TrackerElement& TrackerElement::operator&=(int16_t i) {
    except_type_mismatch(TrackerInt16);
    primitives.int16_value &= i;
    return *this;
}

TrackerElement& TrackerElement::operator&=(uint16_t i) {
    except_type_mismatch(TrackerUInt16);
    primitives.uint16_value &= i;
    return *this;
}

TrackerElement& TrackerElement::operator&=(int32_t i) {
    except_type_mismatch(TrackerInt32);
    primitives.int32_value &= i;
    return *this;
}

TrackerElement& TrackerElement::operator&=(uint32_t i) {
    except_type_mismatch(TrackerUInt32);
    primitives.uint32_value &= i;
    return *this;
}

TrackerElement& TrackerElement::operator&=(int64_t i) {
    except_type_mismatch(TrackerInt64);
    primitives.int64_value &= i;
    return *this;
}

TrackerElement& TrackerElement::operator&=(uint64_t i) {
    except_type_mismatch(TrackerUInt64);
    primitives.uint64_value &= i;
    return *this;
}

TrackerElement& TrackerElement::operator^=(int8_t i) {
    except_type_mismatch(TrackerInt8);
    primitives.int8_value ^= i;
    return *this;
}

TrackerElement& TrackerElement::operator^=(uint8_t i) {
    except_type_mismatch(TrackerUInt8);
    primitives.uint8_value ^= i;
    return *this;
}

TrackerElement& TrackerElement::operator^=(int16_t i) {
    except_type_mismatch(TrackerInt16);
    primitives.int16_value ^= i;
    return *this;
}

TrackerElement& TrackerElement::operator^=(uint16_t i) {
    except_type_mismatch(TrackerUInt16);
    primitives.uint16_value ^= i;
    return *this;
}

TrackerElement& TrackerElement::operator^=(int32_t i) {
    except_type_mismatch(TrackerInt32);
    primitives.int32_value ^= i;
    return *this;
}

TrackerElement& TrackerElement::operator^=(uint32_t i) {
    except_type_mismatch(TrackerUInt32);
    primitives.uint32_value ^= i;
    return *this;
}

TrackerElement& TrackerElement::operator^=(int64_t i) {
    except_type_mismatch(TrackerInt64);
    primitives.int64_value ^= i;
    return *this;
}

TrackerElement& TrackerElement::operator^=(uint64_t i) {
    except_type_mismatch(TrackerUInt64);
    primitives.uint64_value ^= i;
    return *this;
}

TrackerElement *TrackerElement::operator[](int i) {
    string w;
    map<int, TrackerElement *>::iterator itr;

    switch (type) {
        case TrackerVector:
            if (i >= 0 && (unsigned int) i < subvector_value->size()) {
                return (*subvector_value)[i];
            }
            break;
        case TrackerMap:
            itr = submap_value->find(i);
            if (itr != submap_value->end())
                return itr->second;
            return NULL;
        case TrackerIntMap:
            itr = subintmap_value->find(i);
            if (itr != subintmap_value->end())
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

    mac_map_const_iterator itr = submacmap_value->find(i);

    if (itr != submacmap_value->end())
        return itr->second;

    return NULL;
}

TrackerElement::map_const_iterator TrackerElement::begin() {
    switch (type) {
        case TrackerMap:
            return submap_value->begin();
        case TrackerIntMap:
            return subintmap_value->begin();
        default:
            throw std::runtime_error(string("can't address " + 
                        type_to_string(type) + " as a map"));
    }
}

TrackerElement::map_const_iterator TrackerElement::end() {
    switch (type) {
        case TrackerMap:
            return submap_value->end();
        case TrackerIntMap:
            return subintmap_value->end();
        default:
            throw std::runtime_error(string("can't address " + 
                        type_to_string(type) + " as a map"));
    }
}

TrackerElement::map_iterator TrackerElement::find(int k) {
    switch (type) {
        case TrackerMap:
            return submap_value->find(k);
        case TrackerIntMap:
            return subintmap_value->find(k);
        default:
            throw std::runtime_error(string("can't address " + 
                        type_to_string(type) + " as a map"));
    }
}

TrackerElement *TrackerElement::get_macmap_value(int idx) {
    except_type_mismatch(TrackerMacMap);

    map<mac_addr, TrackerElement *>::iterator i = submacmap_value->find(idx);

    if (i == submacmap_value->end()) {
        return NULL;
    }

    return i->second;
}

TrackerElement::vector_const_iterator TrackerElement::vec_begin() {
    except_type_mismatch(TrackerVector);

    return subvector_value->begin();
}

TrackerElement::vector_const_iterator TrackerElement::vec_end() {
    except_type_mismatch(TrackerVector);

    return subvector_value->end();
}

TrackerElement::mac_map_const_iterator TrackerElement::mac_begin() {
    except_type_mismatch(TrackerMacMap);

    return submacmap_value->begin();
}

TrackerElement::mac_map_const_iterator TrackerElement::mac_end() {
    except_type_mismatch(TrackerMacMap);

    return submacmap_value->end();
}

TrackerElement::mac_map_iterator TrackerElement::mac_find(mac_addr k) {
    except_type_mismatch(TrackerMacMap);

    return submacmap_value->find(k);
}

void TrackerElement::add_macmap(mac_addr i, TrackerElement *s) {
    except_type_mismatch(TrackerMacMap);

    TrackerElement *old = NULL;

    mac_map_iterator mi = submacmap_value->find(i);

    if (mi != submacmap_value->end()) {
        old = mi->second;
    }

    (*submacmap_value)[i] = s;

    s->link();

    if (old != NULL)
        old->unlink();
}

void TrackerElement::del_macmap(mac_addr f) {
    except_type_mismatch(TrackerMacMap);

    mac_map_iterator mi = submacmap_value->find(f);
    if (mi != submacmap_value->end()) {
        submacmap_value->erase(mi);
        mi->second->unlink();
    }
}

void TrackerElement::del_macmap(mac_map_iterator i) {
    except_type_mismatch(TrackerMacMap);

    i->second->unlink();
    submacmap_value->erase(i);
}

void TrackerElement::clear_macmap() {
    except_type_mismatch(TrackerMacMap);

    for (mac_map_iterator i = submacmap_value->begin();
            i != submacmap_value->end(); ++i) {
        i->second->unlink();
    }

    submacmap_value->clear();
}

void TrackerElement::insert_macmap(mac_map_pair p) {
    except_type_mismatch(TrackerMacMap);

    std::pair<mac_map_iterator, bool> ret = submacmap_value->insert(p);

    if (ret.second) {
        ret.first->second->link();
    }
}

TrackerElement *TrackerElement::get_stringmap_value(string idx) {
    except_type_mismatch(TrackerStringMap);

    map<string, TrackerElement *>::iterator i = substringmap_value->find(idx);

    if (i == substringmap_value->end()) {
        return NULL;
    }

    return i->second;
}

TrackerElement::string_map_const_iterator TrackerElement::string_begin() {
    except_type_mismatch(TrackerStringMap);

    return substringmap_value->begin();
}

TrackerElement::string_map_const_iterator TrackerElement::string_end() {
    except_type_mismatch(TrackerStringMap);

    return substringmap_value->end();
}

TrackerElement::string_map_iterator TrackerElement::string_find(string k) {
    except_type_mismatch(TrackerStringMap);

    return substringmap_value->find(k);
}

void TrackerElement::add_stringmap(string i, TrackerElement *s) {
    except_type_mismatch(TrackerStringMap);

    TrackerElement *old = NULL;

    string_map_iterator mi = substringmap_value->find(i);

    if (mi != substringmap_value->end()) {
        old = mi->second;
    }

    (*substringmap_value)[i] = s;

    s->link();

    if (old != NULL)
        old->unlink();
}

void TrackerElement::del_stringmap(string f) {
    except_type_mismatch(TrackerStringMap);

    string_map_iterator mi = substringmap_value->find(f);
    if (mi != substringmap_value->end()) {
        substringmap_value->erase(mi);
        mi->second->unlink();
    }
}

void TrackerElement::del_stringmap(string_map_iterator i) {
    except_type_mismatch(TrackerStringMap);

    i->second->unlink();

    substringmap_value->erase(i);
}

void TrackerElement::clear_stringmap() {
    except_type_mismatch(TrackerStringMap);

    for (string_map_iterator i = substringmap_value->begin();
            i != substringmap_value->end(); ++i) {
        i->second->unlink();
    }

    substringmap_value->clear();
}

void TrackerElement::insert_stringmap(string_map_pair p) {
    except_type_mismatch(TrackerStringMap);

    std::pair<string_map_iterator, bool> ret = substringmap_value->insert(p);

    if (ret.second) {
        ret.first->second->link();
    }
}

TrackerElement *TrackerElement::get_doublemap_value(double idx) {
    except_type_mismatch(TrackerDoubleMap);

    map<double, TrackerElement *>::iterator i = subdoublemap_value->find(idx);

    if (i == subdoublemap_value->end()) {
        return NULL;
    }

    return i->second;
}

TrackerElement::double_map_const_iterator TrackerElement::double_begin() {
    except_type_mismatch(TrackerDoubleMap);

    return subdoublemap_value->begin();
}

TrackerElement::double_map_const_iterator TrackerElement::double_end() {
    except_type_mismatch(TrackerDoubleMap);

    return subdoublemap_value->end();
}

TrackerElement::double_map_iterator TrackerElement::double_find(double k) {
    except_type_mismatch(TrackerDoubleMap);

    return subdoublemap_value->find(k);
}

void TrackerElement::add_doublemap(double i, TrackerElement *s) {
    except_type_mismatch(TrackerDoubleMap);

    TrackerElement *old = NULL;

    double_map_iterator mi = subdoublemap_value->find(i);

    if (mi != subdoublemap_value->end()) {
        old = mi->second;
    }

    (*subdoublemap_value)[i] = s;

    s->link();

    if (old != NULL)
        old->unlink();
}

void TrackerElement::del_doublemap(double f) {
    except_type_mismatch(TrackerDoubleMap);

    double_map_iterator mi = subdoublemap_value->find(f);
    if (mi != subdoublemap_value->end()) {
        subdoublemap_value->erase(mi);
        mi->second->unlink();
    }
}

void TrackerElement::del_doublemap(double_map_iterator i) {
    except_type_mismatch(TrackerDoubleMap);

    i->second->unlink();
    subdoublemap_value->erase(i);
}

void TrackerElement::clear_doublemap() {
    except_type_mismatch(TrackerDoubleMap);

    for (double_map_iterator i = subdoublemap_value->begin();
            i != subdoublemap_value->end(); ++i) {
        i->second->unlink();
    }

    subdoublemap_value->clear();
}

void TrackerElement::insert_doublemap(double_map_pair p) {
    except_type_mismatch(TrackerDoubleMap);

    std::pair<double_map_iterator, bool> ret = subdoublemap_value->insert(p);

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

    map_iterator mi = submap_value->find(f);

    if (mi != submap_value->end()) {
        old = mi->second;
    }

    (*submap_value)[f] = s;

    s->link();

    if (old != NULL)
        old->unlink();
}

void TrackerElement::add_map(TrackerElement *s) {
    except_type_mismatch(TrackerMap);


    TrackerElement *old = NULL;

    map_iterator mi = submap_value->find(s->get_id());

    if (mi != submap_value->end()) {
        old = mi->second;
    }

    (*submap_value)[s->get_id()] = s;

    s->link();

    if (old != NULL)
        old->unlink();
}

void TrackerElement::del_map(int f) {
    except_type_mismatch(TrackerMap);

    map<int, TrackerElement *>::iterator i = submap_value->find(f);
    if (i != submap_value->end()) {
        submap_value->erase(i);
        i->second->unlink();
    }
}

void TrackerElement::del_map(TrackerElement *e) {
    del_map(e->get_id());
}

void TrackerElement::del_map(map_iterator i) {
    except_type_mismatch(TrackerMap);
    i->second->unlink();
    submap_value->erase(i);
}

void TrackerElement::insert_map(tracked_pair p) {
    except_type_mismatch(TrackerMap);

    std::pair<map_iterator, bool> ret = submap_value->insert(p);

    if (ret.second) {
        ret.first->second->link();
    }
}

void TrackerElement::clear_map() {
    except_type_mismatch(TrackerMap);
    
    for (map_iterator i = submap_value->begin();
            i != submap_value->end(); ++i) {
        i->second->unlink();
    }

    submap_value->clear();
}

TrackerElement *TrackerElement::get_intmap_value(int idx) {
    except_type_mismatch(TrackerIntMap);

    map<int, TrackerElement *>::iterator i = subintmap_value->find(idx);

    if (i == submap_value->end()) {
        return NULL;
    }

    return i->second;
}

TrackerElement::int_map_const_iterator TrackerElement::int_begin() {
    except_type_mismatch(TrackerIntMap);

    return subintmap_value->begin();
}

TrackerElement::int_map_const_iterator TrackerElement::int_end() {
    except_type_mismatch(TrackerIntMap);

    return subintmap_value->end();
}

TrackerElement::int_map_iterator TrackerElement::int_find(int k) {
    except_type_mismatch(TrackerIntMap);

    return subintmap_value->find(k);
}

void TrackerElement::clear_intmap() {
    except_type_mismatch(TrackerIntMap);

    for (int_map_iterator i = subintmap_value->begin(); 
            i != subintmap_value->end(); ++i) {
        i->second->unlink();
    }

    subintmap_value->clear();
}

void TrackerElement::insert_intmap(int_map_pair p) {
    except_type_mismatch(TrackerIntMap);

    std::pair<int_map_iterator, bool> ret = subintmap_value->insert(p);

    if (ret.second) {
        ret.first->second->link();
    }
}

void TrackerElement::add_intmap(int i, TrackerElement *s) {
    except_type_mismatch(TrackerIntMap);

    TrackerElement *old = NULL;

    int_map_iterator mi = subintmap_value->find(i);

    if (mi != subintmap_value->end()) {
        old = mi->second;
    }

    (*subintmap_value)[i] = s;

    s->link();

    if (old != NULL)
        old->unlink();
}

void TrackerElement::del_intmap(int i) {
    except_type_mismatch(TrackerIntMap);

    map<int, TrackerElement *>::iterator itr = subintmap_value->find(i);
    if (itr != subintmap_value->end()) {
        subintmap_value->erase(i);
        itr->second->unlink();
    }
}

void TrackerElement::del_intmap(int_map_iterator i) {
    except_type_mismatch(TrackerIntMap);

    i->second->unlink();
    subintmap_value->erase(i);
}

void TrackerElement::add_vector(TrackerElement *s) {
    except_type_mismatch(TrackerVector);
    subvector_value->push_back(s);
    s->link();
}

void TrackerElement::del_vector(unsigned int p) {
    except_type_mismatch(TrackerVector);

    if (p > subvector_value->size()) {
        string w = "del_vector out of range (" + IntToString(p) + ", vector " + 
            IntToString(submap_value->size()) + ")";
        throw std::runtime_error(w);
    }

    TrackerElement *e = (*subvector_value)[p];
    vector<TrackerElement *>::iterator i = subvector_value->begin() + p;
    subvector_value->erase(i);

    e->unlink();
}

void TrackerElement::del_vector(vector_iterator i) {
    except_type_mismatch(TrackerVector);

    (*i)->unlink();

    subvector_value->erase(i);
}

void TrackerElement::clear_vector() {
    except_type_mismatch(TrackerVector);

    for (unsigned int i = 0; i < subvector_value->size(); i++) {
        (*subvector_value)[i]->unlink();
    }

    subvector_value->clear();
}

size_t TrackerElement::size() {
    switch (type) {
        case TrackerVector:
            return subvector_value->size();
        case TrackerMap:
            return submap_value->size();
        case TrackerIntMap:
            return subintmap_value->size();
        case TrackerMacMap:
            return submacmap_value->size();
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


