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

#include "util.h"

#include "trackedelement.h"

TrackerElement::TrackerElement(TrackerType type) {
    this->type = type;
    reference_count = 0;

    set_id(-1);

    int8_value = 0;
    uint8_value = 0;
    int16_value = 0;
    uint16_value = 0;
    int32_value = 0;
    uint32_value = 0;
    int64_value = 0;
    uint64_value = 0;
    float_value = 0.0f;
    double_value = 0.0f;
    mac_value = mac_addr(0);
}

TrackerElement::TrackerElement(TrackerType type, int id) {
    this->type = type;
    set_id(id);

    reference_count = 0;

    int8_value = 0;
    uint8_value = 0;
    int16_value = 0;
    uint16_value = 0;
    int32_value = 0;
    uint32_value = 0;
    int64_value = 0;
    uint64_value = 0;
    float_value = 0.0f;
    double_value = 0.0f;
    mac_value = mac_addr(0);
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
        for (unsigned int i = 0; i < subvector_value.size(); i++) {
            subvector_value[i]->unlink();
        }
    } else if (type == TrackerMap) {
        map<int, TrackerElement *>::iterator i;

        for (i = submap_value.begin(); i != submap_value.end(); ++i) {
            i->second->unlink();
        }
    }
}

TrackerElement& TrackerElement::operator++(int) {
    switch (type) {
        case TrackerString:
            throw std::runtime_error("can't increment a string");
        case TrackerInt8:
            int8_value++;
            break;
        case TrackerUInt8:
            uint8_value++;
            break;
        case TrackerInt16:
            int16_value++;
            break;
        case TrackerUInt16:
            uint16_value++;
            break;
        case TrackerInt32:
            int32_value++;
            break;
        case TrackerUInt32:
            uint32_value++;
            break;
        case TrackerInt64:
            int64_value++;
            break;
        case TrackerUInt64:
            uint64_value++;
            break;
        case TrackerFloat:
            float_value++;
            break;
        case TrackerDouble:
            double_value++;
            break;
        case TrackerMac:
            throw std::runtime_error("can't increment a mac");
        case TrackerUuid:
            throw std::runtime_error("can't increment a uuid");
        case TrackerCustom:
            throw std::runtime_error("can't increment a custom");
        default:
            throw std::runtime_error("can't increment unknown");
    }

    return *this;
}

TrackerElement& TrackerElement::operator--(int) {
    switch (type) {
        case TrackerString:
            throw std::runtime_error("can't increment a string");
        case TrackerInt8:
            int8_value--;
            break;
        case TrackerUInt8:
            uint8_value--;
            break;
        case TrackerInt16:
            int16_value--;
            break;
        case TrackerUInt16:
            uint16_value--;
            break;
        case TrackerInt32:
            int32_value--;
            break;
        case TrackerUInt32:
            uint32_value--;
            break;
        case TrackerInt64:
            int64_value--;
            break;
        case TrackerUInt64:
            uint64_value--;
            break;
        case TrackerFloat:
            float_value--;
            break;
        case TrackerDouble:
            double_value--;
            break;
        case TrackerMac:
        case TrackerVector:
        case TrackerMap:
        case TrackerCustom:
        default:
            throw std::runtime_error(string("can't decrement " + type_to_string(type)));
    }

    return *this;
}

TrackerElement& TrackerElement::operator+=(const float& v) {
    switch (type) {
        case TrackerString:
        case TrackerInt8:
        case TrackerUInt8:
        case TrackerInt16:
        case TrackerUInt16:
        case TrackerInt32:
        case TrackerUInt32:
        case TrackerInt64:
        case TrackerUInt64:
        case TrackerMac:
        case TrackerVector:
        case TrackerMap:
        case TrackerUuid:
        case TrackerCustom:
            throw std::runtime_error(string("can't += float to " + type_to_string(type)));
        case TrackerFloat:
            float_value+= v;
            break;
        case TrackerDouble:
            double_value+= v;
            break;
        default:
            throw std::runtime_error("can't += unknown");
    }

    return *this;
}

TrackerElement& TrackerElement::operator+=(const int& v) {
    switch (type) {
        case TrackerString:
            throw std::runtime_error("can't += int to string");
        case TrackerInt8:
            int8_value += v;
            break;
        case TrackerUInt8:
            uint8_value += v;
            break;
        case TrackerInt16:
            int16_value+= v;
            break;
        case TrackerUInt16:
            uint16_value+= v;
            break;
        case TrackerInt32:
            int32_value+= v;
            break;
        case TrackerUInt32:
            uint32_value+= v;
            break;
        case TrackerInt64:
            int64_value+= v;
            break;
        case TrackerUInt64:
            uint64_value+= v;
            break;
        case TrackerFloat:
            float_value+= v;
            break;
        case TrackerDouble:
            double_value+= v;
            break;
        case TrackerMac:
        case TrackerMap:
        case TrackerVector:
        case TrackerUuid:
        case TrackerCustom:
            throw std::runtime_error(string("can't += to " + type_to_string(type)));
        default:
            throw std::runtime_error("can't += unknown");
    }

    return *this;
}

TrackerElement& TrackerElement::operator+=(TrackerElement* v) {
    if (type == TrackerVector) 
        subvector_value.push_back(v); 
    else
        throw std::runtime_error("Can't append an element to a non-vector");

    return *this;
}

TrackerElement& TrackerElement::operator-=(const int& v) {
    switch (type) {
        case TrackerString:
            throw std::runtime_error("can't -= int to string");
        case TrackerInt8:
            int8_value -= v;
            break;
        case TrackerUInt8:
            uint8_value -= v;
            break;
        case TrackerInt16:
            int16_value-= v;
            break;
        case TrackerUInt16:
            uint16_value-= v;
            break;
        case TrackerInt32:
            int32_value-= v;
            break;
        case TrackerUInt32:
            uint32_value-= v;
            break;
        case TrackerInt64:
            int64_value-= v;
            break;
        case TrackerUInt64:
            uint64_value-= v;
            break;
        case TrackerFloat:
            float_value-= v;
            break;
        case TrackerDouble:
            double_value-= v;
            break;
        case TrackerMac:
        case TrackerVector:
        case TrackerMap:
        case TrackerUuid:
        case TrackerCustom:
            throw std::runtime_error(string("can't -= to " + type_to_string(type)));
        default:
            throw std::runtime_error("can't -= unknown");
    }

    return *this;
}

TrackerElement& TrackerElement::operator-=(const float& v) {
    switch (type) {
        case TrackerString:
        case TrackerInt8:
        case TrackerUInt8:
        case TrackerInt16:
        case TrackerUInt16:
        case TrackerInt32:
        case TrackerUInt32:
        case TrackerInt64:
        case TrackerUInt64:
        case TrackerMac:
        case TrackerVector:
        case TrackerMap:
        case TrackerUuid:
        case TrackerCustom:
            throw std::runtime_error(string("can't -= float to " + type_to_string(type)));
        case TrackerFloat:
            float_value-= v;
            break;
        case TrackerDouble:
            double_value-= v;
            break;
        default:
            throw std::runtime_error("can't -= unknown");
    }

    return *this;
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
        case TrackerCustom:
            return "custom";
        case TrackerVector:
            return "vector<>";
        case TrackerMap:
            return "map<>";
        case TrackerUuid:
            return "uuid";
        default:
            return "unknown";
    }
}

void TrackerElement::add_map(int f, TrackerElement *s) {
    except_type_mismatch(TrackerMap);
    submap_value[f] = s;
    s->link();
}

void TrackerElement::add_map(TrackerElement *s) {
    except_type_mismatch(TrackerMap);
    submap_value[s->get_id()] = s;
    s->link();
}

void TrackerElement::add_vector(TrackerElement *s) {
    except_type_mismatch(TrackerVector);
    subvector_value.push_back(s);
    s->link();
}

void TrackerElement::del_map(int f) {
    map<int, TrackerElement *>::iterator i = submap_value.find(f);

    if (i != submap_value.end()) {
        submap_value.erase(i);
        i->second->unlink();
    }
}

void TrackerElement::del_vector(unsigned int p) {
    if (p > submap_value.size()) {
        string w = "del_vector out of range (" + IntToString(p) + ", vector " + 
            IntToString(submap_value.size()) + ")";
        throw std::runtime_error(w);
    }

    TrackerElement *e = submap_value[p];
    submap_value.erase(p);

    e->unlink();
}

void TrackerElement::del_map(TrackerElement *e) {
    del_map(e->get_id());
}

template<> string GetTrackerValue(TrackerElement *e) {

    return e->get_string();
}

template<> int8_t GetTrackerValue(TrackerElement *e) {
    return e->get_int8();
}

template<> uint8_t GetTrackerValue(TrackerElement *e) {
    return e->get_int8();
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

bool operator>(TrackerElement &te1, float f) {
    return te1.get_float() > f;
}

bool operator>(TrackerElement &te1, double d) {
    return te1.get_double() > d;
}



