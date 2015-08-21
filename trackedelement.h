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

#ifndef __TRACKEDELEMENT_H__
#define __TRACKEDELEMENT_H__

#include "config.h"

#include <stdio.h>
#include <stdint.h>

#include <string>
#include <stdexcept>

#include <vector>
#include <map>

#include "macaddr.h"
#include "uuid.h"

// Types of fields we can track and automatically resolve
enum TrackerType {
    TrackerString,

    TrackerInt8, TrackerUInt8,
    TrackerInt16, TrackerUInt16,
    TrackerInt32, TrackerUInt32,
    TrackerInt64, TrackerUInt64,
    TrackerFloat, TrackerDouble,

    TrackerMac,

    TrackerVector, TrackerMap,

    TrackerUuid,

    TrackerCustom
};

class TrackerElement {
public:
    TrackerElement(TrackerType type);

    TrackerType get_type() { return type; }

    // Getter per type, use templated GetTrackerValue() for easy fetch
    string get_string() {
        except_type_mismatch(TrackerString);
        return string_value;
    }

    uint8_t get_uint8() {
        except_type_mismatch(TrackerUInt8);
        return uint8_value;
    }

    int8_t get_int8() {
        except_type_mismatch(TrackerInt8);
        return int8_value;
    }

    uint16_t get_uint16() {
        except_type_mismatch(TrackerUInt16);
        return uint16_value;
    }

    int16_t get_int16() {
        except_type_mismatch(TrackerInt16);
        return int16_value;
    }

    uint32_t get_uint32() {
        except_type_mismatch(TrackerUInt32);
        return uint32_value;
    }

    int32_t get_int32() {
        except_type_mismatch(TrackerInt32);
        return int32_value;
    }

    uint64_t get_uint64() {
        except_type_mismatch(TrackerUInt64);
        return uint64_value;
    }

    int64_t get_int64() {
        except_type_mismatch(TrackerInt64);
        return int64_value;
    }

    float get_float() {
        except_type_mismatch(TrackerFloat);
        return float_value;
    }

    double get_double() {
        except_type_mismatch(TrackerDouble);
        return double_value;
    }

    mac_addr get_mac() {
        except_type_mismatch(TrackerMac);
        return mac_value;
    }

    vector<TrackerElement *> *get_vector() {
        except_type_mismatch(TrackerVector);
        return &subvector_value;
    }

    map<int, TrackerElement *> *get_map() {
        except_type_mismatch(TrackerMap);
        return &submap_value;
    }

    uuid get_uuid() {
        except_type_mismatch(TrackerUuid);
        return uuid_value;
    }

    // Overloaded set
    void set(string v) {
        except_type_mismatch(TrackerString);
        string_value = v;
    }

    void set(uint8_t v) {
        except_type_mismatch(TrackerUInt8);
        uint8_value = v;
    }

    void set(int8_t v) {
        except_type_mismatch(TrackerInt8);
        int8_value = v;
    }

    void set(uint16_t v) {
        except_type_mismatch(TrackerUInt16);
        uint16_value = v;
    }

    void set(int16_t v) {
        except_type_mismatch(TrackerInt16);
        int16_value = v;
    }

    void set(uint32_t v) {
        except_type_mismatch(TrackerUInt32);
        uint32_value = v;
    }

    void set(int32_t v) {
        except_type_mismatch(TrackerInt32);
        int32_value = v;
    }

    void set(uint64_t v) {
        except_type_mismatch(TrackerUInt64);
        uint64_value = v;
    }

    void set(int64_t v) {
        except_type_mismatch(TrackerInt64);
        int64_value = v;
    }

    void set(float v) {
        except_type_mismatch(TrackerFloat);
        float_value = v;
    }

    void set(double v) {
        except_type_mismatch(TrackerDouble);
        double_value = v;
    }

    void set(mac_addr v) {
        except_type_mismatch(TrackerMac);
        mac_value = v;
    }

    void set(uuid v) {
        except_type_mismatch(TrackerUuid);
        uuid_value = v;
    }

    void add_map(int f, TrackerElement *s) {
        except_type_mismatch(TrackerMap);
        submap_value[f] = s;
    }

    void add_vector(TrackerElement *s) {
        except_type_mismatch(TrackerVector);
        subvector_value.push_back(s);
    }

    // Do our best to increment a value
    TrackerElement& operator++(int);

    // Do our best to decrement a value
    TrackerElement& operator--(int);

    // Do our best to do compound addition
    TrackerElement& operator+=(const int& v);
    TrackerElement& operator+=(const float& v);

    // We can append to vectors
    TrackerElement& operator+=(TrackerElement* v);

    // Do our best to do compound subtraction
    TrackerElement& operator-=(const int& v);
    TrackerElement& operator-=(const float& v);

    string type_to_string(TrackerType t);

protected:
    // Generic coercion exception
    void except_type_mismatch(TrackerType t) {
        if (type != t) {
            string w = "element type mismatch, is " + type_to_string(this->type) + 
                " tried to use as " + type_to_string(t);

            throw std::runtime_error(w);
        }
    }

    TrackerType type;

    string string_value;

    // We could make these all one type, but then we'd have odd interactions
    // with incrementing and I'm not positive that's safe in all cases
    uint8_t uint8_value;
    int8_t int8_value;

    uint16_t uint16_value;
    int16_t int16_value;

    uint32_t uint32_value;
    int32_t int32_value;

    uint64_t uint64_value;
    int64_t int64_value;

    float float_value;
    double double_value;

    mac_addr mac_value;

    map<int, TrackerElement *> submap_value;
    vector<TrackerElement *> subvector_value;

    uuid uuid_value;

    void *custom_value;
};



// Templated access functions

template<typename T> T GetTrackerValue(TrackerElement *);

template<> string GetTrackerValue(TrackerElement *e);
template<> int8_t GetTrackerValue(TrackerElement *e);
template<> uint8_t GetTrackerValue(TrackerElement *e);
template<> int16_t GetTrackerValue(TrackerElement *e);
template<> uint16_t GetTrackerValue(TrackerElement *e);
template<> int32_t GetTrackerValue(TrackerElement *e);
template<> uint32_t GetTrackerValue(TrackerElement *e);
template<> int64_t GetTrackerValue(TrackerElement *e);
template<> uint64_t GetTrackerValue(TrackerElement *e);
template<> float GetTrackerValue(TrackerElement *e);
template<> double GetTrackerValue(TrackerElement *e);
template<> mac_addr GetTrackerValue(TrackerElement *e);
template<> map<int, TrackerElement *> *GetTrackerValue(TrackerElement *e);
template<> vector<TrackerElement *> *GetTrackerValue(TrackerElement *e);

class TrackerElementFormatter {
public:
    virtual void get_as_stream(TrackerElement *e, ostream& stream) = 0;
    virtual void vector_to_stream(TrackerElement *e, ostream& stream) = 0;
    virtual void map_to_stream(TrackerElement *e, ostream& stream) = 0;
};

class TrackerElementFormatterBasic : public TrackerElementFormatter {
public:
    virtual void get_as_stream(TrackerElement *e, ostream& stream) {
        switch (e->get_type()) {
            case TrackerString:
                stream << GetTrackerValue<string>(e);
            case TrackerInt8:
                stream << GetTrackerValue<int8_t>(e);
                break;
            case TrackerUInt8:
                stream << GetTrackerValue<uint8_t>(e);
                break;
            case TrackerInt16:
                stream << GetTrackerValue<int16_t>(e);
                break;
            case TrackerUInt16:
                stream << GetTrackerValue<uint16_t>(e);
                break;
            case TrackerInt32:
                stream << GetTrackerValue<int32_t>(e);
                break;
            case TrackerUInt32:
                stream << GetTrackerValue<uint32_t>(e);
                break;
            case TrackerInt64:
                stream << GetTrackerValue<int64_t>(e);
                break;
            case TrackerUInt64:
                stream << GetTrackerValue<uint16_t>(e);
                break;
            case TrackerFloat:
                stream << GetTrackerValue<float>(e);
                break;
            case TrackerDouble:
                stream << GetTrackerValue<double>(e);
                break;
            case TrackerMac:
                stream << GetTrackerValue<mac_addr>(e).Mac2String();
                break;
            case TrackerVector:
                vector_to_stream(e, stream);
                break;
            case TrackerMap:
                map_to_stream(e, stream);
                break;
            case TrackerCustom:
                throw std::runtime_error("can't stream a custom");
            default:
                throw std::runtime_error("can't stream unknown");
        }

    }

    virtual void vector_to_stream(TrackerElement *e, ostream& stream) {
        unsigned int x;

        stream << "vector[";

        vector<TrackerElement *> *vec = GetTrackerValue<vector<TrackerElement *>*>(e);

        for (x = 0; x < vec->size(); x++) {
            get_as_stream((*vec)[x], stream);
            stream << ",";
        }

        stream << "]";
    }

    virtual void map_to_stream(TrackerElement *e, ostream& stream) {
        map<int, TrackerElement *>::iterator i;

        stream << "map{";

        map<int, TrackerElement *> *smap = GetTrackerValue<map<int, TrackerElement *>*>(e);

        for (i = smap->begin(); i != smap->end(); ++i) {
            stream << "[" << i->first << ",";
            get_as_stream(i->second, stream);
            stream << "],";
        }

        stream << "}";
    }


};

#endif
