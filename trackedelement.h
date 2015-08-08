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

#include "macaddr.h"

// Types of fields we can track and automatically resolve
enum TrackerType {
    TrackerString,

    TrackerInt8, TrackerUInt8,
    TrackerInt16, TrackerUInt16,
    TrackerInt32, TrackerUInt32,
    TrackerInt64, TrackerUInt64,
    TrackerFloat, TrackerDouble,

    TrackerMac,

    TrackerCustom
};

class TrackerElement {
public:
    TrackerElement(TrackerType type) {
        this->type = type;

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

    // Do our best to increment a value
    TrackerElement& operator++(int) {
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
            case TrackerCustom:
                throw std::runtime_error("can't increment a custom");
            default:
                throw std::runtime_error("can't increment unknown");
        }

        return *this;
    }

    // Do our best to decrement a value
    TrackerElement& operator--(int) {
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
                throw std::runtime_error("can't increment a mac");
            case TrackerCustom:
                throw std::runtime_error("can't increment a custom");
            default:
                throw std::runtime_error("can't increment unknown");
        }

        return *this;
    }

    TrackerElement& operator+=(const float& v) {
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

    // Do our best to do compound addition
    TrackerElement& operator+=(const int& v) {
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
                throw std::runtime_error("can't += a mac");
            case TrackerCustom:
                throw std::runtime_error("can't += a custom");
            default:
                throw std::runtime_error("can't += unknown");
        }

        return *this;
    }

    // Do our best to do compound subtraction
    TrackerElement& operator-=(const int& v) {
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
                throw std::runtime_error("can't += a mac");
            case TrackerCustom:
                throw std::runtime_error("can't -= a custom");
            default:
                throw std::runtime_error("can't -= unknown");
        }

        return *this;
    }

    TrackerElement& operator-=(const float& v) {
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

    string type_to_string(TrackerType t) {
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
            default:
                return "unknown";
        }
    }

protected:
    // Generic coercion exception
    void except_type_mismatch(TrackerType t) {
        if (type != t) {
            string w = "element type mismatch, is " + type_to_string(this->type) + " tried to use as " + type_to_string(t);

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

    void *custom_value;
};

// Templated access functions

template<typename T> T GetTrackerValue(TrackerElement *);

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

#endif
