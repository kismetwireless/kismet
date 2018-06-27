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

#include <memory>

#include "fmt.h"

#include "kis_mutex.h"
#include "macaddr.h"
#include "uuid.h"

// Set this to 0 to disable type safety; this stops Kismet from validating that the
// tracked element validates properly against the requested type; this will definitely
// lead to segfaults if the element does not.
//
// On the flip side, validating the type is one of the most commonly called 
// functions, and if this presents a problem, turning off type checking can cull 
// a large percentage of the function calls
#define TE_TYPE_SAFETY  1

class EntryTracker;
class TrackerElement;

using SharedTrackerElement = std::shared_ptr<TrackerElement>;

// Very large key wrapper class, needed for keying devices with per-server/per-phy 
// but consistent keys.  Components are store in big-endian format internally so that
// they are consistent across platforms.
//
// Values are exported as big endian, hex, [SPKEY]_[DKEY]
class device_key {
public:
    friend bool operator <(const device_key& x, const device_key& y);
    friend bool operator ==(const device_key& x, const device_key& y);
    friend std::ostream& operator<<(std::ostream& os, const device_key& k);

    device_key();

    device_key(const device_key& k);

    // Create a key from a server/phy component and device component
    device_key(uint64_t in_spkey, uint64_t in_dkey);

    // Create a key from independent components
    device_key(uint32_t in_skey, uint32_t in_pkey, uint64_t in_dkey);

    // Create a key from a cached spkey and a mac address
    device_key(uint64_t in_spkey, mac_addr in_device);

    // Create a key from a computed hashes and a mac address
    device_key(uint32_t in_skey, uint32_t in_pkey, mac_addr in_device);

    // Create a key from an incoming string/exported key; this should only happen during
    // deserialization and rest queries; it's fairly expensive otherwise
    device_key(std::string in_keystr);

    std::string as_string() const;

    // Generate a cached phykey component; phyhandlers do this to cache
    static uint32_t gen_pkey(std::string in_phy);

    // Generate a cached SP key combination
    static uint64_t gen_spkey(uuid s_uuid, std::string phy);

    bool get_error() { return error; }

protected:
    uint64_t spkey, dkey;
    bool error;
};

bool operator <(const device_key& x, const device_key& y);
bool operator ==(const device_key& x, const device_key& y);
std::ostream& operator<<(std::ostream& os, const device_key& k);

// Types of fields we can track and automatically resolve
// Statically assigned type numbers which MUST NOT CHANGE as things go forwards for 
// binary/fast serialization, new types must be added to the end of the list
enum class TrackerType {
    TrackerString = 0,

    TrackerInt8 = 1, 
    TrackerUInt8 = 2,

    TrackerInt16 = 3, 
    TrackerUInt16 = 4,

    TrackerInt32 = 5, 
    TrackerUInt32 = 6,

    TrackerInt64 = 7,
    TrackerUInt64 = 8,

    TrackerFloat = 9,
    TrackerDouble = 10,

    // Less basic types
    TrackerMac = 11, 
    TrackerUuid = 12,

    // Vector and named map
    TrackerVector = 13, 
    TrackerMap = 14,

    // unsigned integer map (int-keyed data not field-keyed)
    TrackerIntMap = 15,

    // Mac map (mac-keyed tracker data)
    TrackerMacMap = 16,

    // String-keyed map
    TrackerStringMap = 17,
    
    // Double-keyed map
    TrackerDoubleMap = 18,

    // Byte array
    TrackerByteArray = 19,

    // Large key
    TrackerKey = 20,

    // Key-map (Large keys, 128 bit or higher, using the TrackedKey class)
    TrackerKeyMap = 21,
};

class TrackerElement {
public:
    TrackerElement() = delete;

    TrackerElement(TrackerType t) : 
        type(t),
        tracked_id(-1), 
        signature(static_cast<uint32_t>(t)) { }

    TrackerElement(TrackerType t, int id) :
        type(t),
        tracked_id(id),
        signature(static_cast<uint32_t>(t)) { }

    virtual ~TrackerElement() { };

    TrackerElement(TrackerElement&&) = default;
    TrackerElement& operator=(TrackerElement&&) = default;

    TrackerElement(TrackerElement&) = delete;
    TrackerElement& operator=(TrackerElement&) = delete;

    // Factory-style for easily making more of the same if we're subclassed
    virtual std::unique_ptr<TrackerElement> clone_type() = 0;
    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) = 0;

    // Called prior to serialization output
    virtual void pre_serialize() { }

    // Called after serialization is completed
    virtual void post_serialize() { }

    uint32_t get_signature() const {
        return signature;
    }

    int get_id() const {
        return tracked_id;
    }

    void set_id(int id) {
        tracked_id = id;
    }

    void set_local_name(const std::string& in_name) {
        local_name = in_name;
    }

    std::string get_local_name() {
        return local_name;
    }

    void set_type(TrackerType type);

    TrackerType get_type() const { 
        return type; 
    }

    std::string get_type_as_string() const {
        return type_to_string(get_type());
    }

    // Coercive set - attempt to fit incoming data into the type (for basic types)
    // Set string values - usable for strings, macs, UUIDs
    virtual void coercive_set(const std::string& in_str) = 0;
    // Set numerical values - usable for all numeric types
    virtual void coercive_set(double in_num) = 0;
    // Attempt to coerce one complete item to another
    virtual void coercive_set(const SharedTrackerElement& in_elem) = 0;

    size_t size();

    static std::string type_to_string(TrackerType t);
    static TrackerType typestring_to_type(const std::string& s);
    static std::string type_to_typestring(TrackerType t);

    void enforce_type(TrackerType t) {
        if (get_type() != t) 
            throw std::runtime_error(fmt::format("invalid trackedelement access, cannot use a {} "
                        "as a {}", type_to_string(get_type()), type_to_string(t)));
    }

    static void enforce_type(TrackerType t1, TrackerType t2) {
        if (t1 != t2)
            throw std::runtime_error(fmt::format("invalid trackedlement access, cannot use a {} "
                        "as a {}", type_to_string(t1), type_to_string(t2)));
    }

protected:
    TrackerType type;
    int tracked_id;

    uint32_t signature;

    // Overridden name for this instance only
    std::string local_name;
};

// Generator function for making various elements
template<typename SUB, typename... Args>
std::unique_ptr<TrackerElement> TrackerElementFactory(const Args& ... args) {
    auto dup = std::unique_ptr<SUB>(new SUB(args...));
    return dup;
}

// Superclass for generic components for pod-like scalar attributes, though
// they don't need to be explicitly POD
template <class P>
class TrackerElementCoreScalar : public TrackerElement {
public:
    TrackerElementCoreScalar() = delete;

    TrackerElementCoreScalar(TrackerType t) :
        TrackerElement(t) { }

    TrackerElementCoreScalar(TrackerType t, int id) :
        TrackerElement(t, id) { }

    TrackerElementCoreScalar(TrackerType t, int id, const P& v) :
        TrackerElement(t, id),
        value(v) { }

    // We don't define coercion, subclasses have to do that
    virtual void coercive_set(const std::string& in_str) override = 0;
    virtual void coercive_set(double in_num) override = 0;
    virtual void coercive_set(const SharedTrackerElement& in_elem) override = 0;

    // We don't define cloning, subclasses have to do that
    virtual std::unique_ptr<TrackerElement> clone_type() override = 0;
    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override = 0;

    P& get() {
        return value;
    }

    void set(const P& in) {
        value = in;
    }


protected:
    P value;

};

class TrackerElementString : public TrackerElementCoreScalar<std::string> {
public:
    TrackerElementString() :
        TrackerElementCoreScalar<std::string>(TrackerType::TrackerString) { }

    TrackerElementString(int id) :
        TrackerElementCoreScalar<std::string>(TrackerType::TrackerString, id) { }

    TrackerElementString(int id, const std::string& s) :
        TrackerElementCoreScalar<std::string>(TrackerType::TrackerString, id, s) { }

    virtual void coercive_set(const std::string& in_str) override;
    virtual void coercive_set(double in_num) override;
    virtual void coercive_set(const SharedTrackerElement& e) override;

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }

};

class TrackerElementByteArray : public TrackerElementCoreScalar<std::string> {
public:
    TrackerElementByteArray() :
        TrackerElementCoreScalar<std::string>(TrackerType::TrackerByteArray) { }

    TrackerElementByteArray(int id) :
        TrackerElementCoreScalar<std::string>(TrackerType::TrackerByteArray, id) { }

    TrackerElementByteArray(int id, const std::string& s) :
        TrackerElementCoreScalar<std::string>(TrackerType::TrackerString, id, s) { }

    virtual void coercive_set(const std::string& in_str) override {
        value = in_str;
    }

    virtual void coercive_set(double in_num) override {
        throw(std::runtime_error("Cannot coercive_set a bytearray from a numeric"));
    }

    virtual void coercive_set(const SharedTrackerElement& e) override {
        throw(std::runtime_error("Cannot coercive_set a bytearray from an element"));
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }

    template<typename T>
    void set(const T& v) {
        value = std::string(v);
    }

    void set(const uint8_t* v, size_t len) {
        value = std::string((const char *) v, len);
    }

    void set(const char *v, size_t len) {
        value = std::string(v, len);
    }

    size_t length() const {
        return value.length();
    }

    std::string to_hex() const {
        std::stringstream ss;
        auto fflags = ss.flags();

        ss << std::uppercase << std::setfill('0') << std::setw(2) << std::hex;

        for (size_t i = 0; i < value.length(); i++) 
            ss << value.data()[i];

        ss.flags(fflags);

        return ss.str();
    }

};

class TrackerElementDeviceKey : public TrackerElementCoreScalar<device_key> {
public:
    TrackerElementDeviceKey() :
        TrackerElementCoreScalar<device_key>(TrackerType::TrackerKey) { }

    TrackerElementDeviceKey(int id) :
        TrackerElementCoreScalar<device_key>(TrackerType::TrackerKey) { }

    virtual void coercive_set(const std::string& in_str) override {
        throw(std::runtime_error("Cannot coercive_set a devicekey from a string"));
    }

    virtual void coercive_set(double in_num) override {
        throw(std::runtime_error("Cannot coercive_set a devicekey from a numeric"));
    }

    // Attempt to coerce one complete item to another
    virtual void coercive_set(const SharedTrackerElement& in_elem) override {
        throw(std::runtime_error("Cannot coercive_set a devicekey from an element"));
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }
};

class TrackerElementUUID : public TrackerElementCoreScalar<uuid> {
public:
    TrackerElementUUID() :
        TrackerElementCoreScalar<uuid>(TrackerType::TrackerUuid) { }

    TrackerElementUUID(int id) :
        TrackerElementCoreScalar<uuid>(TrackerType::TrackerUuid, id) { }

    virtual void coercive_set(const std::string& in_str) override;
    virtual void coercive_set(double in_num) override;
    virtual void coercive_set(const SharedTrackerElement& e) override;

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }

};

class TrackerElementMacAddr : public TrackerElementCoreScalar<mac_addr> {
public:
    TrackerElementMacAddr() :
        TrackerElementCoreScalar<mac_addr>(TrackerType::TrackerMac) { }

    TrackerElementMacAddr(int id) :
        TrackerElementCoreScalar<mac_addr>(TrackerType::TrackerMac, id) { }

    TrackerElementMacAddr(int id, const std::string& s) :
        TrackerElementCoreScalar<mac_addr>(TrackerType::TrackerMac, id, mac_addr(s)) { }

    TrackerElementMacAddr(int id, const mac_addr& m) :
        TrackerElementCoreScalar<mac_addr>(TrackerType::TrackerMac, id, m) { }

    virtual void coercive_set(const std::string& in_str) override;
    virtual void coercive_set(double in_num) override;
    virtual void coercive_set(const SharedTrackerElement& e) override;

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }

};

// Simplify numeric conversion w/ an interstitial scalar-like that holds all 
// our numeric subclasses
template<class N>
class TrackerElementCoreNumeric : public TrackerElement {
public:
    TrackerElementCoreNumeric() = delete;

    TrackerElementCoreNumeric(TrackerType t) :
        TrackerElement(t) { }

    TrackerElementCoreNumeric(TrackerType t, int id) :
        TrackerElement(t, id) { }

    TrackerElementCoreNumeric(TrackerType t, int id, const N& v) :
        TrackerElement(t, id),
        value(v) { }

    virtual void coercive_set(const std::string& in_str) override {
        auto d = std::stod(in_str);
        coercive_set(d);
    }

    virtual void coercive_set(double in_num) override {
        if (in_num < value_min || in_num > value_max)
            throw std::runtime_error(fmt::format("cannot coerce to {}, number out of range",
                        this->get_type_as_string()));

        this->value = static_cast<N>(in_num);
    }

    virtual void coercive_set(const SharedTrackerElement& e) override {
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
                coercive_set(std::static_pointer_cast<TrackerElementCoreNumeric>(e)->get());
                break;
            case TrackerType::TrackerString:
                coercive_set(std::static_pointer_cast<TrackerElementString>(e)->get());
                break;
            default:
                throw std::runtime_error(fmt::format("Could not coerce {} to {}",
                            e->get_type_as_string(), this->get_type_as_string()));
        }
    }

    // We don't define cloning, subclasses have to do that
    virtual std::unique_ptr<TrackerElement> clone_type() override = 0;
    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override = 0;

    N& get() {
        return value;
    }

    void set(const N& in) {
        value = in;
    }

    inline bool operator==(const TrackerElementCoreNumeric<N>& rhs) const { 
        return value == rhs.value;
    }

    inline bool operator==(const N& rhs) {
        return value != rhs;
    }

    inline bool operator!=(const TrackerElementCoreNumeric<N>& rhs) { 
        return !(value == rhs.value); 
    }

    inline bool operator!=(const N& rhs) {
        return value != rhs;
    }

    inline bool operator<=(const TrackerElementCoreNumeric<N>& rhs) {
        return value <= rhs.value;
    }

    inline bool operator<=(const N& rhs) {
        return value <= rhs;
    }

    inline bool operator<(const TrackerElementCoreNumeric<N>& rhs) {
        return value < rhs.value;
    }

    inline bool operator<(const N& rhs) {
        return value < rhs;
    }

    inline bool operator>=(const TrackerElementCoreNumeric<N>& rhs) {
        return value >= rhs.value;
    }

    inline bool operator>=(const N& rhs) {
        return value >= rhs;
    }

    inline bool operator>(const TrackerElementCoreNumeric<N>& rhs) {
        return value > rhs.value;
    }

    inline bool operator>(const N& rhs) {
        return value  > rhs;
    }

    TrackerElementCoreNumeric<N>& operator+=(const N& rhs) {
        value += rhs;
        return *this;
    }

    TrackerElementCoreNumeric<N>& operator-=(const N& rhs) {
        value -= rhs;
        return *this;
    }

    friend TrackerElementCoreNumeric<N> operator+(TrackerElementCoreNumeric lhs,
            const TrackerElementCoreNumeric<N>& rhs) {
        lhs += rhs;
        return lhs;
    }

    friend TrackerElementCoreNumeric<N> operator-(TrackerElementCoreNumeric lhs,
            const TrackerElementCoreNumeric<N>& rhs) {
        lhs -= rhs;
        return lhs;
    }

    TrackerElementCoreNumeric<N>& operator|=(const TrackerElementCoreNumeric<N>& rhs) {
        value |= rhs.value;
        return *this;
    }

    TrackerElementCoreNumeric<N>& operator|=(const N& rhs) {
        value |= rhs;
        return *this;
    }

    TrackerElementCoreNumeric<N>& operator&=(const TrackerElementCoreNumeric<N>& rhs) {
        value &= rhs.value;
        return *this;
    }

    TrackerElementCoreNumeric<N>& operator&=(const N& rhs) {
        value &= rhs;
        return *this;
    }

    TrackerElementCoreNumeric<N>& operator^=(const TrackerElementCoreNumeric<N>& rhs) {
        value ^= rhs.value;
        return *this;
    }

    TrackerElementCoreNumeric<N>& operator^=(const N& rhs) {
        value ^= rhs;
        return *this;
    }

protected:
    // Min/max ranges for conversion
    double value_min, value_max;
    N value;
};


class TrackerElementUInt8 : public TrackerElementCoreNumeric<uint8_t> {
public:
    TrackerElementUInt8() :
        TrackerElementCoreNumeric<uint8_t>(TrackerType::TrackerUInt8) {
            value_min = 0;
            value_max = INT8_MAX;
        }

    TrackerElementUInt8(int id) :
        TrackerElementCoreNumeric<uint8_t>(TrackerType::TrackerUInt8, id) {
            value_min = 0;
            value_max = INT8_MAX;
        }

    TrackerElementUInt8(int id, const uint8_t& v) :
        TrackerElementCoreNumeric<uint8_t>(TrackerType::TrackerUInt8, id, v) {
            value_min = 0;
            value_max = INT8_MAX;
        }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }
};

class TrackerElementInt8 : public TrackerElementCoreNumeric<int8_t> {
public:
    TrackerElementInt8() :
        TrackerElementCoreNumeric<int8_t>(TrackerType::TrackerInt8) {
            value_min = INT8_MIN;
            value_max = INT8_MAX;
        }

    TrackerElementInt8(int id) :
        TrackerElementCoreNumeric<int8_t>(TrackerType::TrackerInt8, id) {
            value_min = INT8_MIN;
            value_max = INT8_MAX;
        }

    TrackerElementInt8(int id, const int8_t& v) :
        TrackerElementCoreNumeric<int8_t>(TrackerType::TrackerInt8, id, v) {
            value_min = INT8_MIN;
            value_max = INT8_MAX;
        }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }
};

class TrackerElementUInt16 : public TrackerElementCoreNumeric<uint16_t> {
public:
    TrackerElementUInt16() :
        TrackerElementCoreNumeric<uint16_t>(TrackerType::TrackerUInt16) {
            value_min = 0;
            value_max = UINT16_MAX;
        }

    TrackerElementUInt16(int id) :
        TrackerElementCoreNumeric<uint16_t>(TrackerType::TrackerUInt16, id) {
            value_min = 0;
            value_max = UINT16_MAX;
        }

    TrackerElementUInt16(int id, const uint16_t& v) :
        TrackerElementCoreNumeric<uint16_t>(TrackerType::TrackerUInt16, id, v) {
            value_min = 0;
            value_max = UINT16_MAX;
        }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }
};

class TrackerElementInt16 : public TrackerElementCoreNumeric<int16_t> {
public:
    TrackerElementInt16() :
        TrackerElementCoreNumeric<int16_t>(TrackerType::TrackerInt16) {
            value_min = INT16_MIN;
            value_max = INT16_MAX;
        }

    TrackerElementInt16(int id) :
        TrackerElementCoreNumeric<int16_t>(TrackerType::TrackerInt16, id) {
            value_min = INT16_MIN;
            value_max = INT16_MAX;
        }

    TrackerElementInt16(int id, const int16_t& v) :
        TrackerElementCoreNumeric<int16_t>(TrackerType::TrackerInt16, id, v) {
            value_min = INT16_MIN;
            value_max = INT16_MAX;
        }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }
};

class TrackerElementUInt32 : public TrackerElementCoreNumeric<uint32_t> {
public:
    TrackerElementUInt32() :
        TrackerElementCoreNumeric<uint32_t>(TrackerType::TrackerUInt32) {
            value_min = 0;
            value_max = UINT32_MAX;
        }

    TrackerElementUInt32(int id) :
        TrackerElementCoreNumeric<uint32_t>(TrackerType::TrackerUInt32, id) {
            value_min = 0;
            value_max = UINT32_MAX;
        }

    TrackerElementUInt32(int id, const uint32_t& v) :
        TrackerElementCoreNumeric<uint32_t>(TrackerType::TrackerUInt32, id, v) {
            value_min = 0;
            value_max = UINT32_MAX;
        }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }
};

class TrackerElementInt32 : public TrackerElementCoreNumeric<int32_t> {
public:
    TrackerElementInt32() :
        TrackerElementCoreNumeric<int32_t>(TrackerType::TrackerInt32) {
            value_min = INT32_MIN;
            value_max = INT32_MAX;
        }

    TrackerElementInt32(int id) :
        TrackerElementCoreNumeric<int32_t>(TrackerType::TrackerInt32, id) {
            value_min = INT32_MIN;
            value_max = INT32_MAX;
        }

    TrackerElementInt32(int id, const int32_t& v) :
        TrackerElementCoreNumeric<int32_t>(TrackerType::TrackerInt32, id, v) {
            value_min = INT32_MIN;
            value_max = INT32_MAX;
        }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }
};

class TrackerElementUInt64 : public TrackerElementCoreNumeric<uint64_t> {
public:
    TrackerElementUInt64() :
        TrackerElementCoreNumeric<uint64_t>(TrackerType::TrackerUInt64) {
            value_min = 0;
            value_max = UINT64_MAX;
        }

    TrackerElementUInt64(int id) :
        TrackerElementCoreNumeric<uint64_t>(TrackerType::TrackerUInt64, id) {
            value_min = 0;
            value_max = UINT64_MAX;
        }

    TrackerElementUInt64(int id, const uint64_t& v) :
        TrackerElementCoreNumeric<uint64_t>(TrackerType::TrackerUInt64, id, v) {
            value_min = 0;
            value_max = UINT64_MAX;
        }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }
};

class TrackerElementInt64 : public TrackerElementCoreNumeric<int64_t> {
public:
    TrackerElementInt64() :
        TrackerElementCoreNumeric<int64_t>(TrackerType::TrackerInt64) {
            value_min = INT64_MIN;
            value_max = INT64_MAX;
        }

    TrackerElementInt64(int id) :
        TrackerElementCoreNumeric<int64_t>(TrackerType::TrackerInt64, id) {
            value_min = INT64_MIN;
            value_max = INT64_MAX;
        }

    TrackerElementInt64(int id, const int64_t& v) :
        TrackerElementCoreNumeric<int64_t>(TrackerType::TrackerInt64, id, v) {
            value_min = INT64_MIN;
            value_max = INT64_MAX;
        }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }
};

class TrackerElementFloat : public TrackerElementCoreNumeric<float> {
public:
    TrackerElementFloat() :
        TrackerElementCoreNumeric<float>(TrackerType::TrackerFloat) {
            value_min = std::numeric_limits<float>::min();
            value_max = std::numeric_limits<float>::max();
        }

    TrackerElementFloat(int id) :
        TrackerElementCoreNumeric<float>(TrackerType::TrackerFloat, id) {
            value_min = std::numeric_limits<float>::min();
            value_max = std::numeric_limits<float>::max();
        }

    TrackerElementFloat(int id, const float& v) :
        TrackerElementCoreNumeric<float>(TrackerType::TrackerFloat, id, v) {
            value_min = std::numeric_limits<float>::min();
            value_max = std::numeric_limits<float>::max();
        }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }
};

class TrackerElementDouble : public TrackerElementCoreNumeric<double> {
public:
    TrackerElementDouble() :
        TrackerElementCoreNumeric<double>(TrackerType::TrackerDouble) {
            value_min = std::numeric_limits<double>::min();
            value_max = std::numeric_limits<double>::max();
        }

    TrackerElementDouble(int id) :
        TrackerElementCoreNumeric<double>(TrackerType::TrackerDouble, id) {
            value_min = std::numeric_limits<double>::min();
            value_max = std::numeric_limits<double>::max();
        }

    TrackerElementDouble(int id, const double& v) :
        TrackerElementCoreNumeric<double>(TrackerType::TrackerDouble, id, v) {
            value_min = std::numeric_limits<double>::min();
            value_max = std::numeric_limits<double>::max();
        }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }
};


// Superclass for generic access to maps via multiple key structures
template <class K>
class TrackerElementCoreMap : public TrackerElement {
public:
    using map_t = std::map<K, SharedTrackerElement>;
    using iterator = typename map_t::iterator;
    using const_iterator = typename map_t::const_iterator;
    using pair = std::pair<K, SharedTrackerElement>;

    TrackerElementCoreMap() = delete;

    TrackerElementCoreMap(TrackerType t) : 
        TrackerElement(t) { }

    TrackerElementCoreMap(TrackerType t, int id) :
        TrackerElement(t, id) { }

    virtual void coercive_set(const std::string& in_str) override {
        throw(std::runtime_error("Cannot coercive_set a map from a string"));
    }

    virtual void coercive_set(double in_num) override {
        throw(std::runtime_error("Cannot coercive_set a map from a numeric"));
    }

    // Attempt to coerce one complete item to another
    virtual void coercive_set(const SharedTrackerElement& in_elem) override {
        throw(std::runtime_error("Cannot coercive_set a map from an element"));
    }

    map_t& get() {
        return map;
    }

    iterator begin() {
        return map.begin();
    }

    const_iterator cbegin() {
        return map.cbegin();
    }

    iterator end() {
        return map.end();
    }

    const_iterator cend() {
        return map.cend();
    }

    iterator find(const K& k) {
        return map.find(k);
    }

    const_iterator find(const K& k) const {
        return map.find(k);
    }

    iterator erase(const K& k) {
        iterator i = map.find(k);
        return erase(i);
    }

    iterator erase(const_iterator i) {
        return map.erase(i);
    }

    iterator erase(iterator first, iterator last) {
        return map.erase(first, last);
    }

    iterator erase(SharedTrackerElement e) {
        return map.erase(map.find(e->get_id()));
    }

    bool empty() const noexcept {
        return map.empty();
    }

    void clear() noexcept {
        map.clear();
    }

    std::pair<iterator, bool> insert(pair p) {
        return map.insert(p);
    }

protected:
    std::map<K, SharedTrackerElement> map;
};

// Dictionary / map-by-id
class TrackerElementMap : public TrackerElementCoreMap<int> {
public:
    TrackerElementMap() :
        TrackerElementCoreMap<int>(TrackerType::TrackerMap) {

        }

    TrackerElementMap(int id) :
        TrackerElementCoreMap<int>(TrackerType::TrackerMap, id) {

        }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }

    SharedTrackerElement get_sub(int id) {
        auto v = map.find(id);

        if (v == map.end())
            return NULL;

        return v->second;
    }

    template<typename T>
    std::shared_ptr<T> get_sub_as(int id) {
        auto v = map.find(id);

        if (v == map.end())
            return NULL;

        return std::static_pointer_cast<T>(v->second);
    }

    std::pair<iterator, bool> insert(SharedTrackerElement e) {
        if (e == NULL) 
            throw std::runtime_error("Attempted to insert null TrackerElement with no ID");

        auto existing = map.find(e->get_id());

        if (existing == map.end()) {
            auto p = std::make_pair(e->get_id(), e);
            return map.insert(p);
        } else {
            existing->second = e;
            return std::make_pair(existing, true);
        }
    }

    template<typename TE>
    std::pair<iterator, bool> insert(TE e) {
        if (e == NULL) 
            throw std::runtime_error("Attempted to insert null TrackerElement with no ID");

        auto existing = map.find(e->get_id());

        if (existing == map.end()) {
            auto p = std::make_pair(e->get_id(), std::static_pointer_cast<TrackerElement>(e));
            return map.insert(p);
        } else {
            existing->second = std::static_pointer_cast<TrackerElement>(e);
            return std::make_pair(existing, true);
        }
    }

    template<typename TE>
    std::pair<iterator, bool> insert(int i, TE e) {
        auto existing = map.find(i);

        if (existing == map.end()) {
            auto p = std::make_pair(i, std::static_pointer_cast<TrackerElement>(e));
            return map.insert(p);
        } else {
            existing->second = std::static_pointer_cast<TrackerElement>(e);
            return std::make_pair(existing, true);
        }
    }

};

// Int-keyed map
class TrackerElementIntMap : public TrackerElementCoreMap<int> {
public:
    TrackerElementIntMap() :
        TrackerElementCoreMap<int>(TrackerType::TrackerIntMap) {

        }

    TrackerElementIntMap(int id) :
        TrackerElementCoreMap<int>(TrackerType::TrackerIntMap, id) {

        }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }

};

// Double-keyed map
class TrackerElementDoubleMap : public TrackerElementCoreMap<double> {
public:
    TrackerElementDoubleMap() :
        TrackerElementCoreMap<double>(TrackerType::TrackerDoubleMap) {

        }

    TrackerElementDoubleMap(int id) :
        TrackerElementCoreMap<double>(TrackerType::TrackerDoubleMap, id) {

        }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }
};

// Mac-keyed map
class TrackerElementMacMap : public TrackerElementCoreMap<mac_addr> {
public:
    TrackerElementMacMap() :
        TrackerElementCoreMap<mac_addr>(TrackerType::TrackerMacMap) {

        }

    TrackerElementMacMap(int id) :
        TrackerElementCoreMap<mac_addr>(TrackerType::TrackerMacMap, id) {

        }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }
};

// String-keyed map
class TrackerElementStringMap : public TrackerElementCoreMap<std::string> {
public:
    TrackerElementStringMap() :
        TrackerElementCoreMap<std::string>(TrackerType::TrackerStringMap) {

        }

    TrackerElementStringMap(int id) :
        TrackerElementCoreMap<std::string>(TrackerType::TrackerStringMap, id) {

        }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }
};

// Device-key map
class TrackerElementDeviceKeyMap : public TrackerElementCoreMap<device_key> {
public:
    TrackerElementDeviceKeyMap() :
        TrackerElementCoreMap<device_key>(TrackerType::TrackerKeyMap) { }

    TrackerElementDeviceKeyMap(int id) :
        TrackerElementCoreMap<device_key>(TrackerType::TrackerKeyMap, id) { }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }
};

class TrackerElementVector : public TrackerElement {
public:
    using vector_t = std::vector<SharedTrackerElement>;
    using iterator = vector_t::iterator;
    using const_iterator = vector_t::const_iterator;

    TrackerElementVector() : 
        TrackerElement(TrackerType::TrackerVector) { }

    TrackerElementVector(int id) :
        TrackerElement(TrackerType::TrackerVector, id) { }

    virtual void coercive_set(const std::string& in_str) override {
        throw(std::runtime_error("Cannot coercive_set a vector from a string"));
    }

    virtual void coercive_set(double in_num) override {
        throw(std::runtime_error("Cannot coercive_set a vector from a numeric"));
    }

    // Attempt to coerce one complete item to another
    virtual void coercive_set(const SharedTrackerElement& in_elem) override {
        throw(std::runtime_error("Cannot coercive_set a vector from an element"));
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return dup;
    }

    vector_t& get() {
        return vector;
    }

    iterator begin() {
        return vector.begin();
    }

    const_iterator cbegin() {
        return vector.cbegin();
    }

    iterator end() {
        return vector.end();
    }

    const_iterator cend() {
        return vector.cend();
    }

    iterator erase(const_iterator i) {
        return vector.erase(i);
    }

    iterator erase(iterator first, iterator last) {
        return vector.erase(first, last);
    }

    bool empty() const noexcept {
        return vector.empty();
    }

    void clear() noexcept {
        vector.clear();
    }

    void reserve(size_t cap) {
        vector.reserve(cap);
    }

    SharedTrackerElement& operator[](size_t pos) {
        return vector[pos];
    }

    void push_back(const SharedTrackerElement v) {
        vector.push_back(v);
    }

    void push_back(SharedTrackerElement&& v) {
        vector.push_back(v);
    }

    template<typename TE>
    void push_back(TE v) {
        vector.push_back(std::static_pointer_cast<TrackerElement>(v));
    }

    template<class... Args >
    void emplace_back( Args&&... args ) {
        vector.emplace_back(args...);
    }

protected:
    vector_t vector;
};

// Templated generic access functions

template<typename T> T GetTrackerValue(const SharedTrackerElement&);
template<> std::string GetTrackerValue(const SharedTrackerElement& e);
template<> int8_t GetTrackerValue(const SharedTrackerElement& e);
template<> uint8_t GetTrackerValue(const SharedTrackerElement& e);
template<> int16_t GetTrackerValue(const SharedTrackerElement& e);
template<> uint16_t GetTrackerValue(const SharedTrackerElement& e);
template<> int32_t GetTrackerValue(const SharedTrackerElement& e);
template<> uint32_t GetTrackerValue(const SharedTrackerElement& e);
template<> int64_t GetTrackerValue(const SharedTrackerElement& e);
template<> uint64_t GetTrackerValue(const SharedTrackerElement& e);
template<> float GetTrackerValue(const SharedTrackerElement& e);
template<> double GetTrackerValue(const SharedTrackerElement& e);
template<> mac_addr GetTrackerValue(const SharedTrackerElement& e);
template<> uuid GetTrackerValue(const SharedTrackerElement& e);
template<> device_key GetTrackerValue(const SharedTrackerElement& e);

template<typename T> void SetTrackerValue(const SharedTrackerElement& e, const T& v);
template<> void SetTrackerValue(const SharedTrackerElement& e, const std::string& v);
template<> void SetTrackerValue(const SharedTrackerElement& e, const int8_t& v);
template<> void SetTrackerValue(const SharedTrackerElement& e, const uint8_t& v);
template<> void SetTrackerValue(const SharedTrackerElement& e, const int16_t& v);
template<> void SetTrackerValue(const SharedTrackerElement& e, const uint16_t& v);
template<> void SetTrackerValue(const SharedTrackerElement& e, const int32_t& v);
template<> void SetTrackerValue(const SharedTrackerElement& e, const uint32_t& v);
template<> void SetTrackerValue(const SharedTrackerElement& e, const int64_t& v);
template<> void SetTrackerValue(const SharedTrackerElement& e, const uint64_t& v);
template<> void SetTrackerValue(const SharedTrackerElement& e, const float& v);
template<> void SetTrackerValue(const SharedTrackerElement& e, const double& v);
template<> void SetTrackerValue(const SharedTrackerElement& e, const mac_addr& v);
template<> void SetTrackerValue(const SharedTrackerElement& e, const uuid& v);
template<> void SetTrackerValue(const SharedTrackerElement& e, const device_key& v);

// Complex trackable unit based on trackertype dataunion.
//
// All tracker_components are built from maps.
//
// Tracker components are stored via integer references, but the names are
// mapped via the entrytracker system.
//
// Sub-classes must initialize sub-fields by calling register_fields() in their
// constructors.  The register_fields() function is responsible for defining the
// types and builders, and recording the field_ids for all sub-fields and nested 
// components.
//
// Fields are allocated via the reserve_fields function, which must be called before
// use of the component.  By passing an existing trackermap object, a parsed tree
// can be annealed into the c++ representation without copying/re-parsing the data.
//
// Subclasses MUST override the signature, typically with a checksum of the class
// name, so that the entry tracker can differentiate multiple TrackerMap classes
class tracker_component : public TrackerElementMap {

// Ugly trackercomponent macro for proxying trackerelement values
// Defines get_<name> function, for a TrackerElement of type <ptype>, returning type 
// <rtype>, referencing class variable <cvar>
// Defines set_<name> funciton, for a TrackerElement of type <ptype>, taking type 
// <itype>, which must be castable to the TrackerElement type (itype), referencing 
// class variable <cvar>
#define __Proxy(name, ptype, itype, rtype, cvar) \
    virtual SharedTrackerElement get_tracker_##name() const { \
        return (std::shared_ptr<TrackerElement>) cvar; \
    } \
    virtual rtype get_##name() const { \
        return (rtype) GetTrackerValue<ptype>(cvar); \
    } \
    virtual void set_##name(const itype& in) { \
        SetTrackerValue<ptype>(cvar, static_cast<ptype>(in)); \
    }

// Ugly trackercomponent macro for proxying trackerelement values
// Defines get_<name> function, for a TrackerElement of type <ptype>, returning type 
// <rtype>, referencing class variable <cvar>
// Defines set_<name> funciton, for a TrackerElement of type <ptype>, taking type 
// <itype>, which must be castable to the TrackerElement type (itype), referencing 
// class variable <cvar>, which executes function <lambda> after the set command has
// been executed.  <lambda> should be of the form [](itype) -> bool
// Defines set_only_<name> which sets the trackerelement variable without
// calling the callback function
#define __ProxyL(name, ptype, itype, rtype, cvar, lambda) \
    virtual SharedTrackerElement get_tracker_##name() { \
        return (std::shared_ptr<TrackerElement>) cvar; \
    } \
    virtual rtype get_##name() const { \
        return (rtype) GetTrackerValue<ptype>(cvar); \
    } \
    virtual bool set_##name(const itype& in) { \
        cvar->set((ptype) in); \
        return lambda(in); \
    } \
    virtual void set_only_##name(const itype& in) { \
        cvar->set((ptype) in); \
    }

// Only proxy a Get function
#define __ProxyGet(name, ptype, rtype, cvar) \
    virtual rtype get_##name() { \
        return (rtype) GetTrackerValue<ptype>(cvar); \
    } 

// Only proxy a Set function for overload
#define __ProxySet(name, ptype, stype, cvar) \
    virtual void set_##name(const stype& in) { \
        SetTrackerValue<ptype>(cvar, in); \
    } 

// Proxy a split public/private get/set function; This is even funkier than the 
// normal proxy macro and should only be used in a 'public' segment of the class.
#define __ProxyPrivSplit(name, ptype, itype, rtype, cvar) \
    public: \
    virtual rtype get_##name() { \
        return (rtype) GetTrackerValue<ptype>(cvar); \
    } \
    protected: \
    virtual void set_int_##name(const itype& in) { \
        cvar->set((ptype) in); \
    } \
    public:

// Proxy increment and decrement functions
#define __ProxyIncDec(name, ptype, rtype, cvar) \
    virtual void inc_##name() { \
        (*cvar) += 1; \
    } \
    virtual void inc_##name(rtype i) { \
        (*cvar) += (ptype) i; \
    } \
    virtual void dec_##name() { \
        (*cvar) -= 1; \
    } \
    virtual void dec_##name(rtype i) { \
        (*cvar) -= (ptype) i; \
    }

// Proxy add/subtract
#define __ProxyAddSub(name, ptype, itype, cvar) \
    virtual void add_##name(itype i) { \
        (*cvar) += (ptype) i; \
    } \
    virtual void sub_##name(itype i) { \
        (*cvar) -= (ptype) i; \
    }

// Proxy sub-trackable (name, trackable type, class variable)
#define __ProxyTrackable(name, ttype, cvar) \
    virtual std::shared_ptr<ttype> get_##name() { \
        return cvar; \
    } \
    virtual void set_##name(const std::shared_ptr<ttype>& in) { \
        if (cvar != NULL) \
            erase(cvar->get_id()); \
        cvar = in; \
        if (cvar != NULL) \
            insert(cvar); \
    }  \
    virtual SharedTrackerElement get_tracker_##name() { \
        return std::static_pointer_cast<TrackerElement>(cvar); \
    } 

// Proxy ONLY the get_tracker_* functions
#define __ProxyOnlyTrackable(name, ttype, cvar) \
    virtual SharedTrackerElement get_tracker_##name() { \
        return std::static_pointer_cast<TrackerElement>(cvar); \
    } 

// Proxy sub-trackable (name, trackable type, class variable, set function)
// Returns a shared_ptr instance of a trackable object, or defines a basic
// setting function.  Set function calls lambda, which should be of the signature
// [] (shared_ptr<ttype>) -> bool
#define __ProxyTrackableL(name, ttype, cvar, lambda) \
    virtual std::shared_ptr<ttype> get_##name() { \
        return cvar; \
    } \
    virtual bool set_##name(const shared_ptr<ttype>& in) { \
        if (cvar != NULL) \
            del_map(std::static_pointer_cast<TrackerElement>(cvar)); \
        cvar = in; \
        if (cvar != NULL) \
            add_map(std::static_pointer_cast<TrackerElement>(cvar)); \
        return lambda(in); \
    }  \
    virtual void set_only_##name(const shared_ptr<ttype>& in) { \
        cvar = in; \
    }  \
    virtual SharedTrackerElement get_tracker_##name() { \
        return std::static_pointer_cast<TrackerElement>(cvar); \
    } 


// Proxy dynamic trackable (value in class may be null and is dynamically
// built)
#define __ProxyDynamicTrackable(name, ttype, cvar, id) \
    virtual std::shared_ptr<ttype> get_##name() { \
        if (cvar == NULL) { \
            cvar = std::static_pointer_cast<ttype>(tracker_component::entrytracker->GetSharedInstance(id)); \
            if (cvar != NULL) \
                insert(std::static_pointer_cast<TrackerElement>(cvar)); \
        } \
        return cvar; \
    } \
    virtual void set_tracker_##name(const std::shared_ptr<ttype>& in) { \
        if (cvar != NULL) \
            erase(std::static_pointer_cast<TrackerElement>(cvar)); \
        cvar = in; \
        if (cvar != NULL) { \
            cvar->set_id(id); \
            insert(std::static_pointer_cast<TrackerElement>(cvar)); \
        } \
    } \
    virtual SharedTrackerElement get_tracker_##name() { \
        return std::static_pointer_cast<TrackerElement>(cvar); \
    } \
    virtual bool has_##name() const { \
        return cvar != NULL; \
    }

// Proxy bitset functions (name, trackable type, data type, class var)
#define __ProxyBitset(name, dtype, cvar) \
    virtual void bitset_##name(dtype bs) { \
        (*cvar) |= bs; \
    } \
    virtual void bitclear_##name(dtype bs) { \
        (*cvar) &= ~(bs); \
    } \
    virtual dtype bitcheck_##name(dtype bs) { \
        return (dtype) (GetTrackerValue<dtype>(cvar) & bs); \
    }

public:
    tracker_component(std::shared_ptr<EntryTracker> tracker, int in_id) :
        TrackerElementMap(in_id),
        entrytracker(tracker) {

    }

    tracker_component(std::shared_ptr<EntryTracker> tracker, int in_id, 
            std::shared_ptr<TrackerElementMap> e __attribute__((unused))) :
        TrackerElementMap(in_id),
        entrytracker(tracker) {

    }

	virtual ~tracker_component() { }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(entrytracker, 0));
        return dup;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(entrytracker, in_id));
        return dup;
    }

    tracker_component(tracker_component&&) = default;
    tracker_component& operator=(tracker_component&&) = default;

    tracker_component(tracker_component&) = delete;
    tracker_component& operator=(tracker_component&) = delete;

    // Return the name via the entrytracker
    virtual std::string get_name();

    // Proxy getting any name via entry tracker
    virtual std::string get_name(int in_id);

    SharedTrackerElement get_child_path(const std::string& in_path);
    SharedTrackerElement get_child_path(const std::vector<std::string>& in_path);

protected:
    // Register a field via the entrytracker, using standard entrytracker build methods.
    // This field will be automatically assigned or created during the reservefields 
    // stage.
    //
    // If in_dest is a nullptr, it will not be instantiated; this is useful for registering
    // sub-components of maps which may not be directly instantiated as top-level fields
    int RegisterField(const std::string& in_name, std::unique_ptr<TrackerElement> in_builder,
            const std::string& in_desc, SharedTrackerElement *in_dest = nullptr);

    // Register a field, automatically deriving its type from the provided destination
    // field.  The destination field must be specified.
    template<typename T>
    int RegisterField(const std::string& in_name, const std::string& in_desc, 
            std::shared_ptr<T> *in_dest);

    // Register field types and get a field ID.  Called during record creation, prior to 
    // assigning an existing trackerelement tree or creating a new one
    virtual void register_fields() { }

    // Populate fields - either new (e == NULL) or from an existing structure which
    //  may contain a generic version of our data.
    // When populating from an existing structure, bind each field to this instance so
    //  that we can track usage and delete() appropriately.
    // Populate automatically based on the fields we have reserved, subclasses can 
    // override if they really need to do something special
    virtual void reserve_fields(std::shared_ptr<TrackerElementMap> e);

    // Inherit from an existing element or assign a new one.
    // Add imported or new field to our map for use tracking.
    virtual SharedTrackerElement import_or_new(std::shared_ptr<TrackerElementMap> e, int i);

    class registered_field {
        public:
            registered_field(int id, SharedTrackerElement *assign) { 
                this->id = id; 
                this->assign = assign;
            }

            int id;
            SharedTrackerElement *assign;
    };

    std::shared_ptr<EntryTracker> entrytracker;

    std::vector<std::unique_ptr<registered_field>> registered_fields;
};

class TrackerElementSummary;
using SharedElementSummary =  std::shared_ptr<TrackerElementSummary>;

// Element simplification record for summarizing and simplifying records
class TrackerElementSummary {
public:
    TrackerElementSummary(const std::string& in_path, const std::string& in_rename, 
            std::shared_ptr<EntryTracker> entrytracker);

    TrackerElementSummary(const std::vector<std::string>& in_path, const std::string& in_rename,
            std::shared_ptr<EntryTracker> entrytracker);

    TrackerElementSummary(const std::string& in_path, 
            std::shared_ptr<EntryTracker> entrytracker);

    TrackerElementSummary(const std::vector<std::string>& in_path, 
            std::shared_ptr<EntryTracker> entrytracker);

    TrackerElementSummary(const std::vector<int>& in_path, const std::string& in_rename);
    TrackerElementSummary(const std::vector<int>& in_path);

    // copy constructor
    TrackerElementSummary(const SharedElementSummary& in_c);

    SharedTrackerElement parent_element;
    std::vector<int> resolved_path;
    std::string rename;

protected:
    void parse_path(const std::vector<std::string>& in_path, const std::string& in_rename, 
            std::shared_ptr<EntryTracker> entrytracker);
};

// Generic serializer class to allow easy swapping of serializers
class TrackerElementSerializer {
public:
    TrackerElementSerializer() { }

    using rename_map = std::map<SharedTrackerElement, SharedElementSummary>;

    virtual ~TrackerElementSerializer() {
        local_locker lock(&mutex);
    }

    virtual void serialize(SharedTrackerElement in_elem, 
            std::ostream &stream, std::shared_ptr<rename_map> name_map) = 0;

    // Fields extracted from a summary path need to preserialize their parent
    // paths or updates may not happen in the expected fashion, serializers should
    // call this when necessary
    static void pre_serialize_path(const SharedElementSummary& in_summary);
    static void post_serialize_path(const SharedElementSummary& in_summary);
protected:
    kis_recursive_timed_mutex mutex;
};

// Get an element using path semantics
// Full std::string path
SharedTrackerElement GetTrackerElementPath(const std::string& in_path, 
        SharedTrackerElement elem, std::shared_ptr<EntryTracker> entrytracker);
// Split std::string path
SharedTrackerElement GetTrackerElementPath(const std::vector<std::string>& in_path, 
        SharedTrackerElement elem, std::shared_ptr<EntryTracker> entrytracker);
// Resolved field ID path
SharedTrackerElement GetTrackerElementPath(const std::vector<int>& in_path, 
        SharedTrackerElement elem);

// Get a list of elements from a complex path which may include vectors
// or key maps.  Returns a vector of all elements within that map.
// For example, for a field spec:
// 'dot11.device/dot11.device.advertised.ssid.map/dot11.advertised.ssid'
// it would return a vector of dot11.advertised.ssid for every SSID in
// the dot11.device.advertised.ssid.map keyed map
std::vector<SharedTrackerElement> GetTrackerElementMultiPath(const std::string& in_path,
        SharedTrackerElement elem,
        std::shared_ptr<EntryTracker> entrytracker);
// Split std::string path
std::vector<SharedTrackerElement> GetTrackerElementMultiPath(const std::vector<std::string>& in_path, 
        SharedTrackerElement elem,
        std::shared_ptr<EntryTracker> entrytracker);
// Resolved field ID path
std::vector<SharedTrackerElement> GetTrackerElementMultiPath(const std::vector<int>& in_path, 
        SharedTrackerElement elem);

// Summarize a complex record using a collection of summary elements.  The summarized
// element is returned in ret_elem, and the rename mapping for serialization is
// completed in rename.
void SummarizeTrackerElement(std::shared_ptr<EntryTracker> entrytracker,
        const SharedTrackerElement& in, 
        const std::vector<SharedElementSummary>& in_summarization, 
        SharedTrackerElement &ret_elem, 
        TrackerElementSerializer::rename_map &rename_map);


#endif
