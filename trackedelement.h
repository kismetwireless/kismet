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
    friend std::istream& operator>>(std::istream& is, device_key& k);

    device_key();

    device_key(const device_key& k);

    // Create a key from a computed phy hash and a mac address
    device_key(uint32_t in_pkey, mac_addr in_device);

    // Create a key from a computed phy hash and a computed mac address
    device_key(uint32_t in_pkey, uint64_t in_device);

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
std::istream& operator>>(std::istream& is, device_key& k);

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

    // "Complex-Scalar" types provide memory-efficient maps for specific collections
    // of data Kismet uses; RRDs use vectors of doubles and frequency counting use maps
    // of double:double, both of which benefit greatly from not tracking element fields for 
    // the collected types.
    
    // Vector of scalar double, not object, values
    TrackerVectorDouble = 22,

    // Map of double:double, not object, values
    TrackerDoubleMapDouble = 23,

    // Vector of strings
    TrackerVectorString = 24,

    // Hash-keyed map, using size_t as the keying element
    TrackerHashkeyMap = 25,
};

class TrackerElement {
public:
    TrackerElement() = delete;

    TrackerElement(TrackerType t) : 
        type(t),
        tracked_id(-1) { }

    TrackerElement(TrackerType t, int id) :
        type(t),
        tracked_id(id) { }

    virtual ~TrackerElement() { };

    // Factory-style for easily making more of the same if we're subclassed
    virtual std::unique_ptr<TrackerElement> clone_type() {
        return nullptr;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) {
        return nullptr;
    }

    // Called prior to serialization output
    virtual void pre_serialize() { }

    // Called after serialization is completed
    virtual void post_serialize() { }

    template<typename CT>
    static std::shared_ptr<CT> safe_cast_as(std::shared_ptr<TrackerElement> e) {
        if (e == nullptr)
            throw std::runtime_error(fmt::format("null trackedelement can not be safely cast"));

#if TE_TYPE_SAFETY == 1
        if (e->get_type() != CT::static_type())
            throw std::runtime_error(fmt::format("trackedelement can not safely cast a {} to a {}",
                        e->get_type_as_string(), type_to_string(CT::static_type())));
#endif

        return std::static_pointer_cast<CT>(e);
    }

    virtual uint32_t get_signature() const {
        return static_cast<uint32_t>(type);
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

    static std::string type_to_string(TrackerType t);
    static TrackerType typestring_to_type(const std::string& s);
    static std::string type_to_typestring(TrackerType t);

    void enforce_type(TrackerType t) {
        if (get_type() != t) 
            throw std::runtime_error(fmt::format("invalid trackedelement access id {}, cannot use a {} "
                        "as a {}", tracked_id, type_to_string(get_type()), type_to_string(t)));
    }

    static void enforce_type(TrackerType t1, TrackerType t2) {
        if (t1 != t2)
            throw std::runtime_error(fmt::format("invalid trackedlement access, cannot use a {} "
                        "as a {}", type_to_string(t1), type_to_string(t2)));
    }

protected:
    TrackerType type;
    int tracked_id;

    // Overridden name for this instance only
    std::string local_name;
};

// Generator function for making various elements
template<typename SUB, typename... Args>
std::unique_ptr<TrackerElement> TrackerElementFactory(const Args& ... args) {
    auto dup = std::unique_ptr<SUB>(new SUB(args...));
    return std::move(dup);
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

    inline bool operator<(const TrackerElementCoreScalar<P>& rhs) const {
        return value < rhs.value;
    }

    inline bool operator<(const std::shared_ptr<TrackerElement> rhs) const {
        if (get_type() != rhs->get_type())
            throw std::runtime_error(fmt::format("Attempted to compare two non-equal field types, "
                        "{} < {}", get_type_as_string(), rhs->get_type_as_string()));

        return value < std::static_pointer_cast<TrackerElementCoreScalar<P>>(rhs)->value;
    }

    
    inline bool less_than(const TrackerElementCoreScalar<P>& rhs) const {
        return value < rhs.value;
    }

    inline bool less_than(const std::shared_ptr<TrackerElement> rhs) const {
        if (get_type() != rhs->get_type())
            throw std::runtime_error(fmt::format("Attempted to compare two non-equal field types, "
                        "{} < {}", get_type_as_string(), rhs->get_type_as_string()));

        return value < safe_cast_as<TrackerElementCoreScalar<P>>(rhs)->value;
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

    static TrackerType static_type() {
        return TrackerType::TrackerString;
    }

    virtual void coercive_set(const std::string& in_str) override;
    virtual void coercive_set(double in_num) override;
    virtual void coercive_set(const SharedTrackerElement& e) override;

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    using TrackerElementCoreScalar<std::string>::less_than;
    inline bool less_than(const TrackerElementString& rhs) const;

};

class TrackerElementByteArray : public TrackerElementCoreScalar<std::string> {
public:
    TrackerElementByteArray() :
        TrackerElementCoreScalar<std::string>(TrackerType::TrackerByteArray) { }

    TrackerElementByteArray(int id) :
        TrackerElementCoreScalar<std::string>(TrackerType::TrackerByteArray, id) { }

    TrackerElementByteArray(int id, const std::string& s) :
        TrackerElementCoreScalar<std::string>(TrackerType::TrackerString, id, s) { }

    static TrackerType static_type() {
        return TrackerType::TrackerByteArray;
    }

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
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
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
        TrackerElementCoreScalar<device_key>(TrackerType::TrackerKey, id) { }

    static TrackerType static_type() {
        return TrackerType::TrackerKey;
    }

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
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }
};

class TrackerElementUUID : public TrackerElementCoreScalar<uuid> {
public:
    TrackerElementUUID() :
        TrackerElementCoreScalar<uuid>(TrackerType::TrackerUuid) { }

    TrackerElementUUID(int id) :
        TrackerElementCoreScalar<uuid>(TrackerType::TrackerUuid, id) { }

    TrackerElementUUID(int id, const uuid& u) :
        TrackerElementCoreScalar<uuid>(TrackerType::TrackerUuid, id, u) { }

    static TrackerType static_type() {
        return TrackerType::TrackerUuid;
    }

    virtual void coercive_set(const std::string& in_str) override;
    virtual void coercive_set(double in_num) override;
    virtual void coercive_set(const SharedTrackerElement& e) override;

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
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

    static TrackerType static_type() {
        return TrackerType::TrackerMac;
    }

    virtual void coercive_set(const std::string& in_str) override;
    virtual void coercive_set(double in_num) override;
    virtual void coercive_set(const SharedTrackerElement& e) override;

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

};

// Simplify numeric conversion w/ an interstitial scalar-like that holds all 
// our numeric subclasses
template<class N>
class TrackerElementCoreNumeric : public TrackerElement {
public:
    TrackerElementCoreNumeric() = delete;

    TrackerElementCoreNumeric(TrackerType t) :
        TrackerElement(t) { 
        value = 0;
    }

    TrackerElementCoreNumeric(TrackerType t, int id) :
        TrackerElement(t, id) { 
        value = 0;
    }

    TrackerElementCoreNumeric(TrackerType t, int id, const N& v) :
        TrackerElement(t, id),
        value(v) { }

    virtual void coercive_set(const std::string& in_str) override {
        // Inefficient workaround for compilers that don't define std::stod properly
        // auto d = std::stod(in_str);
        
        std::stringstream ss(in_str);
        double d;

        ss >> d;

        if (ss.fail())
            throw std::runtime_error("could not convert string to numeric");

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
    virtual std::unique_ptr<TrackerElement> clone_type() override {
        return nullptr;
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        return nullptr;
    }

    N& get() {
        return value;
    }

    void set(const N& in) {
        value = in;
    }

    inline bool operator==(const TrackerElementCoreNumeric<N>& rhs) const { 
        return value == rhs.value;
    }

    inline bool operator==(const N& rhs) const {
        return value != rhs;
    }

    inline bool operator!=(const TrackerElementCoreNumeric<N>& rhs) const { 
        return !(value == rhs.value); 
    }

    inline bool operator!=(const N& rhs) const {
        return value != rhs;
    }

    inline bool operator<=(const TrackerElementCoreNumeric<N>& rhs) const {
        return value <= rhs.value;
    }

    inline bool operator<=(const N& rhs) const {
        return value <= rhs;
    }

    inline bool operator<(const TrackerElementCoreNumeric<N>& rhs) const {
        return value < rhs.value;
    }

    inline bool operator<(const N& rhs) {
        return value < rhs;
    }

    inline bool operator>=(const TrackerElementCoreNumeric<N>& rhs) const {
        return value >= rhs.value;
    }

    inline bool operator>=(const N& rhs) {
        return value >= rhs;
    }

    inline bool operator>(const TrackerElementCoreNumeric<N>& rhs) const {
        return value > rhs.value;
    }

    inline bool operator>(const N& rhs) const {
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

    inline bool less_than(const TrackerElementCoreNumeric<N>& rhs) const {
        return value < rhs.value;
    }

    inline bool less_than(const std::shared_ptr<TrackerElement> rhs) const {
        if (get_type() != rhs->get_type())
            throw std::runtime_error(fmt::format("Attempted to compare two non-equal field types, "
                        "{} < {}", get_type_as_string(), rhs->get_type_as_string()));

        return value < safe_cast_as<TrackerElementCoreNumeric<N>>(rhs)->value;
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

    static TrackerType static_type() {
        return TrackerType::TrackerUInt8;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
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

    static TrackerType static_type() {
        return TrackerType::TrackerInt8;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
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

    static TrackerType static_type() {
        return TrackerType::TrackerUInt16;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
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

    static TrackerType static_type() {
        return TrackerType::TrackerInt16;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
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

    static TrackerType static_type() {
        return TrackerType::TrackerUInt32;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
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

    static TrackerType static_type() {
        return TrackerType::TrackerInt32;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
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

    static TrackerType static_type() {
        return TrackerType::TrackerUInt64;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
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

    static TrackerType static_type() {
        return TrackerType::TrackerInt64;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
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

    static TrackerType static_type() {
        return TrackerType::TrackerFloat;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
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

    static TrackerType static_type() {
        return TrackerType::TrackerDouble;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }
};


// Superclass for generic access to maps via multiple key structures
template <typename K, typename V>
class TrackerElementCoreMap : public TrackerElement {
public:
    using map_t = std::map<K, V>;
    using iterator = typename map_t::iterator;
    using const_iterator = typename map_t::const_iterator;
    using pair = std::pair<K, V>;

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

    bool empty() const noexcept {
        return map.empty();
    }

    void clear() noexcept {
        map.clear();
    }

    size_t size() const {
        return map.size();
    }

    // std::insert methods, does not replace existing objects
    std::pair<iterator, bool> insert(pair p) {
        return map.insert(p);
    }

    std::pair<iterator, bool> insert(const K& i, const V& e) {
        return insert(std::make_pair(i, e));
    }

    // insert, and replace if key is found.  if key is not found, insert
    // as normal.
    std::pair<iterator, bool> replace(pair p) {
        auto k = map.find(p.first);
        if (k != map.end())
            map.erase(k);

        return map.insert(p);
    }

    std::pair<iterator, bool> replace(const K& i, const V& e) {
        auto k = map.find(i);
        if (k != map.end())
            map.erase(k);

        return map.insert(std::make_pair(i, e));
    }

protected:
    map_t map;
};

// Dictionary / map-by-id
class TrackerElementMap : public TrackerElementCoreMap<int, std::shared_ptr<TrackerElement>> {
public:
    TrackerElementMap() :
        TrackerElementCoreMap<int, std::shared_ptr<TrackerElement>>(TrackerType::TrackerMap) { }

    TrackerElementMap(int id) :
        TrackerElementCoreMap<int, std::shared_ptr<TrackerElement>>(TrackerType::TrackerMap, id) { }

    static TrackerType static_type() {
        return TrackerType::TrackerMap;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
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
            auto p = 
                std::make_pair(i, std::static_pointer_cast<TrackerElement>(e));
            return map.insert(p);
        } else {
            existing->second = std::static_pointer_cast<TrackerElement>(e);
            return std::make_pair(existing, true);
        }
    }

    iterator erase(SharedTrackerElement e) {
        if (e == nullptr)
            throw std::runtime_error("Attempted to erase null value from map");

        auto i = map.find(e->get_id());

        if (i != map.end())
            return map.erase(i);

        return i;
    }
};

// Int-keyed map
class TrackerElementIntMap : public TrackerElementCoreMap<int, std::shared_ptr<TrackerElement>> {
public:
    TrackerElementIntMap() :
        TrackerElementCoreMap<int, std::shared_ptr<TrackerElement>>(TrackerType::TrackerIntMap) { }

    TrackerElementIntMap(int id) :
        TrackerElementCoreMap<int, std::shared_ptr<TrackerElement>>(TrackerType::TrackerIntMap, id) { }

    static TrackerType static_type() {
        return TrackerType::TrackerIntMap;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

};

// Hash key compatible map
class TrackerElementHashkeyMap : public TrackerElementCoreMap<size_t, std::shared_ptr<TrackerElement>> {
public:
    TrackerElementHashkeyMap() :
        TrackerElementCoreMap<size_t, std::shared_ptr<TrackerElement>>(TrackerType::TrackerHashkeyMap) { }

    TrackerElementHashkeyMap(int id) :
        TrackerElementCoreMap<size_t, std::shared_ptr<TrackerElement>>(TrackerType::TrackerHashkeyMap, id) { }

    static TrackerType static_type() {
        return TrackerType::TrackerIntMap;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

};

// Double-keyed map
class TrackerElementDoubleMap : public TrackerElementCoreMap<double, std::shared_ptr<TrackerElement>> {
public:
    TrackerElementDoubleMap() :
        TrackerElementCoreMap<double, std::shared_ptr<TrackerElement>>(TrackerType::TrackerDoubleMap) { }

    TrackerElementDoubleMap(int id) :
        TrackerElementCoreMap<double, std::shared_ptr<TrackerElement>>(TrackerType::TrackerDoubleMap, id) { }

    static TrackerType static_type() {
        return TrackerType::TrackerDoubleMap;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }
};

// Mac-keyed map
class TrackerElementMacMap : public TrackerElementCoreMap<mac_addr, std::shared_ptr<TrackerElement>> {
public:
    TrackerElementMacMap() :
        TrackerElementCoreMap<mac_addr, std::shared_ptr<TrackerElement>>(TrackerType::TrackerMacMap) { }

    TrackerElementMacMap(int id) :
        TrackerElementCoreMap<mac_addr, std::shared_ptr<TrackerElement>>(TrackerType::TrackerMacMap, id) { }

    static TrackerType static_type() {
        return TrackerType::TrackerMacMap;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }
};

// String-keyed map
class TrackerElementStringMap : public TrackerElementCoreMap<std::string, std::shared_ptr<TrackerElement>> {
public:
    TrackerElementStringMap() :
        TrackerElementCoreMap<std::string, std::shared_ptr<TrackerElement>>(TrackerType::TrackerStringMap) { }

    TrackerElementStringMap(int id) :
        TrackerElementCoreMap<std::string, std::shared_ptr<TrackerElement>>(TrackerType::TrackerStringMap, id) { }

    static TrackerType static_type() {
        return TrackerType::TrackerStringMap;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }
};

// Device-key map
class TrackerElementDeviceKeyMap : public TrackerElementCoreMap<device_key, std::shared_ptr<TrackerElement>> {
public:
    TrackerElementDeviceKeyMap() :
        TrackerElementCoreMap<device_key, std::shared_ptr<TrackerElement>>(TrackerType::TrackerKeyMap) { }

    TrackerElementDeviceKeyMap(int id) :
        TrackerElementCoreMap<device_key, std::shared_ptr<TrackerElement>>(TrackerType::TrackerKeyMap, id) { }

    static TrackerType static_type() {
        return TrackerType::TrackerKeyMap;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }
};

// Double::Double map
class TrackerElementDoubleMapDouble : public TrackerElementCoreMap<double, double> {
public:
    TrackerElementDoubleMapDouble() :
        TrackerElementCoreMap<double, double>(TrackerType::TrackerDoubleMapDouble) { }

    TrackerElementDoubleMapDouble(int id) :
        TrackerElementCoreMap<double, double>(TrackerType::TrackerDoubleMapDouble, id) { }

    static TrackerType static_type() {
        return TrackerType::TrackerDoubleMapDouble;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }
};

// Core vector
template<typename T>
class TrackerElementCoreVector : public TrackerElement {
public:
    using vector_t = std::vector<T>;
    using iterator = typename vector_t::iterator;
    using const_iterator = typename vector_t::const_iterator;

    TrackerElementCoreVector() = delete;

    TrackerElementCoreVector(TrackerType t) :
        TrackerElement(t) { }

    TrackerElementCoreVector(TrackerType t, int id) :
        TrackerElement(t, id) { }

    virtual void coercive_set(const std::string& in_str) override {
        throw(std::runtime_error("Cannot coercive_set a scalar vector from a string"));
    }

    virtual void coercive_set(double in_num) override {
        throw(std::runtime_error("Cannot coercive_set a scalar vector from a numeric"));
    }

    // Attempt to coerce one complete item to another
    virtual void coercive_set(const SharedTrackerElement& in_elem) override {
        throw(std::runtime_error("Cannot coercive_set a scalar vector from an element"));
    }

    virtual void set(const_iterator a, const_iterator b) {
        vector = vector_t(a, b);
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

    iterator erase(iterator i) {
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

    size_t size() const {
        return vector.size();
    }

    T& operator[](size_t pos) {
        return vector[pos];
    }

    void push_back(const T& v) {
        vector.push_back(v);
    }

    void push_back(const T&& v) {
        vector.push_back(v);
    }

    template<class... Args >
    void emplace_back( Args&&... args ) {
        vector.emplace_back(args...);
    }

protected:
    vector_t vector;
};

class TrackerElementVector : public TrackerElementCoreVector<std::shared_ptr<TrackerElement>> {
public:
    TrackerElementVector() : 
        TrackerElementCoreVector(TrackerType::TrackerVector) { }

    TrackerElementVector(int id) :
        TrackerElementCoreVector(TrackerType::TrackerVector, id) { }

    TrackerElementVector(std::shared_ptr<TrackerElementVector> v) :
        TrackerElementCoreVector(TrackerType::TrackerVector, v->get_id()) { 
        vector = vector_t(v->begin(), v->end());
    }

    TrackerElementVector(const_iterator a, const_iterator b) :
        TrackerElementCoreVector(TrackerType::TrackerVector) { 
        vector = vector_t(a, b);
    }

    static TrackerType static_type() {
        return TrackerType::TrackerVector;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }
};

class TrackerElementVectorDouble : public TrackerElementCoreVector<double> {
public:
    TrackerElementVectorDouble() :
        TrackerElementCoreVector<double>(TrackerType::TrackerVectorDouble) { }

    TrackerElementVectorDouble(int id) :
        TrackerElementCoreVector<double>(TrackerType::TrackerVectorDouble, id) { }

    TrackerElementVectorDouble(std::shared_ptr<TrackerElementVectorDouble> v) :
        TrackerElementCoreVector(TrackerType::TrackerVector, v->get_id()) { 
        vector = v->vector;
    }

    TrackerElementVectorDouble(const_iterator a, const_iterator b) :
        TrackerElementCoreVector(TrackerType::TrackerVector) { 
        vector = vector_t(a, b);
    }

    TrackerElementVectorDouble(const vector_t& v) :
        TrackerElementCoreVector(TrackerType::TrackerVector) {
        vector = vector_t(v);
    }

    static TrackerType static_type() {
        return TrackerType::TrackerVectorDouble;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }
};

class TrackerElementVectorString : public TrackerElementCoreVector<std::string> {
public:
    TrackerElementVectorString() :
        TrackerElementCoreVector<std::string>(TrackerType::TrackerVectorString) { }

    TrackerElementVectorString(int id) :
        TrackerElementCoreVector<std::string>(TrackerType::TrackerVectorString, id) { }

    TrackerElementVectorString(std::shared_ptr<TrackerElementVectorString> v) :
        TrackerElementCoreVector(TrackerType::TrackerVector, v->get_id()) { 
        vector = v->vector;
    }

    TrackerElementVectorString(const_iterator a, const_iterator b) :
        TrackerElementCoreVector(TrackerType::TrackerVector) { 
        vector = vector_t(a, b);
    }

    static TrackerType static_type() {
        return TrackerType::TrackerVectorString;
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }
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

class TrackerElementSummary;
using SharedElementSummary =  std::shared_ptr<TrackerElementSummary>;

// Element simplification record for summarizing and simplifying records
class TrackerElementSummary {
public:
    TrackerElementSummary(const std::string& in_path, const std::string& in_rename);

    TrackerElementSummary(const std::vector<std::string>& in_path, const std::string& in_rename);

    TrackerElementSummary(const std::string& in_path);

    TrackerElementSummary(const std::vector<std::string>& in_path);

    TrackerElementSummary(const std::vector<int>& in_path, const std::string& in_rename);
    TrackerElementSummary(const std::vector<int>& in_path);

    // copy constructor
    TrackerElementSummary(const SharedElementSummary& in_c);

    SharedTrackerElement parent_element;
    std::vector<int> resolved_path;
    std::string rename;

protected:
    void parse_path(const std::vector<std::string>& in_path, const std::string& in_rename);
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
SharedTrackerElement GetTrackerElementPath(const std::string& in_path, SharedTrackerElement elem);
// Split std::string path
SharedTrackerElement GetTrackerElementPath(const std::vector<std::string>& in_path, 
        SharedTrackerElement elem);
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
        SharedTrackerElement elem);
// Split std::string path
std::vector<SharedTrackerElement> GetTrackerElementMultiPath(const std::vector<std::string>& in_path, 
        SharedTrackerElement elem);
// Resolved field ID path
std::vector<SharedTrackerElement> GetTrackerElementMultiPath(const std::vector<int>& in_path, 
        SharedTrackerElement elem);

// Summarize a complex record using a collection of summary elements.  The summarized
// element is returned, and the rename mapping for serialization is updated in rename.
// When passed a vector, returns a vector of simplified objects.
std::shared_ptr<TrackerElement> SummarizeTrackerElement(SharedTrackerElement in, 
        const std::vector<SharedElementSummary>& in_summarization, 
        std::shared_ptr<TrackerElementSerializer::rename_map> rename_map);

// Summarize a complex record using a collection of summary elements.  The summarized
// element is returned, and the rename mapping for serialization is updated in rename.
// DOES NOT descend into vectors, only performs summarization on the object provided.
std::shared_ptr<TrackerElement> SummarizeSingleTrackerElement(SharedTrackerElement in, 
        const std::vector<SharedElementSummary>& in_summarization, 
        std::shared_ptr<TrackerElementSerializer::rename_map> rename_map);

// Handle comparing fields
bool SortTrackerElementLess(const std::shared_ptr<TrackerElement> lhs, 
        const std::shared_ptr<TrackerElement> rhs);

// Compare fields, in a faster, but not type-safe, way.  This should be used only when
// the caller is positive that both fields are of the same type, but avoids a number of
// compares.
bool FastSortTrackerElementLess(const std::shared_ptr<TrackerElement> lhs, 
        const std::shared_ptr<TrackerElement> rhs) noexcept;

#endif
