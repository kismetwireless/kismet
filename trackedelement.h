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

class GlobalRegistry;
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
    TrackerUnassigned = -1,

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
    TrackerElement(TrackerType t) : 
        type(t),
        tracked_id(-1) { }

    TrackerElement(TrackerType t, int id) :
        type(t),
        tracked_id(id) { }

    virtual ~TrackerElement() { };

    TrackerElement(TrackerElement&&) = default;
    TrackerElement& operator=(TrackerElement&&) = default;

    TrackerElement(TrackerElement&) = delete;
    TrackerElement& operator=(TrackerElement&) = delete;

    // Factory-style for easily making more of the same if we're subclassed
    virtual std::shared_ptr<TrackerElement> clone_type() = 0;
    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) = 0;

    // Called prior to serialization output
    virtual void pre_serialize() { }

    // Called after serialization is completed
    virtual void post_serialize() { }

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
#if TE_TYPE_SAFETY == 1
        if (get_type() != t) 
            throw std::runtime_error(fmt::format("invalid trackedelement access, cannot use a {} "
                        "as a {}", type_to_string(get_type()), type_to_string(t)));
#endif
    }

    static void enforce_type(TrackerType t1, TrackerType t2) {
#if TE_TYPE_SAFETY == 1
        if (t1 != t2)
            throw std::runtime_error(fmt::format("invalid trackedlement access, cannot use a {} "
                        "as a {}", type_to_string(t1), type_to_string(t2)));
#endif
    }

protected:
    TrackerType type;
    int tracked_id;

    // Overridden name for this instance only
    std::string local_name;
};

// Superclass for generic components for pod-like scalar attributes, though
// they don't need to be explicitly POD
template <class P>
class TrackerElementCoreScalar : public TrackerElement {
public:
    TrackerElementCoreScalar(TrackerType t) :
        TrackerElement(t) { }

    TrackerElementCoreScalar(TrackerType t, int id) :
        TrackerElement(t, id) { }

    // We don't define coercion, subclasses have to do that
    virtual void coercive_set(const std::string& in_str) override = 0;
    virtual void coercive_set(double in_num) override = 0;
    virtual void coercive_set(const SharedTrackerElement& in_elem) override = 0;

    // We don't define cloning, subclasses have to do that
    virtual std::shared_ptr<TrackerElement> clone_type() override = 0;
    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override = 0;

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
    TrackerElementString() :
        TrackerElementCoreScalar<std::string>(TrackerType::TrackerString) {

        }

    TrackerElementString(int id) :
        TrackerElementCoreScalar<std::string>(TrackerType::TrackerString, id) {

        }

    virtual void coercive_set(const std::string& in_str) override;
    virtual void coercive_set(double in_num) override;
    virtual void coercive_set(const SharedTrackerElement& e) override;

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
        return dup;
    }

};

class TrackerElementByteArray : public TrackerElementCoreScalar<std::string> {
    TrackerElementByteArray() :
        TrackerElementCoreScalar<std::string>(TrackerType::TrackerByteArray) {

        }

    TrackerElementByteArray(int id) :
        TrackerElementCoreScalar<std::string>(TrackerType::TrackerByteArray, id) {

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

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
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
    TrackerElementDeviceKey() :
        TrackerElementCoreScalar<device_key>(TrackerType::TrackerKey) {

        }

    TrackerElementDeviceKey(int id) :
        TrackerElementCoreScalar<device_key>(TrackerType::TrackerKey) {

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

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
        return dup;
    }
};

class TrackerElementUUID : public TrackerElementCoreScalar<uuid> {
    TrackerElementUUID() :
        TrackerElementCoreScalar<uuid>(TrackerType::TrackerUuid) {

        }

    TrackerElementUUID(int id) :
        TrackerElementCoreScalar<uuid>(TrackerType::TrackerUuid, id) {

        }

    virtual void coercive_set(const std::string& in_str) override;
    virtual void coercive_set(double in_num) override;
    virtual void coercive_set(const SharedTrackerElement& e) override;

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
        return dup;
    }

};

class TrackerElementMacAddr : public TrackerElementCoreScalar<mac_addr> {
    TrackerElementMacAddr() :
        TrackerElementCoreScalar<mac_addr>(TrackerType::TrackerMac) {

        }

    TrackerElementMacAddr(int id) :
        TrackerElementCoreScalar<mac_addr>(TrackerType::TrackerMac, id) {

        }

    virtual void coercive_set(const std::string& in_str) override;
    virtual void coercive_set(double in_num) override;
    virtual void coercive_set(const SharedTrackerElement& e) override;

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
        return dup;
    }

};

// Simplify numeric conversion w/ an interstitial scalar-like that holds all 
// our numeric subclasses
template<class N>
class TrackerElementCoreNumeric : public TrackerElement {
public:
    TrackerElementCoreNumeric(TrackerType t) :
        TrackerElementCoreScalar<N>(t) {

        }

    TrackerElementCoreNumeric(TrackerType t, int id) :
        TrackerElementCoreScalar<N>(t, id) {

        }

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
    virtual std::shared_ptr<TrackerElement> clone_type() override = 0;
    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override = 0;

    N& get() {
        return value;
    }

    void set(const N& in) {
        value = in;
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

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
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

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
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

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
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

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
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

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
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

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
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

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
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

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
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

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
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

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
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
    using pair = std::pair<int, SharedTrackerElement>;

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

    std::pair<iterator, bool> insert(pair p) {
        return map.insert(p);
    }

    std::pair<iterator, bool> insert(SharedTrackerElement e) {
        auto existing = map.find(e->get_id());

        if (existing == map.end()) {
            auto p = std::make_pair(e->get_id(), e);
            return insert(p);
        } else {
            existing->second = e;
            return std::make_pair(existing, true);
        }
    }

protected:
    std::map<int, SharedTrackerElement> map;
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

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
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

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
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

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
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

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
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

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
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

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
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

    void push_back(const SharedTrackerElement& v) {
        vector.push_back(v);
    }

    void push_back(SharedTrackerElement&& v) {
        vector.push_back(v);
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

template<> std::map<int, SharedTrackerElement> GetTrackerValue(const SharedTrackerElement& e);
template<> std::vector<SharedTrackerElement> GetTrackerValue(const SharedTrackerElement& e);

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
        cvar->set((ptype) in); \
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
        cvar->set((ptype) in); \
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
        (*cvar)++; \
    } \
    virtual void inc_##name(rtype i) { \
        (*cvar) += (ptype) i; \
    } \
    virtual void dec_##name() { \
        (*cvar)--; \
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
            del_map(std::static_pointer_cast<TrackerElement>(cvar)); \
        cvar = in; \
        if (cvar != NULL) \
            add_map(std::static_pointer_cast<TrackerElement>(cvar)); \
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
            cvar = std::static_pointer_cast<ttype>(tracker_component::entrytracker->GetTrackedInstance(id)); \
            if (cvar != NULL) \
                add_map(std::static_pointer_cast<TrackerElement>(cvar)); \
        } \
        return cvar; \
    } \
    virtual void set_tracker_##name(const std::shared_ptr<ttype>& in) { \
        if (cvar != NULL) \
            del_map(std::static_pointer_cast<TrackerElement>(cvar)); \
        cvar = in; \
        if (cvar != NULL) { \
            cvar->set_id(id); \
            add_map(std::static_pointer_cast<TrackerElement>(cvar)); \
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

#define __RegisterComplexField(type, id, name, description) \
        auto builder_##id = std::make_shared< type >(globalreg, 0); \
        id = RegisterComplexField(name, builder_##id, description);

public:
    tracker_component(std::shared_ptr<EntryTracker> tracker, int in_id) :
        TrackerElementMap(in_id),
        entrytracker(tracker) {

    }

    tracker_component(std::shared_ptr<EntryTracker> tracker, int in_id, 
            SharedTrackerElement e __attribute__((unused))) :
        TrackerElementMap(in_id),
        entrytracker(tracker) {

    }

	virtual ~tracker_component() {

    }

    virtual std::shared_ptr<TrackerElement> clone_type() override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>();
        return dup;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) override {
        auto dup = std::make_shared<std::remove_pointer<decltype(this)>::type>(in_id);
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
    // Reserve a field via the entrytracker, using standard entrytracker build methods.
    // This field will be automatically assigned or created during the reservefields 
    // stage.
    int RegisterField(const std::string& in_name, TrackerType in_type, const std::string& in_desc, 
            SharedTrackerElement *in_dest);

    // Reserve a field via the entrytracker, using standard entrytracker build methods,
    // but do not assign or create during the reservefields stage.
    // This can be used for registering sub-components of maps which are not directly
    // instantiated as top-level fields.
    int RegisterField(const std::string& in_name, TrackerType in_type, const std::string& in_desc);

    // Reserve a field via the entrytracker, using standard entrytracker build methods.
    // This field will be automatically assigned or created during the reservefields 
    // stage.
    // You will nearly always want to use registercomplex below since fields with 
    // specific builders typically want to inherit from a subtype
    int RegisterField(const std::string& in_name, const SharedTrackerElement& in_builder, 
            const std::string& in_desc, SharedTrackerElement *in_dest);

    // Reserve a complex via the entrytracker, using standard entrytracker build methods.
    // This field will NOT be automatically assigned or built during the reservefields 
    // stage, callers should manually create these fields, importing from the parent
    int RegisterComplexField(const std::string& in_name, const SharedTrackerElement& in_builder, 
            const std::string& in_desc);

    // Register field types and get a field ID.  Called during record creation, prior to 
    // assigning an existing trackerelement tree or creating a new one
    virtual void register_fields() { }

    // Populate fields - either new (e == NULL) or from an existing structure which
    //  may contain a generic version of our data.
    // When populating from an existing structure, bind each field to this instance so
    //  that we can track usage and delete() appropriately.
    // Populate automatically based on the fields we have reserved, subclasses can 
    // override if they really need to do something special
    virtual void reserve_fields(SharedTrackerElement e);

    // Inherit from an existing element or assign a new one.
    // Add imported or new field to our map for use tracking.
    virtual SharedTrackerElement 
        import_or_new(SharedTrackerElement e, int i);

    class registered_field {
        public:
            registered_field(int id, SharedTrackerElement *assign) { 
                this->id = id; 
                this->assign = assign;
            }

            int id;
            SharedTrackerElement *assign;
    };

    GlobalRegistry *globalreg;
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
    TrackerElementSerializer(GlobalRegistry *in_globalreg) {
        globalreg = in_globalreg;
    }

    using rename_map = std::map<SharedTrackerElement, SharedElementSummary>;

    virtual ~TrackerElementSerializer() {
        local_locker lock(&mutex);
    }

    virtual void serialize(SharedTrackerElement in_elem, 
            std::ostream &stream, rename_map *name_map = NULL) = 0;

    // Fields extracted from a summary path need to preserialize their parent
    // paths or updates may not happen in the expected fashion, serializers should
    // call this when necessary
    static void pre_serialize_path(const SharedElementSummary& in_summary);
    static void post_serialize_path(const SharedElementSummary& in_summary);
protected:
    GlobalRegistry *globalreg;
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
