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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <functional>

#include <string>
#include <stdexcept>

#include <vector>
#include <map>
#include <memory>
#include <unordered_map>

#include "fmt.h"
#include "globalregistry.h"
#include "nlohmann/json.hpp"
#include "kis_mutex.h"
#include "macaddr.h"
#include "unordered_dense.h"
#include "uuid.h"

class entry_tracker;
class tracker_element;

using shared_tracker_element = std::shared_ptr<tracker_element>;

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

    std::string as_string();

    // Generate a cached phykey component; phyhandlers do this to cache
    static uint32_t gen_pkey(std::string in_phy);

    // Generate a cached SP key combination
    static uint64_t gen_spkey(uuid s_uuid, std::string phy);

    bool get_error() const { return error; }

    uint64_t get_spkey() const {
        return spkey;
    }

    uint64_t get_dkey() const {
        return dkey;
    }

protected:
    uint64_t spkey, dkey;
    bool error;
};

bool operator <(const device_key& x, const device_key& y);
bool operator ==(const device_key& x, const device_key& y);
std::ostream& operator<<(std::ostream& os, const device_key& k);
std::istream& operator>>(std::istream& is, device_key& k);

template <>struct fmt::formatter<device_key> : fmt::ostream_formatter {};

namespace std {
    template<> struct hash<device_key> {
        std::size_t operator()(device_key const& d) const noexcept {
            std::size_t h1 = std::hash<uint64_t>{}(d.get_spkey());
            std::size_t h2 = std::hash<uint64_t>{}(d.get_dkey());
            return h1 ^ (h2 << 1);
        }
    };
}

// Types of fields we can track and automatically resolve
// Statically assigned type numbers which MUST NOT CHANGE as things go forwards for 
// binary/fast serialization, new types must be added to the end of the list
enum class tracker_type {
    tracker_unassigned = -1,

    tracker_string = 0,

    tracker_int8 = 1, 
    tracker_uint8 = 2,

    tracker_int16 = 3, 
    tracker_uint16 = 4,

    tracker_int32 = 5, 
    tracker_uint32 = 6,

    tracker_int64 = 7,
    tracker_uint64 = 8,

    tracker_float = 9,
    tracker_double = 10,

    // Less basic types
    tracker_mac_addr = 11, 
    tracker_uuid = 12,

    // Vector and named map
    tracker_vector = 13, 
    tracker_map = 14,

    // unsigned integer map (int-keyed data not field-keyed)
    tracker_int_map = 15,

    // Mac map (mac-keyed tracker data)
    tracker_mac_map = 16,

    // String-keyed map
    tracker_string_map = 17,
    
    // Double-keyed map
    tracker_double_map = 18,

    // Byte array
    tracker_byte_array = 19,

    // Large key
    tracker_key = 20,

    // Key-map (Large keys, 128 bit or higher, using the TrackedKey class)
    tracker_key_map = 21,

    // "Complex-Scalar" types provide memory-efficient maps for specific collections
    // of data Kismet uses; RRDs use vectors of doubles and frequency counting use maps
    // of double:double, both of which benefit greatly from not tracking element fields for 
    // the collected types.
    
    // Vector of scalar double, not object, values
    tracker_vector_double = 22,

    // Map of double:double, not object, values
    tracker_double_map_double = 23,

    // Vector of strings
    tracker_vector_string = 24,

    // Hash-keyed map, using size_t as the keying element
    tracker_hashkey_map = 25,

    // Alias of another field
    tracker_alias = 26,

    // IPv4 address
    tracker_ipv4_addr = 27,

    // Double pair for geopoints
    tracker_pair_double = 28,

    // Placeholder/missing field
    tracker_placeholder_missing = 29,

    // Map of UUIDs
    tracker_uuid_map = 30,
    
    // Map of MAC addresses capable of handling masks / filtering
    tracker_macfilter_map = 31, 

    // Serialization "map" which is actually a vector so we can have duplicate instances 
    // of items with the same ID 
    tracker_summary_mapvec = 32,

    // Raw pointer to a string
    tracker_string_pointer = 33,

};

class tracker_element {
public:
    tracker_element() : 
        tracked_id(-1) {
            Globalreg::n_tracked_fields++;
        }

    tracker_element(tracker_element&& o) noexcept :
        tracked_id{o.tracked_id} { }

    tracker_element( int id) :
        tracked_id(id) { 
            Globalreg::n_tracked_fields++;
        }

    // Inherit from builder
    tracker_element(const tracker_element *p) :
        tracked_id{p->tracked_id} {
            Globalreg::n_tracked_fields++;
        }

    virtual ~tracker_element() {
        Globalreg::n_tracked_fields--;
    };

    // Factory-style for easily making more of the same if we're subclassed
    virtual std::shared_ptr<tracker_element> clone_type() noexcept {
        return nullptr;
    }

    // Called prior to serialization output
    virtual void pre_serialize() { }

    // Called after serialization is completed
    virtual void post_serialize() { }

    template<typename CT>
    static std::shared_ptr<CT> safe_cast_as(const std::shared_ptr<tracker_element>& e) {
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
        return static_cast<uint32_t>(get_type());
    }

    // Serialization helpers
    virtual bool is_stringable() const {
        return false;
    } 

    virtual std::string as_string() {
        return "";
    }

    virtual bool needs_quotes() const {
        return false;
    }

    constexpr17 uint16_t get_id() const {
        return tracked_id;
    }

    void set_id(uint16_t id) {
        tracked_id = id;
    }

    void set_type(tracker_type type);

    virtual tracker_type get_type() const {
        return tracker_type::tracker_unassigned;
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
    virtual void coercive_set(const shared_tracker_element& in_elem) = 0;

    static std::string type_to_string(tracker_type t);
    static tracker_type typestring_to_type(const std::string& s);
    static std::string type_to_typestring(tracker_type t);

    tracker_type enforce_type(tracker_type t) {
        if (get_type() != t) 
            throw std::runtime_error(fmt::format("invalid trackedelement access id {}, cannot use a {} "
                        "as a {}", tracked_id, type_to_string(get_type()), type_to_string(t)));

        return t;
    }

    tracker_type enforce_type(tracker_type t1, tracker_type t2) {
        if (get_type() == t1)
            return t1;
        
        if (get_type() == t2)
            return t2;

        throw std::runtime_error(fmt::format("invalid trackedelement access id {}, cannot use a {} "
                    "as a {} or {}", tracked_id, type_to_string(get_type()), type_to_string(t1), type_to_string(t2)));
    }

    friend std::ostream& operator<<(std::ostream& os, const tracker_element& e);
    friend std::istream& operator>>(std::istream& is, tracker_element& k);

protected:
    uint16_t tracked_id;
};

std::ostream& operator<<(std::ostream& os, const tracker_element& e);
std::istream& operator>>(std::istream& is, tracker_element& e);
std::ostream& operator<<(std::ostream& os, std::shared_ptr<tracker_element>& se);

template <>struct fmt::formatter<tracker_element> : fmt::ostream_formatter {};

// Basic generator function for making various elements; objects may also prefer pooling allocation
// to minimize malloc thrash
template<typename SUB, typename... Args>
std::unique_ptr<tracker_element> tracker_element_factory(const Args& ... args) {
    auto dup = std::unique_ptr<SUB>(new SUB(args...));
    return std::move(dup);
}

// Adapter function for converting cloned elements
template<class C>
constexpr17 C tracker_element_clone_adaptor(C p) {
    using c_t = typename std::remove_pointer<decltype(p.get())>::type;
    return std::static_pointer_cast<c_t>(std::move(p->clone_type()));
    // return std::static_pointer_cast<c_t>(std::shared_ptr<tracker_element>(std::move(p->clone_type())));
}

// Aliased element used to link one element to anothers name, for instance to
// allow the dot11 tracker a way to link the most recently used ssid from the
// map to a custom field
class tracker_element_alias : public tracker_element {
public:
    tracker_element_alias() :
        tracker_element() { }

    tracker_element_alias(int in_id) :
        tracker_element(in_id) { }

    tracker_element_alias(int id, std::shared_ptr<tracker_element> e) :
        tracker_element(id),
        alias_element(e) { }

    tracker_element_alias(const std::string& al, std::shared_ptr<tracker_element>& e) :
        tracker_element(),
        alias_element{e},
        alias_name{al} { }

    tracker_element_alias(const tracker_element_alias* p) :
        tracker_element(p) { }

    virtual tracker_type get_type() const override {
        return tracker_type::tracker_alias;
    }

    static tracker_type static_type() {
        return tracker_type::tracker_alias;
    }

    virtual const std::string& get_alias_name() const {
        return alias_name;
    }

    virtual bool is_stringable() const override {
        return alias_element->is_stringable();
    }

    virtual std::string as_string() override {
        return alias_element->as_string();
    }

    virtual bool needs_quotes() const override {
        return alias_element->needs_quotes();
    }

    virtual void coercive_set(const std::string& in_str) override {
        throw std::runtime_error("cannot coercively set aliases");
    }
    virtual void coercive_set(double in_num) override {
        throw std::runtime_error("cannot coercively set aliases");
    }

    virtual void coercive_set(const shared_tracker_element& e) override {
        throw std::runtime_error("cannot coercively set aliases");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = Globalreg::new_from_pool<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    std::shared_ptr<tracker_element> get() {
        return alias_element;
    }

    template <class A>
    std::shared_ptr<A> get_as() {
        return std::static_pointer_cast<A>(alias_element);
    }

    void set(std::shared_ptr<tracker_element> ae) {
        alias_element = ae;
    }

    void set_name(const std::string& n) {
        alias_name = n;
    }

    void reset() {
        alias_name = "";
        alias_element.reset();
    }

protected:
    std::shared_ptr<tracker_element> alias_element;
    std::string alias_name;
};

// Superclass for generic components for pod-like scalar attributes, though
// they don't need to be explicitly POD
template <class P>
class tracker_element_core_scalar : public tracker_element {
public:
    tracker_element_core_scalar() :
        tracker_element{} { }

    tracker_element_core_scalar(tracker_element_core_scalar&& o) noexcept :
        tracker_element{o},
        value{std::move(o.value)} { }

    tracker_element_core_scalar(int id) :
        tracker_element(id),
        value() { }

    tracker_element_core_scalar(int id, const P& v) :
        tracker_element(id),
        value(v) { }

    tracker_element_core_scalar(const tracker_element_core_scalar *p) :
        tracker_element{p} { }

    tracker_element_core_scalar(const P& v) :
        tracker_element{},
        value{v} { }

    // We don't define coercion, subclasses have to do that
    virtual void coercive_set(const std::string& in_str) override = 0;
    virtual void coercive_set(double in_num) override = 0;
    virtual void coercive_set(const shared_tracker_element& in_elem) override = 0;

    // We don't define cloning, subclasses have to do that
    virtual std::shared_ptr<tracker_element> clone_type() noexcept override = 0;

    P& get() {
        return value;
    }

    void set(const P& in) {
        value = in;
    }

    inline bool operator<(const tracker_element_core_scalar<P>& rhs) const {
        return value < rhs.value;
    }

    inline bool operator<(const std::shared_ptr<tracker_element>& rhs) const {
        if (get_type() != rhs->get_type())
            throw std::runtime_error(fmt::format("Attempted to compare two non-equal field types, "
                        "{} < {}", get_type_as_string(), rhs->get_type_as_string()));

        return value < std::static_pointer_cast<tracker_element_core_scalar<P>>(rhs)->value;
    }

    
    inline bool less_than(const tracker_element_core_scalar<P>& rhs) const {
        return value < rhs.value;
    }

    inline bool less_than(const std::shared_ptr<tracker_element>& rhs) const {
        if (get_type() != rhs->get_type())
            throw std::runtime_error(fmt::format("Attempted to compare two non-equal field types, "
                        "{} < {}", get_type_as_string(), rhs->get_type_as_string()));

        // return value < safe_cast_as<tracker_element_core_scalar<P>>(rhs)->value;
        return value < static_cast<tracker_element_core_scalar<P> *>(rhs.get())->value;
    }

protected:
    P value;

};

class tracker_element_string : public tracker_element_core_scalar<std::string> {
public:
    tracker_element_string() :
        tracker_element_core_scalar<std::string>() { }

    tracker_element_string(int id) :
        tracker_element_core_scalar<std::string>(id) { }

    tracker_element_string(int id, const std::string& s) :
        tracker_element_core_scalar<std::string>(id, s) { }

    tracker_element_string(const std::string& s) :
        tracker_element_core_scalar<std::string>(0, s) { }

    tracker_element_string(const tracker_element_string *p) :
        tracker_element_core_scalar{p} { }

    virtual tracker_type get_type() const override {
        return tracker_type::tracker_string;
    }

    static tracker_type static_type() {
        return tracker_type::tracker_string;
    }

    void reset() {
        value = "";
    }

    virtual bool is_stringable() const override {
        return true;
    }

    virtual std::string as_string() override {
        return value;
    }

    virtual bool needs_quotes() const override {
        return true;
    }

    virtual void coercive_set(const std::string& in_str) override;
    virtual void coercive_set(double in_num) override;
    virtual void coercive_set(const shared_tracker_element& e) override;

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = Globalreg::new_from_pool<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    using tracker_element_core_scalar<std::string>::less_than;
    inline bool less_than(const tracker_element_string& rhs) const;

    size_t length() {
        return value.length();
    }

};

class tracker_element_string_ptr : public tracker_element_core_scalar<std::string *> {
public:
    tracker_element_string_ptr() :
        tracker_element_core_scalar<std::string *>() {
        value = nullptr;
    }

    tracker_element_string_ptr(int id) :
        tracker_element_core_scalar<std::string *>(id) {
        value = nullptr;
    }

    tracker_element_string_ptr(int id, std::string *s) :
        tracker_element_core_scalar<std::string *>(id, s) {
        value = nullptr;
    }

    tracker_element_string_ptr(std::string *s) :
        tracker_element_core_scalar<std::string *>(0, s) {
        value = nullptr;
    }

    tracker_element_string_ptr(const tracker_element_string_ptr *p) :
        tracker_element_core_scalar{p} { 
        value = nullptr;
    }

    virtual tracker_type get_type() const override {
        return tracker_type::tracker_string_pointer;
    }

    static tracker_type static_type() {
        return tracker_type::tracker_string_pointer;
    }

    void reset() {
        value = nullptr;
    }

    virtual bool is_stringable() const override {
        return true;
    }

    virtual std::string as_string() override {
        if (value == nullptr)
            return "";

        return *value;
    }

    virtual bool needs_quotes() const override {
        return true;
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = Globalreg::new_from_pool<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    virtual void coercive_set(const std::string& in_str) override {
        throw std::runtime_error(fmt::format("Can not coerce std::string to {}",
                    get_type_as_string()));
    }

    virtual void coercive_set(double in_num) override {
        throw std::runtime_error(fmt::format("Can not coerce double to {}",
                    get_type_as_string()));
    }

    virtual void coercive_set(const shared_tracker_element& e) override {
        throw std::runtime_error(fmt::format("Can not coerce {} to {}",
                    e->get_type_as_string(), get_type_as_string()));
    }

    size_t length() {
        if (value == NULL)
            return 0;

        return value->length();
    }

};

class tracker_element_byte_array : public tracker_element_string {
public:
    tracker_element_byte_array() :
        tracker_element_string() { }

    tracker_element_byte_array(int id) :
        tracker_element_string(id) { }

    tracker_element_byte_array(int id, const std::string& s) :
        tracker_element_string(id, s) { }

    tracker_element_byte_array(const tracker_element_byte_array *p) :
        tracker_element_string{p} { }

    virtual tracker_type get_type() const override {
        return tracker_type::tracker_byte_array;
    }

    static tracker_type static_type() {
        return tracker_type::tracker_byte_array;
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = Globalreg::new_from_pool<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    virtual std::string as_string() override {
        return to_hex();
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
        std::string rs;

        rs.reserve(value.length() * 2);

        for (auto c : value) {
            auto n = (c >> 4) & 0x0F;
            if (n <= 9)
                rs += '0' + n;
            else
                rs += 'A' + n - 10;

            auto n2 = c & 0x0F;
            if (n2 <= 9)
                rs += '0' + n2;
            else
                rs += 'A' + n2 - 10;
        }

        return rs;
    }

    char hex2nibble(const char& c) const {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'A' && c <= 'F')
            return (c - 'A') + 10;
        if (c >= 'a' && c <= 'f')
            return (c - 'a') + 10;

        return 0;
    }

    std::string from_hex(const std::string& s) {
        std::string rs;

        size_t pos = 0;

        if (s.length() == 0)
            return rs;

        if (s.length() % 2 != 0) {
            rs.reserve((s.length() / 2) + 1);
            rs += hex2nibble(s[0]);
            pos = 1;
        } else {
            rs.reserve(s.length() / 2);
        }

        for (; pos < s.length(); pos += 2)  
            rs += ((hex2nibble(s[pos]) << 4) | hex2nibble(s[pos + 1]));

        return rs;
    }

};

class tracker_element_device_key : public tracker_element_core_scalar<device_key> {
public:
    tracker_element_device_key() :
        tracker_element_core_scalar<device_key>() { }

    tracker_element_device_key(int id) :
        tracker_element_core_scalar<device_key>(id) { }

    tracker_element_device_key(const tracker_element_device_key *p) :
        tracker_element_core_scalar<device_key>{p} { }

    virtual tracker_type get_type() const override {
        return tracker_type::tracker_key;
    }

    static tracker_type static_type() {
        return tracker_type::tracker_key;
    }

    void reset() {
        value = device_key{};
    }

    virtual bool is_stringable() const override {
        return true;
    }

    virtual std::string as_string() override {
        return value.as_string();
    }

    virtual bool needs_quotes() const override {
        return true;
    }

    virtual void coercive_set(const std::string& in_str) override {
        throw(std::runtime_error("Cannot coercive_set a devicekey from a string"));
    }

    virtual void coercive_set(double in_num) override {
        throw(std::runtime_error("Cannot coercive_set a devicekey from a numeric"));
    }

    // Attempt to coerce one complete item to another
    virtual void coercive_set(const shared_tracker_element& in_elem) override {
        throw(std::runtime_error("Cannot coercive_set a devicekey from an element"));
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = Globalreg::new_from_pool<this_t>();
        r->set_id(this->get_id());
        return r;
    }
};

class tracker_element_uuid : public tracker_element_core_scalar<uuid> {
public:
    tracker_element_uuid() :
        tracker_element_core_scalar<uuid>() { }

    tracker_element_uuid(int id) :
        tracker_element_core_scalar<uuid>(id) { }

    tracker_element_uuid(int id, const uuid& u) :
        tracker_element_core_scalar<uuid>(id, u) { }

    tracker_element_uuid(const tracker_element_uuid *p) :
        tracker_element_core_scalar<uuid>{p} { }

    virtual tracker_type get_type() const override {
        return tracker_type::tracker_uuid;
    }

    static tracker_type static_type() {
        return tracker_type::tracker_uuid;
    }

    void reset() {
        value = uuid{};
    }

    virtual bool is_stringable() const override {
        return true;
    }

    virtual std::string as_string() override {
        return value.as_string();
    }

    virtual bool needs_quotes() const override {
        return true;
    }

    virtual void coercive_set(const std::string& in_str) override;
    virtual void coercive_set(double in_num) override;
    virtual void coercive_set(const shared_tracker_element& e) override;

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = Globalreg::new_from_pool<this_t>();
        r->set_id(this->get_id());
        return r;
    }
};

class tracker_element_mac_addr : public tracker_element_core_scalar<mac_addr> {
public:
    tracker_element_mac_addr() :
        tracker_element_core_scalar<mac_addr>() { }

    tracker_element_mac_addr(int id) :
        tracker_element_core_scalar<mac_addr>(id) { }

    tracker_element_mac_addr(int id, const std::string& s) :
        tracker_element_core_scalar<mac_addr>(id, mac_addr(s)) { }

    tracker_element_mac_addr(int id, const mac_addr& m) :
        tracker_element_core_scalar<mac_addr>(id, m) { }

    tracker_element_mac_addr(const tracker_element_mac_addr *p) :
        tracker_element_core_scalar<mac_addr>{p} { }

    tracker_element_mac_addr(const mac_addr& m) :
        tracker_element_core_scalar<mac_addr>{m} { }

    virtual tracker_type get_type() const override {
        return tracker_type::tracker_mac_addr;
    }

    static tracker_type static_type() {
        return tracker_type::tracker_mac_addr;
    }

    void reset() {
        value = mac_addr{};
    }

    virtual bool is_stringable() const override {
        return true;
    }

    virtual std::string as_string() override {
        return value.as_string();
    }

    virtual bool needs_quotes() const override {
        return true;
    }

    virtual void coercive_set(const std::string& in_str) override;
    virtual void coercive_set(double in_num) override;
    virtual void coercive_set(const shared_tracker_element& e) override;

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = Globalreg::new_from_pool<this_t>();
        r->set_id(this->get_id());
        return r;
    }
};

class tracker_element_ipv4_addr : public tracker_element_core_scalar<uint32_t> {
public:
    tracker_element_ipv4_addr() :
        tracker_element_core_scalar<uint32_t>() { }

    tracker_element_ipv4_addr(int id) :
        tracker_element_core_scalar<uint32_t>(id) { }

    tracker_element_ipv4_addr(int id, const std::string& s) :
        tracker_element_core_scalar<uint32_t>(id) { 

        struct in_addr addr;

        if (inet_aton(s.c_str(), &addr) != 1)
            value = 0;

        value = addr.s_addr;
    }

    tracker_element_ipv4_addr(int id, struct in_addr addr) :
        tracker_element_core_scalar<uint32_t>(id, addr.s_addr) { }

    tracker_element_ipv4_addr(int id, struct in_addr *addr) :
        tracker_element_core_scalar<uint32_t>(id, addr->s_addr) { }

    tracker_element_ipv4_addr(tracker_element_ipv4_addr *p) :
        tracker_element_core_scalar<uint32_t>{p} { }

    virtual tracker_type get_type() const override {
        return tracker_type::tracker_ipv4_addr;
    }

    static tracker_type static_type() {
        return tracker_type::tracker_ipv4_addr;
    }

    void reset() {
        value = 0;
    }

    virtual bool is_stringable() const override {
        return true;
    }

    virtual std::string as_string() override {
        struct in_addr addr;
        char buf[32];
        addr.s_addr = value;
        std::string s(inet_ntop(AF_INET, &addr, buf, 32));
        return s;
    }

    virtual bool needs_quotes() const override {
        return true;
    }

    virtual void coercive_set(const std::string& in_str) override;
    virtual void coercive_set(double in_num) override;
    virtual void coercive_set(const shared_tracker_element& e) override;

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = Globalreg::new_from_pool<this_t>();
        r->set_id(this->get_id());
        return r;
    }

};

template<class N>
class numerical_string {
public:
    virtual std::string as_string(N v) const {
        if (std::isnan(v) || std::isinf(v))
            return "0";

        return fmt::format("{}", v);
    }
};

// Simplify numeric conversion w/ an interstitial scalar-like that holds all 
// our numeric subclasses
template<class N, tracker_type T = tracker_type::tracker_double, class S = numerical_string<N>>
class tracker_element_core_numeric : public tracker_element {
public:
    tracker_element_core_numeric() :
        tracker_element(),
        value{0} { }

    tracker_element_core_numeric(int id) :
        tracker_element(id),
        value{0} { }

    tracker_element_core_numeric(int id, const N& v) :
        tracker_element(id),
        value(v) { }

    tracker_element_core_numeric(const tracker_element_core_numeric<N, T, S> *p) :
        tracker_element{p},
        value{0} { }

    virtual tracker_type get_type() const override {
        return T;
    }

    static tracker_type static_type() {
        return T;
    }

    void reset() {
        value = 0;
    }

    virtual bool is_stringable() const override {
        return true;
    }

    virtual std::string as_string() override {
        S s;
        return s.as_string(value);
    }

    virtual bool needs_quotes() const override {
        return false;
    }

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
        this->value = static_cast<N>(in_num);
    }

    virtual void coercive_set(const shared_tracker_element& e) override {
        switch (e->get_type()) {
            case tracker_type::tracker_int8:
            case tracker_type::tracker_uint8:
            case tracker_type::tracker_int16:
            case tracker_type::tracker_uint16:
            case tracker_type::tracker_int32:
            case tracker_type::tracker_uint32:
            case tracker_type::tracker_int64:
            case tracker_type::tracker_uint64:
            case tracker_type::tracker_float:
            case tracker_type::tracker_double:
                coercive_set(std::static_pointer_cast<tracker_element_core_numeric>(e)->get());
                break;
            case tracker_type::tracker_string:
                coercive_set(std::static_pointer_cast<tracker_element_string>(e)->get());
                break;
            default:
                throw std::runtime_error(fmt::format("Could not coerce {} to {}",
                            e->get_type_as_string(), this->get_type_as_string()));
        }
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = Globalreg::new_from_pool<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    N& get() {
        return value;
    }

    void set(const N& in) {
        value = in;
    }

    inline bool operator==(const tracker_element_core_numeric<N, T, S>& rhs) const { 
        return value == rhs.value;
    }

    inline bool operator==(const N& rhs) const {
        return value != rhs;
    }

    inline bool operator!=(const tracker_element_core_numeric<N, T, S>& rhs) const { 
        return !(value == rhs.value); 
    }

    inline bool operator!=(const N& rhs) const {
        return value != rhs;
    }

    inline bool operator<=(const tracker_element_core_numeric<N, T, S>& rhs) const {
        return value <= rhs.value;
    }

    inline bool operator<=(const N& rhs) const {
        return value <= rhs;
    }

    inline bool operator<(const tracker_element_core_numeric<N, T, S>& rhs) const {
        return value < rhs.value;
    }

    inline bool operator<(const N& rhs) {
        return value < rhs;
    }

    inline bool operator>=(const tracker_element_core_numeric<N, T, S>& rhs) const {
        return value >= rhs.value;
    }

    inline bool operator>=(const N& rhs) {
        return value >= rhs;
    }

    inline bool operator>(const tracker_element_core_numeric<N, T, S>& rhs) const {
        return value > rhs.value;
    }

    inline bool operator>(const N& rhs) const {
        return value  > rhs;
    }

    tracker_element_core_numeric<N, T, S>& operator+=(const N& rhs) {
        value += rhs;
        return *this;
    }

    tracker_element_core_numeric<N, T, S>& operator-=(const N& rhs) {
        value -= rhs;
        return *this;
    }

    friend tracker_element_core_numeric<N, T, S> operator+(tracker_element_core_numeric lhs,
            const tracker_element_core_numeric<N, T, S>& rhs) {
        lhs += rhs;
        return lhs;
    }

    friend tracker_element_core_numeric<N, T, S> operator-(tracker_element_core_numeric lhs,
            const tracker_element_core_numeric<N, T, S>& rhs) {
        lhs -= rhs;
        return lhs;
    }

    tracker_element_core_numeric<N, T, S>& operator|=(const tracker_element_core_numeric<N, T, S>& rhs) {
        value |= rhs.value;
        return *this;
    }

    tracker_element_core_numeric<N, T, S>& operator|=(const N& rhs) {
        value |= rhs;
        return *this;
    }

    tracker_element_core_numeric<N, T, S>& operator&=(const tracker_element_core_numeric<N, T, S>& rhs) {
        value &= rhs.value;
        return *this;
    }

    tracker_element_core_numeric<N, T, S>& operator&=(const N& rhs) {
        value &= rhs;
        return *this;
    }

    tracker_element_core_numeric<N, T, S>& operator^=(const tracker_element_core_numeric<N, T, S>& rhs) {
        value ^= rhs.value;
        return *this;
    }

    tracker_element_core_numeric<N, T, S>& operator^=(const N& rhs) {
        value ^= rhs;
        return *this;
    }

    inline bool less_than(const tracker_element_core_numeric<N, T, S>& rhs) const {
        return value < rhs.value;
    }

    inline bool less_than(const std::shared_ptr<tracker_element>& rhs) const {
        if (get_type() != rhs->get_type())
            throw std::runtime_error(fmt::format("Attempted to compare two non-equal field types, "
                        "{} < {}", get_type_as_string(), rhs->get_type_as_string()));

        // return value < safe_cast_as<tracker_element_core_numeric<N, T, S>>(rhs)->value;
        return value < static_cast<tracker_element_core_numeric<N, T, S> *>(rhs.get)->value;
    }

protected:
    N value;
};

using tracker_element_uint8 = tracker_element_core_numeric<uint8_t, tracker_type::tracker_uint8>;
using tracker_element_int8 = tracker_element_core_numeric<int8_t, tracker_type::tracker_int8>;

using tracker_element_uint16 = tracker_element_core_numeric<uint16_t, tracker_type::tracker_uint16>;
using tracker_element_int16 = tracker_element_core_numeric<int16_t, tracker_type::tracker_int16>;

using tracker_element_uint32 = tracker_element_core_numeric<uint32_t, tracker_type::tracker_uint32>;
using tracker_element_int32 = tracker_element_core_numeric<int32_t, tracker_type::tracker_int32>;

using tracker_element_uint64 = tracker_element_core_numeric<uint64_t, tracker_type::tracker_uint64>;
using tracker_element_int64 = tracker_element_core_numeric<int64_t, tracker_type::tracker_int64>;

template<class N>
class float_numerical_string {
public:
    virtual std::string as_string(const N v) {
        if (std::isnan(v) || std::isinf(v))
            return "0";

        // Jump through some hoops to collapse things like 0.000000 to 0 to save 
        // space/time in serializing
        if (floor(v) == v)
            return fmt::format("{}", (long long) v);

        return fmt::format("{:f}", v);
    }
};

using tracker_element_float = tracker_element_core_numeric<float, tracker_type::tracker_float, float_numerical_string<float>>;
using tracker_element_double = tracker_element_core_numeric<double, tracker_type::tracker_double, float_numerical_string<double>>;



// Superclass for generic access to maps via multiple key structures; use a std::map tree
// map;  alternate implementation available as core_unordered_map for structures which don't
// need comparator operations
template <typename MT, typename K, typename V, tracker_type T>
class tracker_element_core_map : public tracker_element {
public:
    using map_t = MT;
    using iterator = typename map_t::iterator;
    using const_iterator = typename map_t::const_iterator;
    using pair = std::pair<K, V>;

    tracker_element_core_map() : 
        tracker_element(),
        present_set{0} { }

    tracker_element_core_map(tracker_element_core_map&& o) noexcept :
        tracker_element{o},
        present_set{o.present_set},
        map{std::move(o.map)} { }

    tracker_element_core_map(int id) :
        tracker_element(id),
        present_set{0} { }

    // Inherit attributes but not content
    tracker_element_core_map(const tracker_element_core_map<MT, K, V, T> *p) :
        tracker_element{p},
        present_set{p->present_set} { }

    virtual tracker_type get_type() const override {
        return T;
    }

    static tracker_type static_type() {
        return T;
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = Globalreg::new_from_pool<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    void reset() {
        map.clear();
    }

    virtual bool is_stringable() const override {
        return false;
    }

    virtual std::string as_string() override {
        return "";
    }

    virtual bool needs_quotes() const override {
        return true;
    }

    // Optionally present as a vector of content when serializing
    virtual void set_as_vector(const bool in_v) {
        if (in_v)
            present_set |= 0x01;
        else
            present_set &= ~(0x01);
    }

    virtual bool as_vector() const {
        return (present_set & 0x01);
    }

    // Optionally present as a vector of keys when serializing
    virtual void set_as_key_vector(const bool in_v) {
        if (in_v)
            present_set |= 0x02;
        else
            present_set &= ~(0x02);
    }

    virtual bool as_key_vector() const {
        return (present_set & 0x02);
    }

    virtual void coercive_set(const std::string& in_str) override {
        throw(std::runtime_error("Cannot coercive_set a map from a string"));
    }

    virtual void coercive_set(double in_num) override {
        throw(std::runtime_error("Cannot coercive_set a map from a numeric"));
    }

    // Attempt to coerce one complete item to another
    virtual void coercive_set(const shared_tracker_element& in_elem) override {
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

    const_iterator cend() const {
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
        return map.insert({p.first, p.second});
    }

    std::pair<iterator, bool> insert(const K& i, const V& e) {
        return map.insert({i, e});
    }

    // insert, and replace if key is found.  if key is not found, insert
    // as normal.
    std::pair<iterator, bool> replace(pair p) {
        auto k = map.find(p.first);
        if (k != map.end())
            map.erase(k);

        return map.insert({p.first, p.second});
    }

    std::pair<iterator, bool> replace(const K& i, const V& e) {
        auto k = map.find(i);
        if (k != map.end())
            map.erase(k);

        return map.insert({i, e});
    }

protected:
    map_t map;
    uint8_t present_set;
};

// Dictionary / map-by-id
class tracker_element_map : public tracker_element_core_map<ankerl::unordered_dense::map<uint16_t, std::shared_ptr<tracker_element>>, uint16_t, std::shared_ptr<tracker_element>, tracker_type::tracker_map> {
public:
    tracker_element_map() :
        tracker_element_core_map<ankerl::unordered_dense::map<uint16_t, std::shared_ptr<tracker_element>>, uint16_t, std::shared_ptr<tracker_element>, tracker_type::tracker_map>() { }

    tracker_element_map(int id) :
        tracker_element_core_map<ankerl::unordered_dense::map<uint16_t, std::shared_ptr<tracker_element>>, uint16_t, std::shared_ptr<tracker_element>, tracker_type::tracker_map>(id) { }

    tracker_element_map(const tracker_element_map *p) :
        tracker_element_core_map<ankerl::unordered_dense::map<uint16_t, std::shared_ptr<tracker_element>>, uint16_t, std::shared_ptr<tracker_element>, tracker_type::tracker_map>(p) { }

    shared_tracker_element get_sub(int id) {
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

    std::pair<iterator, bool> insert(shared_tracker_element e) {
        if (e == NULL) 
            throw std::runtime_error("Attempted to insert null tracker_element with no ID");

        auto existing = map.find(e->get_id());

        if (existing == map.end()) {
            return map.insert({e->get_id(), e});
        } else {
            existing->second = e;
            return std::make_pair(existing, true);
        }
    }

    template<typename TE>
    std::pair<iterator, bool> insert(TE e) {
        if (e == NULL) 
            throw std::runtime_error("Attempted to insert null tracker_element with no ID");

        auto existing = map.find(e->get_id());

        if (existing == map.end()) {
            return map.insert({e->get_id(), std::static_pointer_cast<tracker_element>(e)});
        } else {
            existing->second = std::static_pointer_cast<tracker_element>(e);
            return std::make_pair(existing, true);
        }
    }

    template<typename TE>
    std::pair<iterator, bool> insert(int i, TE e) {
        auto existing = map.find(i);

        if (existing == map.end()) {
            return map.insert({i, std::static_pointer_cast<tracker_element>(e)});
        } else {
            existing->second = std::static_pointer_cast<tracker_element>(e);
            return std::make_pair(existing, true);
        }
    }

    iterator erase(shared_tracker_element e) {
        if (e == nullptr)
            throw std::runtime_error("Attempted to erase null value from map");

        auto i = map.find(e->get_id());

        if (i != map.end())
            return map.erase(i);

        return i;
    }

    iterator erase(const_iterator i) {
        return map.erase(i);
    }
};

// int::element
using tracker_element_int_map = tracker_element_core_map<ankerl::unordered_dense::map<int, std::shared_ptr<tracker_element>>, int, std::shared_ptr<tracker_element>, tracker_type::tracker_int_map>;

// hash::element
using tracker_element_hashkey_map = tracker_element_core_map<ankerl::unordered_dense::map<size_t, std::shared_ptr<tracker_element>>, size_t, std::shared_ptr<tracker_element>, tracker_type::tracker_hashkey_map>;

// double::element
using tracker_element_double_map = tracker_element_core_map<ankerl::unordered_dense::map<double, std::shared_ptr<tracker_element>>, double, std::shared_ptr<tracker_element>, tracker_type::tracker_double_map>;

// mac::element, keyed as *unordered*, does not allow mask operations.  for generating mac maps which allow
// masks, use tracker_element_macfilter_map
using tracker_element_mac_map = tracker_element_core_map<ankerl::unordered_dense::map<mac_addr, std::shared_ptr<tracker_element>>, mac_addr, std::shared_ptr<tracker_element>, tracker_type::tracker_mac_map>;
using tracker_element_macfilter_map = tracker_element_core_map<std::map<mac_addr, std::shared_ptr<tracker_element>>, mac_addr, std::shared_ptr<tracker_element>, tracker_type::tracker_mac_map>;

// string::element
using tracker_element_string_map = tracker_element_core_map<ankerl::unordered_dense::map<std::string, std::shared_ptr<tracker_element>>, std::string, std::shared_ptr<tracker_element>, tracker_type::tracker_string_map>;

// devicekey::element
using tracker_element_device_key_map = tracker_element_core_map<ankerl::unordered_dense::map<device_key, std::shared_ptr<tracker_element>>, device_key, std::shared_ptr<tracker_element>, tracker_type::tracker_key_map>;

using tracker_element_uuid_map = tracker_element_core_map<ankerl::unordered_dense::map<uuid, std::shared_ptr<tracker_element>>, uuid, std::shared_ptr<tracker_element>, tracker_type::tracker_uuid_map>;

// double::double
using tracker_element_double_map_double = tracker_element_core_map<ankerl::unordered_dense::map<double, double>, double, double, tracker_type::tracker_double_map_double>;

// Core vector
template<typename T, tracker_type TT>
class tracker_element_core_vector : public tracker_element {
public:
    using vector_t = std::vector<T>;
    using iterator = typename vector_t::iterator;
    using const_iterator = typename vector_t::const_iterator;

    tracker_element_core_vector() :
        tracker_element() { }

    tracker_element_core_vector(tracker_element_core_vector&& o) noexcept :
        tracker_element{o},
        vector{std::move(o.vector)} { }

    tracker_element_core_vector(int id) :
        tracker_element(id) { }

    tracker_element_core_vector(int id, const vector_t& init_v) :
        tracker_element(id),
        vector{init_v} { }

    tracker_element_core_vector(std::shared_ptr<tracker_element_core_vector<T, TT>> v) :
        tracker_element_core_vector(v->get_id()) {
            vector = vector_t(v->begin(), v->end());
        }

    tracker_element_core_vector(const tracker_element_core_vector<T, TT> *p) :
        tracker_element{p} { }

    virtual tracker_type get_type() const override {
        return TT;
    }

    static tracker_type static_type() {
        return TT;
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = Globalreg::new_from_pool<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    void reset() {
        vector.clear();
    }

    virtual bool is_stringable() const override {
        return false;
    }

    virtual std::string as_string() override {
        return "";
    }

    virtual bool needs_quotes() const override {
        return true;
    }

    virtual void coercive_set(const std::string& in_str) override {
        throw(std::runtime_error("Cannot coercive_set a scalar vector from a string"));
    }

    virtual void coercive_set(double in_num) override {
        throw(std::runtime_error("Cannot coercive_set a scalar vector from a numeric"));
    }

    // Attempt to coerce one complete item to another
    virtual void coercive_set(const shared_tracker_element& in_elem) override {
        throw(std::runtime_error("Cannot coercive_set a scalar vector from an element"));
    }

    virtual void set(const_iterator a, const_iterator b) {
        vector = vector_t(a, b);
    }

    virtual void set(const vector_t& v) {
        vector = vector_t{v};
    }

    vector_t& get() {
        return vector;
    }

    T& at(size_t idx) {
        return vector.at(idx);
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

using tracker_element_vector = tracker_element_core_vector<std::shared_ptr<tracker_element>, tracker_type::tracker_vector>;
using tracker_element_vector_double = tracker_element_core_vector<double, tracker_type::tracker_vector_double>;
using tracker_element_vector_string = tracker_element_core_vector<std::string, tracker_type::tracker_vector_string>;

template<typename T1, typename T2, tracker_type TT>
class tracker_element_core_pair : public tracker_element {
public:
    using pair_t = std::pair<T1, T2>;

    tracker_element_core_pair() :
        tracker_element() { }

    tracker_element_core_pair(tracker_element_core_pair&& o) noexcept :
        tracker_element{o},
        pair{std::move(o.pair)} { }

    tracker_element_core_pair(int id) :
        tracker_element(id) { }

    tracker_element_core_pair(int id, const pair_t& init_p) :
        tracker_element(id),
        pair{init_p} { }

    tracker_element_core_pair(std::shared_ptr<tracker_element_core_pair<T1, T2, TT>> p) :
        tracker_element_core_pair(p->get_id()) {
            pair = pair_t(p->pair);
        }

    tracker_element_core_pair(const tracker_element_core_pair<T1, T2, TT> *p) :
        tracker_element{p} { }

    virtual tracker_type get_type() const override {
        return TT;
    }

    static tracker_type static_type() {
        return TT;
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = Globalreg::new_from_pool<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    void reset() {
        // do nothing, keep old data until new data is set since a pair has
        // no reset function; determine if this is safe in the future
    }

    virtual bool is_stringable() const override {
        return false;
    }

    virtual std::string as_string() override {
        return "";
    }

    virtual bool needs_quotes() const override {
        return true;
    }

    virtual void coercive_set(const std::string& in_str) override {
        throw(std::runtime_error("Cannot coercive_set a scalar pair from a string"));
    }

    virtual void coercive_set(double in_num) override {
        throw(std::runtime_error("Cannot coercive_set a scalar pair from a numeric"));
    }

    // Attempt to coerce one complete item to another
    virtual void coercive_set(const shared_tracker_element& in_elem) override {
        throw(std::runtime_error("Cannot coercive_set a scalar pair from an element"));
    }

    virtual void set(const T1& t1, const T2& t2) {
        pair = std::make_pair(t1, t2);
    }

    pair_t& get() {
        return pair;
    }

protected:
    pair_t pair;
};

using tracker_element_pair_double = tracker_element_core_pair<double, double, tracker_type::tracker_pair_double>;

class tracker_element_placeholder : public tracker_element_core_numeric<uint8_t, tracker_type::tracker_placeholder_missing> {
public:
    tracker_element_placeholder() :
        tracker_element_core_numeric<uint8_t, tracker_type::tracker_placeholder_missing>() { }

    tracker_element_placeholder(tracker_element_placeholder&& o) noexcept :
        tracker_element_core_numeric<uint8_t, tracker_type::tracker_placeholder_missing>(),
        placeholder_name{std::move(o.placeholder_name)} { }

    tracker_element_placeholder(int id) :
        tracker_element_core_numeric<uint8_t, tracker_type::tracker_placeholder_missing>(id) { }

    tracker_element_placeholder(int id, const std::string& name) :
        tracker_element_core_numeric<uint8_t, tracker_type::tracker_placeholder_missing>{id},
        placeholder_name{name} { }

    tracker_element_placeholder(std::shared_ptr<tracker_element_placeholder> p) :
        tracker_element_core_numeric<uint8_t, tracker_type::tracker_placeholder_missing>{p->get_id()},
        placeholder_name{p->placeholder_name} { }

    tracker_element_placeholder(const tracker_element_placeholder *p) :
        tracker_element_core_numeric<uint8_t, tracker_type::tracker_placeholder_missing>{p} { }

    virtual tracker_type get_type() const override {
        return tracker_type::tracker_placeholder_missing;
    }

    static tracker_type static_type() {
        return tracker_type::tracker_placeholder_missing;
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = Globalreg::new_from_pool<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    void reset() {
        placeholder_name = "";
        value = 0;
    }

    void set_name(const std::string& name) {
        placeholder_name = name;
    }

    const std::string& get_name() const {
        return placeholder_name;
    }

protected:
    std::string placeholder_name;
};

using tracker_element_mapvec = tracker_element_core_vector<std::shared_ptr<tracker_element>, tracker_type::tracker_summary_mapvec>;

// Templated generic access functions

template<typename T> T get_tracker_value(const shared_tracker_element&);
template<> std::string get_tracker_value(const shared_tracker_element& e);
template<> int8_t get_tracker_value(const shared_tracker_element& e);
template<> uint8_t get_tracker_value(const shared_tracker_element& e);
template<> int16_t get_tracker_value(const shared_tracker_element& e);
template<> uint16_t get_tracker_value(const shared_tracker_element& e);
template<> int32_t get_tracker_value(const shared_tracker_element& e);
template<> uint32_t get_tracker_value(const shared_tracker_element& e);
template<> int64_t get_tracker_value(const shared_tracker_element& e);
template<> uint64_t get_tracker_value(const shared_tracker_element& e);
template<> float get_tracker_value(const shared_tracker_element& e);
template<> double get_tracker_value(const shared_tracker_element& e);
template<> mac_addr get_tracker_value(const shared_tracker_element& e);
template<> uuid get_tracker_value(const shared_tracker_element& e);
template<> device_key get_tracker_value(const shared_tracker_element& e);

template<typename T> void set_tracker_value(const shared_tracker_element& e, const T& v);
template<> void set_tracker_value(const shared_tracker_element& e, const std::string& v);
template<> void set_tracker_value(const shared_tracker_element& e, const int8_t& v);
template<> void set_tracker_value(const shared_tracker_element& e, const uint8_t& v);
template<> void set_tracker_value(const shared_tracker_element& e, const int16_t& v);
template<> void set_tracker_value(const shared_tracker_element& e, const uint16_t& v);
template<> void set_tracker_value(const shared_tracker_element& e, const int32_t& v);
template<> void set_tracker_value(const shared_tracker_element& e, const uint32_t& v);
template<> void set_tracker_value(const shared_tracker_element& e, const int64_t& v);
template<> void set_tracker_value(const shared_tracker_element& e, const uint64_t& v);
template<> void set_tracker_value(const shared_tracker_element& e, const float& v);
template<> void set_tracker_value(const shared_tracker_element& e, const double& v);
template<> void set_tracker_value(const shared_tracker_element& e, const mac_addr& v);
template<> void set_tracker_value(const shared_tracker_element& e, const uuid& v);
template<> void set_tracker_value(const shared_tracker_element& e, const device_key& v);

class tracker_element_summary;
using SharedElementSummary =  std::shared_ptr<tracker_element_summary>;

// Element simplification record for summarizing and simplifying records
class tracker_element_summary {
public:
    tracker_element_summary() { };

    tracker_element_summary(const std::string& in_path, const std::string& in_rename);

    tracker_element_summary(const std::vector<std::string>& in_path, const std::string& in_rename);

    tracker_element_summary(const std::string& in_path);

    tracker_element_summary(const std::vector<std::string>& in_path);

    tracker_element_summary(const std::vector<int>& in_path, const std::string& in_rename);
    tracker_element_summary(const std::vector<int>& in_path);

    // copy constructor
    tracker_element_summary(const SharedElementSummary& in_c);


    void assign(const SharedElementSummary& in_c);
    void assign(const std::string& in_path, const std::string& in_rename);
    void assign(const std::vector<std::string>& in_path, const std::string& in_rename);
    void assign(const std::string& in_path);
    void assign(const std::vector<std::string>& in_path);
    void assign(const std::vector<int>& in_path, const std::string& in_rename);
    void assign(const std::vector<int>& in_path);


    shared_tracker_element parent_element;
    std::vector<int> resolved_path;
    std::string rename;

    void reset() {
        parent_element.reset();
        resolved_path.clear();
        rename = "";
    }

protected:
    void parse_path(const std::vector<std::string>& in_path, const std::string& in_rename);
};

// Generic serializer class to allow easy swapping of serializers
class tracker_element_serializer {
public:
    tracker_element_serializer() { }

    using rename_map = std::map<shared_tracker_element, SharedElementSummary>;

    virtual ~tracker_element_serializer() { }

    virtual int serialize(shared_tracker_element in_elem, 
            std::ostream &stream, std::shared_ptr<rename_map> name_map) = 0;

    // Fields extracted from a summary path need to preserialize their parent
    // paths or updates may not happen in the expected fashion, serializers should
    // call this when necessary
    static void pre_serialize_path(const SharedElementSummary& in_summary);
    static void post_serialize_path(const SharedElementSummary& in_summary);
protected:
    kis_mutex mutex;
};

// Get an element using path semantics
// Full std::string path
shared_tracker_element get_tracker_element_path(const std::string& in_path, shared_tracker_element elem);
// Split std::string path
shared_tracker_element get_tracker_element_path(const std::vector<std::string>& in_path, 
        shared_tracker_element elem);
// Resolved field ID path
shared_tracker_element get_tracker_element_path(const std::vector<int>& in_path, 
        shared_tracker_element elem);

// Get a list of elements from a complex path which may include vectors
// or key maps.  Returns a vector of all elements within that map.
// For example, for a field spec:
// 'dot11.device/dot11.device.advertised.ssid.map/dot11.advertised.ssid'
// it would return a vector of dot11.advertised.ssid for every SSID in
// the dot11.device.advertised.ssid.map keyed map
std::vector<shared_tracker_element> get_tracker_element_multi_path(const std::string& in_path,
        shared_tracker_element elem);
// Split std::string path
std::vector<shared_tracker_element> get_tracker_element_multi_path(const std::vector<std::string>& in_path, 
        shared_tracker_element elem);
// Resolved field ID path
std::vector<shared_tracker_element> get_tracker_element_multi_path(const std::vector<int>& in_path, 
        shared_tracker_element elem);

// Summarize a complex record using a collection of summary elements.  The summarized
// element is returned, and the rename mapping for serialization is updated in rename.
// The element type returned is the same as the type provided.  Can only be used to 
// summarize vector and map derived objects.

// Specialized simplifications that resolve complex maps; we consider a field:field basic map to be
// the final target object so we let that fall into the final handler

std::shared_ptr<tracker_element> summarize_tracker_element_with_json(std::shared_ptr<tracker_element>, 
        const nlohmann::json& json, std::shared_ptr<tracker_element_serializer::rename_map> rename_map);

std::shared_ptr<tracker_element> summarize_tracker_element(std::shared_ptr<tracker_element_vector>,
        const std::vector<std::shared_ptr<tracker_element_summary>>&,
        std::shared_ptr<tracker_element_serializer::rename_map>);

std::shared_ptr<tracker_element> summarize_tracker_element(std::shared_ptr<tracker_element_double_map>,
        const std::vector<std::shared_ptr<tracker_element_summary>>&,
        std::shared_ptr<tracker_element_serializer::rename_map>);

std::shared_ptr<tracker_element> summarize_tracker_element(std::shared_ptr<tracker_element_int_map>,
        const std::vector<std::shared_ptr<tracker_element_summary>>&,
        std::shared_ptr<tracker_element_serializer::rename_map>);

std::shared_ptr<tracker_element> summarize_tracker_element(std::shared_ptr<tracker_element_string_map>,
        const std::vector<std::shared_ptr<tracker_element_summary>>&,
        std::shared_ptr<tracker_element_serializer::rename_map>);

std::shared_ptr<tracker_element> summarize_tracker_element(std::shared_ptr<tracker_element_mac_map>,
        const std::vector<std::shared_ptr<tracker_element_summary>>&,
        std::shared_ptr<tracker_element_serializer::rename_map>);

std::shared_ptr<tracker_element> summarize_tracker_element(std::shared_ptr<tracker_element_macfilter_map>,
        const std::vector<std::shared_ptr<tracker_element_summary>>&,
        std::shared_ptr<tracker_element_serializer::rename_map>);

std::shared_ptr<tracker_element> summarize_tracker_element(std::shared_ptr<tracker_element_device_key_map>,
        const std::vector<std::shared_ptr<tracker_element_summary>>&,
        std::shared_ptr<tracker_element_serializer::rename_map>);

std::shared_ptr<tracker_element> summarize_tracker_element(std::shared_ptr<tracker_element_uuid_map>,
        const std::vector<std::shared_ptr<tracker_element_summary>>&,
        std::shared_ptr<tracker_element_serializer::rename_map>);

std::shared_ptr<tracker_element> summarize_tracker_element(std::shared_ptr<tracker_element_hashkey_map>,
        const std::vector<std::shared_ptr<tracker_element_summary>>&,
        std::shared_ptr<tracker_element_serializer::rename_map>);

// Final single resolved generic element summarization
std::shared_ptr<tracker_element> summarize_tracker_element(std::shared_ptr<tracker_element>,
        const std::vector<std::shared_ptr<tracker_element_summary>>&,
        std::shared_ptr<tracker_element_serializer::rename_map>);

// Handle comparing fields
bool sort_tracker_element_less(const std::shared_ptr<tracker_element> lhs, 
        const std::shared_ptr<tracker_element> rhs);

// Compare fields, in a faster, but not type-safe, way.  This should be used only when
// the caller is positive that both fields are of the same type, but avoids a number of
// compares.
bool fast_sort_tracker_element_less(const std::shared_ptr<tracker_element> lhs, 
        const std::shared_ptr<tracker_element> rhs) noexcept;

#endif
