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

// Type safety can be disabled by commenting out this definition.  This will no
// longer validate that the type of element matches the use; if used improperly this
// will lead to "interesting" errors (for simple types) or segfaults (with complex
// types, either due to a null pointer or due to overlapping union values in the
// complex pointer).
//
// On the flip side, validating the type is one of the most commonly called 
// functions, and if this presents a problem, turning off type checking can cull 
// a large percentage of the function calls

#define TE_TYPE_SAFETY  1

#ifndef TE_TYPE_SAFETY
// If there's no type safety, define an empty except_type_mismatch
#define except_type_mismatch(V) ;
#endif

class GlobalRegistry;
class EntryTracker;
class TrackerElement;

using SharedTrackerElement = std::shared_ptr<TrackerElement>;

// Very large key wrapper class, needed for keying devices with per-server/per-phy 
// but consistent keys.  Components are store in big-endian format internally so that
// they are consistent across platforms.
//
// Values are exported as big endian, hex, [SPKEY]_[DKEY]
class TrackedDeviceKey {
public:
    friend bool operator <(const TrackedDeviceKey& x, const TrackedDeviceKey& y);
    friend bool operator ==(const TrackedDeviceKey& x, const TrackedDeviceKey& y);
    friend std::ostream& operator<<(std::ostream& os, const TrackedDeviceKey& k);

    TrackedDeviceKey();

    TrackedDeviceKey(const TrackedDeviceKey& k);

    // Create a key from a server/phy component and device component
    TrackedDeviceKey(uint64_t in_spkey, uint64_t in_dkey);

    // Create a key from independent components
    TrackedDeviceKey(uint32_t in_skey, uint32_t in_pkey, uint64_t in_dkey);

    // Create a key from a cached spkey and a mac address
    TrackedDeviceKey(uint64_t in_spkey, mac_addr in_device);

    // Create a key from a computed hashes and a mac address
    TrackedDeviceKey(uint32_t in_skey, uint32_t in_pkey, mac_addr in_device);

    // Create a key from an incoming string/exported key; this should only happen during
    // deserialization and rest queries; it's fairly expensive otherwise
    TrackedDeviceKey(std::string in_keystr);

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

bool operator <(const TrackedDeviceKey& x, const TrackedDeviceKey& y);
bool operator ==(const TrackedDeviceKey& x, const TrackedDeviceKey& y);
std::ostream& operator<<(std::ostream& os, const TrackedDeviceKey& k);

// Types of fields we can track and automatically resolve
// Statically assigned type numbers which MUST NOT CHANGE as things go forwards for 
// binary/fast serialization, new types must be added to the end of the list
enum TrackerType {
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
    TrackerElement() {
        Initialize();
    }

    TrackerElement(TrackerType type);
    TrackerElement(TrackerType type, int id);

    virtual ~TrackerElement();

    void Initialize();

    // Factory-style for easily making more of the same if we're subclassed
    virtual std::shared_ptr<TrackerElement> clone_type() {
        auto dup1 = std::make_shared<TrackerElement>(get_type(), get_id());
        return dup1;
    }

    virtual std::shared_ptr<TrackerElement> clone_type(int in_id) {
        auto dup1 = clone_type();
        dup1->set_id(in_id);

        return dup1;
    }

    // Called prior to serialization output
    virtual void pre_serialize() { }

    // Called after serialization is completed
    virtual void post_serialize() { }

    int get_id() {
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

    constexpr TrackerType get_type() const { 
        return type; 
    }

    using tracked_vector = std::vector<SharedTrackerElement>;
    using vector_iterator = std::vector<SharedTrackerElement>::iterator;
    using vector_const_iterator = std::vector<SharedTrackerElement>::const_iterator;

    using tracked_map = std::multimap<int, SharedTrackerElement>;
    using map_iterator = std::multimap<int, SharedTrackerElement>::iterator;
    using map_const_iterator = std::multimap<int, SharedTrackerElement>::const_iterator;
    using tracked_pair = std::pair<int, SharedTrackerElement>;

    using tracked_int_map = std::map<int, SharedTrackerElement>;
    using int_map_iterator = std::map<int, SharedTrackerElement>::iterator;
    using int_map_const_iterator = std::map<int, SharedTrackerElement>::const_iterator;
    using int_map_pair = std::pair<int, SharedTrackerElement>;

    using tracked_mac_map = std::map<mac_addr, SharedTrackerElement>;
    using mac_map_iterator = std::map<mac_addr, SharedTrackerElement>::iterator;
    using mac_map_const_iterator = std::map<mac_addr, SharedTrackerElement>::const_iterator;
    using mac_map_pair = std::pair<mac_addr, SharedTrackerElement>;

    using tracked_string_map = std::map<std::string, SharedTrackerElement>;
    using string_map_iterator = std::map<std::string, SharedTrackerElement>::iterator;
    using string_map_const_iterator = std::map<std::string, SharedTrackerElement>::const_iterator;
    using string_map_pair = std::pair<std::string, SharedTrackerElement>;

    using tracked_double_map = std::map<double, SharedTrackerElement>;
    using double_map_iterator = std::map<double, SharedTrackerElement>::iterator;
    using double_map_const_iterator = std::map<double, SharedTrackerElement>::const_iterator;
    using double_map_pair = std::pair<double, SharedTrackerElement>;

    using tracked_key_map = std::map<TrackedDeviceKey, SharedTrackerElement>; 
    using key_map_iterator =  std::map<TrackedDeviceKey, SharedTrackerElement>::iterator;
    using key_map_const_iterator = std::map<TrackedDeviceKey, SharedTrackerElement>::const_iterator;
    using key_map_pair = std::pair<TrackedDeviceKey, SharedTrackerElement>;

    // Getter per type, use templated GetTrackerValue() for easy fetch
    std::string get_string() const {
        except_type_mismatch(TrackerString);
        return *(dataunion.string_value);
    }

    uint8_t get_uint8() const {
        except_type_mismatch(TrackerUInt8);
        return dataunion.uint8_value;
    }

    int8_t get_int8() const {
        except_type_mismatch(TrackerInt8);
        return dataunion.int8_value;
    }

    uint16_t get_uint16() const {
        except_type_mismatch(TrackerUInt16);
        return dataunion.uint16_value;
    }

    int16_t get_int16() const {
        except_type_mismatch(TrackerInt16);
        return dataunion.int16_value;
    }

    uint32_t get_uint32() const {
        except_type_mismatch(TrackerUInt32);
        return dataunion.uint32_value;
    }

    int32_t get_int32() const {
        except_type_mismatch(TrackerInt32);
        return dataunion.int32_value;
    }

    uint64_t get_uint64() const {
        except_type_mismatch(TrackerUInt64);
        return dataunion.uint64_value;
    }

    int64_t get_int64() const {
        except_type_mismatch(TrackerInt64);
        return dataunion.int64_value;
    }

    float get_float() const {
        except_type_mismatch(TrackerFloat);
        return dataunion.float_value;
    }

    double get_double() const {
        except_type_mismatch(TrackerDouble);
        return dataunion.double_value;
    }

    mac_addr get_mac() const {
        except_type_mismatch(TrackerMac);
        return (*(dataunion.mac_value));
    }

    tracked_vector *get_vector() const {
        except_type_mismatch(TrackerVector);
        return dataunion.subvector_value;
    }

    SharedTrackerElement get_vector_value(unsigned int offt) const {
        except_type_mismatch(TrackerVector);
        return (*dataunion.subvector_value)[offt];
    }

    void reserve_vector(unsigned int sz) {
        except_type_mismatch(TrackerVector);
        (*dataunion.subvector_value).reserve(sz);
    }

    tracked_map *get_map() const {
        except_type_mismatch(TrackerMap);
        return dataunion.submap_value;
    }

    template<class T> std::shared_ptr<T> get_map_value_as(int fn) {
        return std::static_pointer_cast<T>(get_map_value(fn));
    }

    SharedTrackerElement get_map_value(int fn) {
        // Soft-bounce if we're not a map or we cause a lot of problems
        if (get_type() != TrackerMap)
            return NULL;

        auto i = dataunion.submap_value->find(fn);

        if (i == dataunion.submap_value->end())
            return NULL;

        return i->second;
    }

    tracked_int_map *get_intmap() const {
        except_type_mismatch(TrackerIntMap);
        return dataunion.subintmap_value;
    }

    tracked_mac_map *get_macmap() const {
        except_type_mismatch(TrackerMacMap);
        return dataunion.submacmap_value;
    }

    tracked_string_map *get_stringmap() const {
        except_type_mismatch(TrackerStringMap);
        return dataunion.substringmap_value;
    }

    tracked_double_map *get_doublemap() const {
        except_type_mismatch(TrackerDoubleMap);
        return dataunion.subdoublemap_value;
    }

    tracked_key_map *get_keymap() const {
        except_type_mismatch(TrackerKeyMap);
        return dataunion.subkeymap_value;
    }

    TrackedDeviceKey get_key() {
        except_type_mismatch(TrackerKey);
        return *(dataunion.key_value);
    }

    uuid get_uuid() const {
        except_type_mismatch(TrackerUuid);
        return *(dataunion.uuid_value);
    }

    // Overloaded set
    void set(const std::string& v) {
        except_type_mismatch(TrackerString);
        *(dataunion.string_value) = v;
    }

    void set(uint8_t v) {
        except_type_mismatch(TrackerUInt8);
        dataunion.uint8_value = v;
    }

    void set(int8_t v) {
        except_type_mismatch(TrackerInt8);
        dataunion.int8_value = v;
    }

    void set(uint16_t v) {
        except_type_mismatch(TrackerUInt16);
        dataunion.uint16_value = v;
    }

    void set(int16_t v) {
        except_type_mismatch(TrackerInt16);
        dataunion.int16_value = v;
    }

    void set(uint32_t v) {
        except_type_mismatch(TrackerUInt32);
        dataunion.uint32_value = v;
    }

    void set(int32_t v) {
        except_type_mismatch(TrackerInt32);
        dataunion.int32_value = v;
    }

    void set(uint64_t v) {
        except_type_mismatch(TrackerUInt64);
        dataunion.uint64_value = v;
    }

    void set(int64_t v) {
        except_type_mismatch(TrackerInt64);
        dataunion.int64_value = v;
    }

    void set(float v) {
        except_type_mismatch(TrackerFloat);
        dataunion.float_value = v;
    }

    void set(double v) {
        except_type_mismatch(TrackerDouble);
        dataunion.double_value = v;
    }

    void set(const mac_addr& v) {
        except_type_mismatch(TrackerMac);
        // mac has overrided =
        *(dataunion.mac_value) = v;
    }

    void set(const uuid& v) {
        except_type_mismatch(TrackerUuid);
        // uuid has overrided =
        *(dataunion.uuid_value) = v;
    }

    void set(const TrackedDeviceKey& k) {
        except_type_mismatch(TrackerKey);
        *(dataunion.key_value) = k;
    }

    // Coercive set - attempt to fit incoming data into the type (for basic types)
    // Set string values - usable for strings, macs, UUIDs
    void coercive_set(const std::string& in_str);
    // Set numerical values - usable for all numeric types
    void coercive_set(double in_num);
    // Attempt to coerce one complete item to another
    void coercive_set(const SharedTrackerElement& in_elem);

    size_t size();

    vector_iterator vec_begin();
    vector_iterator vec_end();

    map_iterator begin();
    map_iterator end();
    map_iterator find(int k);
    void clear_map();
    size_t size_map();

    void add_map(int f, SharedTrackerElement s);
    void add_map(SharedTrackerElement s); 
    void del_map(int f);
    void del_map(SharedTrackerElement s);
    void del_map(map_iterator i);
    void insert_map(tracked_pair p);

    void add_intmap(int i, SharedTrackerElement s);
    void del_intmap(int i);
    void del_intmap(int_map_iterator i);
    void clear_intmap();
    void insert_intmap(int_map_pair p);
    size_t size_intmap();

    SharedTrackerElement get_intmap_value(int idx);
    int_map_iterator int_begin();
    int_map_iterator int_end();
    int_map_iterator int_find(int k);

    void add_macmap(mac_addr i, SharedTrackerElement s);
    void del_macmap(mac_addr i);
    void del_macmap(mac_map_iterator i);
    void clear_macmap();
    void insert_macmap(mac_map_pair p);
    size_t size_macmap();

    SharedTrackerElement get_macmap_value(int idx);
    mac_map_iterator mac_begin();
    mac_map_iterator mac_end();
    mac_map_iterator mac_find(mac_addr k);

    void add_stringmap(std::string i, SharedTrackerElement s);
    void del_stringmap(std::string i);
    void del_stringmap(string_map_iterator i);
    void clear_stringmap();
    void insert_stringmap(string_map_pair p);
    size_t size_stringmap();

    SharedTrackerElement get_stringmap_value(std::string idx);
    string_map_iterator string_begin();
    string_map_iterator string_end();
    string_map_iterator string_find(std::string k);

    void add_doublemap(double i, SharedTrackerElement s);
    void del_doublemap(double i);
    void del_doublemap(double_map_iterator i);
    void clear_doublemap();
    void insert_doublemap(double_map_pair p);
    size_t size_doublemap();

    SharedTrackerElement get_doublemap_value(double idx);
    double_map_iterator double_begin();
    double_map_iterator double_end();
    double_map_iterator double_find(double k);

    void add_vector(SharedTrackerElement s);
    void del_vector(unsigned int p);
    void del_vector(vector_iterator i);
    void clear_vector();
    size_t size_vector();

    // Set byte array values
    void set_bytearray(uint8_t *d, size_t len);
    void set_bytearray(const std::shared_ptr<uint8_t>& d, size_t len);
    void set_bytearray(const std::string& s);
    size_t get_bytearray_size();
    std::shared_ptr<uint8_t> get_bytearray();
    std::string get_bytearray_str();

    // Do our best to increment a value
    TrackerElement& operator++(const int);

    // Do our best to decrement a value
    TrackerElement& operator--(const int);

    // Do our best to do compound addition
    TrackerElement& operator+=(const int& v);
    TrackerElement& operator+=(const unsigned int& v);
    TrackerElement& operator+=(const float& v);
    TrackerElement& operator+=(const double& v);

    TrackerElement& operator+=(const int64_t& v);
    TrackerElement& operator+=(const uint64_t& v);

    // Do our best to do compound subtraction
    TrackerElement& operator-=(const int& v);
    TrackerElement& operator-=(const unsigned int& v);
    TrackerElement& operator-=(const float& v);
    TrackerElement& operator-=(const double& v);

    TrackerElement& operator-=(const int64_t& v);
    TrackerElement& operator-=(const uint64_t& v);

    // Do our best for equals comparison
    
    // Comparing tracked elements themselves presents weird problems - how do we deal with 
    // conflicting ids but equal data?  Lets see if we actually need it.  /D
    // friend bool operator==(TrackerElement &te1, TrackerElement &te2);

    friend bool operator==(const TrackerElement& te1, int8_t i);
    friend bool operator==(const TrackerElement& te1, uint8_t i);
    friend bool operator==(const TrackerElement& te1, int16_t i);
    friend bool operator==(const TrackerElement& te1, uint16_t i);
    friend bool operator==(const TrackerElement& te1, int32_t i);
    friend bool operator==(const TrackerElement& te1, uint32_t i);
    friend bool operator==(const TrackerElement& te1, int64_t i);
    friend bool operator==(const TrackerElement& te1, uint64_t i);
    friend bool operator==(const TrackerElement& te1, float f);
    friend bool operator==(const TrackerElement& te1, double d);
    friend bool operator==(const TrackerElement& te1, const mac_addr& m);
    friend bool operator==(const TrackerElement& te1, const uuid& u);

    friend bool operator<(const TrackerElement& te1, int8_t i);
    friend bool operator<(const TrackerElement& te1, uint8_t i);
    friend bool operator<(const TrackerElement& te1, int16_t i);
    friend bool operator<(const TrackerElement& te1, uint16_t i);
    friend bool operator<(const TrackerElement& te1, int32_t i);
    friend bool operator<(const TrackerElement& te1, uint32_t i);
    friend bool operator<(const TrackerElement& te1, int64_t i);
    friend bool operator<(const TrackerElement& te1, uint64_t i);
    friend bool operator<(const TrackerElement& te1, float f);
    friend bool operator<(const TrackerElement& te1, double d);
    friend bool operator<(const TrackerElement& te1, const mac_addr& m);
    friend bool operator<(const TrackerElement& te1, const uuid& u);

    // Valid for comparing two fields of the same type
    friend bool operator<(const TrackerElement &te1, const TrackerElement &te2);
    friend bool operator<(const SharedTrackerElement& te1, const SharedTrackerElement& te2);

    friend bool operator>(const TrackerElement& te1, int8_t i);
    friend bool operator>(const TrackerElement& te1, uint8_t i);
    friend bool operator>(const TrackerElement& te1, int16_t i);
    friend bool operator>(const TrackerElement& te1, uint16_t i);
    friend bool operator>(const TrackerElement& te1, int32_t i);
    friend bool operator>(const TrackerElement& te1, uint32_t i);
    friend bool operator>(const TrackerElement& te1, int64_t i);
    friend bool operator>(const TrackerElement& te1, uint64_t i);
    friend bool operator>(const TrackerElement& te1, float f);
    friend bool operator>(const TrackerElement& te1, double d);
    // We don't have > operators on mac or uuid
   
    // Bitwise
    TrackerElement& operator|=(int8_t i);
    TrackerElement& operator|=(uint8_t i);
    TrackerElement& operator|=(int16_t i);
    TrackerElement& operator|=(uint16_t i);
    TrackerElement& operator|=(int32_t i);
    TrackerElement& operator|=(uint32_t i);
    TrackerElement& operator|=(int64_t i);
    TrackerElement& operator|=(uint64_t i);

    TrackerElement& operator&=(int8_t i);
    TrackerElement& operator&=(uint8_t i);
    TrackerElement& operator&=(int16_t i);
    TrackerElement& operator&=(uint16_t i);
    TrackerElement& operator&=(int32_t i);
    TrackerElement& operator&=(uint32_t i);
    TrackerElement& operator&=(int64_t i);
    TrackerElement& operator&=(uint64_t i);

    TrackerElement& operator^=(int8_t i);
    TrackerElement& operator^=(uint8_t i);
    TrackerElement& operator^=(int16_t i);
    TrackerElement& operator^=(uint16_t i);
    TrackerElement& operator^=(int32_t i);
    TrackerElement& operator^=(uint32_t i);
    TrackerElement& operator^=(int64_t i);
    TrackerElement& operator^=(uint64_t i);

    SharedTrackerElement operator[](int i);
    SharedTrackerElement operator[](const mac_addr& i);

    // Type to human readable string
    static std::string type_to_string(TrackerType t);
    // Type to machine readable string
    static std::string type_to_typestring(TrackerType t);
    // Machine readable string to type
    static TrackerType typestring_to_type(std::string s);

protected:
    // Generic coercion exception
#ifdef TE_TYPE_SAFETY
    inline void except_type_mismatch(const TrackerType t) const {
        if (type != t) {
            throw std::runtime_error(fmt::format("tracked element type mismatch, element is {} "
                        "but referenced as {}", type_to_string(this->type), type_to_string(t)));
        }
    }
#endif

    TrackerType type;
    int tracked_id;

    // Overridden name for this instance only
    std::string local_name;

    size_t bytearray_value_len;

    // We could make these all one type, but then we'd have odd interactions
    // with incrementing and I'm not positive that's safe in all cases
    union du {
        std::string *string_value;

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

        // Field ID,Element keyed map
        tracked_map *submap_value;

        // Index int,Element keyed map
        tracked_int_map *subintmap_value;

        // Index mac,element keyed map
        tracked_mac_map *submacmap_value;

        // Index string,element keyed map
        tracked_string_map *substringmap_value;

        // Index double,element keyed map
        tracked_double_map *subdoublemap_value;

        // Index devicekey,element keyed map
        tracked_key_map *subkeymap_value;

        tracked_vector *subvector_value;

        mac_addr *mac_value;

        uuid *uuid_value;

        TrackedDeviceKey *key_value;

        std::shared_ptr<uint8_t> *bytearray_value;

        void *custom_value;
    } dataunion;

    
};

// Helper child classes
class TrackerElementVector {
protected:
    SharedTrackerElement val;

public:
    using iterator = TrackerElement::vector_iterator; 
    using const_iterator = TrackerElement::vector_const_iterator;

    TrackerElementVector() {
        val = NULL;
    }

    TrackerElementVector(SharedTrackerElement t) {
        val = t;
    }

    virtual ~TrackerElementVector() { }

    virtual iterator begin() {
        return val->vec_begin();
    }

    virtual iterator end() {
        return val->vec_end();
    }

    virtual void clear() {
        return val->clear_vector();
    }

    virtual void push_back(SharedTrackerElement i) {
        return val->add_vector(i);
    }

    virtual void erase(unsigned int p) {
        return val->del_vector(p);
    }

    virtual void erase(iterator i) {
        return val->del_vector(i);
    }

    virtual size_t size() {
        return val->size_vector();
    }

    virtual void reserve(unsigned int sz) {
        val->reserve_vector(sz);
    }

    SharedTrackerElement operator[](unsigned int i) {
        return *(begin() + i);
    }

};

class TrackerElementMap {
protected:
    SharedTrackerElement val;

public:
    TrackerElementMap() {
        val = NULL;
    }

    TrackerElementMap(SharedTrackerElement t) {
        val = t;
    }

    virtual ~TrackerElementMap() { }

public:
    using iterator = TrackerElement::map_iterator;
    using const_iterator = TrackerElement::map_const_iterator;
    using pair = TrackerElement::tracked_pair;

    virtual iterator begin() {
        return val->begin();
    }

    virtual iterator end() {
        return val->end();
    }

    virtual iterator find(int k) {
        return val->find(k);
    }

    virtual void insert(pair p) {
        return val->insert_map(p);
    }

    virtual void erase(iterator i) {
        return val->del_map(i);
    }

    virtual void clear() {
        return val->clear_map();
    }

    virtual size_t size() {
        return val->size_map();
    }
};

class TrackerElementKeyMap {
protected:
    SharedTrackerElement val;

public:
    TrackerElementKeyMap() {
        val = NULL;
    }

    TrackerElementKeyMap(SharedTrackerElement t) {
        val = t;
    }

    virtual ~TrackerElementKeyMap() { }

public:
    using iterator = TrackerElement::key_map_iterator;
    using const_iterator = TrackerElement::key_map_const_iterator;
    using pair = TrackerElement::key_map_pair;

    virtual iterator begin() {
        return val->get_keymap()->begin();
    }

    virtual iterator end() {
        return val->get_keymap()->end();
    }

    virtual iterator find(TrackedDeviceKey k) {
        return val->get_keymap()->find(k);
    }

    virtual void insert(pair p) {
        val->get_keymap()->insert(p);
    }

    virtual void erase(iterator i) {
        val->get_keymap()->erase(i);
    }

    virtual void clear() {
        return val->get_keymap()->clear();
    }

    virtual size_t size() {
        return val->get_keymap()->size();
    }
};

class TrackerElementIntMap {
protected:
    SharedTrackerElement val;

public:
    TrackerElementIntMap() {
        val = NULL;
    }

    TrackerElementIntMap(SharedTrackerElement t) {
        val = t;
    }

    virtual ~TrackerElementIntMap() { }

public:
    using iterator = TrackerElement::int_map_iterator;
    using const_iterator = TrackerElement::int_map_const_iterator;
    using pair = TrackerElement::int_map_pair;

    virtual iterator begin() {
        return val->int_begin();
    }

    virtual iterator end() {
        return val->int_end();
    }

    virtual iterator find(int k) {
        return val->int_find(k);
    }

    virtual void insert(pair p) {
        return val->insert_intmap(p);
    }

    virtual void erase(iterator i) {
        return val->del_intmap(i);
    }

    virtual void clear() {
        return val->clear_intmap();
    }

    virtual size_t size() {
        return val->size_intmap();
    }
};

class TrackerElementStringMap {
protected:
    SharedTrackerElement val;

public:
    TrackerElementStringMap() {
        val = NULL;
    }

    TrackerElementStringMap(SharedTrackerElement t) {
        val = t;
    }

    virtual ~TrackerElementStringMap() { }

public:
    using iterator = TrackerElement::string_map_iterator;
    using const_iterator = TrackerElement::string_map_const_iterator;
    using pair = TrackerElement::string_map_pair;

    virtual iterator begin() {
        return val->string_begin();
    }

    virtual iterator end() {
        return val->string_end();
    }

    virtual iterator find(std::string k) {
        return val->string_find(k);
    }

    virtual void insert(pair p) {
        return val->insert_stringmap(p);
    }

    virtual void erase(iterator i) {
        return val->del_stringmap(i);
    }

    virtual void clear() {
        return val->clear_stringmap();
    }

    virtual size_t size() {
        return val->size_stringmap();
    }
};

class TrackerElementMacMap {
protected:
    SharedTrackerElement val;

public:
    TrackerElementMacMap() {
        val = NULL;
    }

    TrackerElementMacMap(SharedTrackerElement t) {
        val = t;
    }

    virtual ~TrackerElementMacMap() { }

public:
    using iterator = TrackerElement::mac_map_iterator;
    using const_iterator = TrackerElement::mac_map_const_iterator;
    using pair = TrackerElement::mac_map_pair;

    virtual iterator begin() {
        return val->mac_begin();
    }

    virtual iterator end() {
        return val->mac_end();
    }

    virtual iterator find(mac_addr k) {
        return val->mac_find(k);
    }

    virtual void insert(pair p) {
        return val->insert_macmap(p);
    }

    virtual void erase(iterator i) {
        return val->del_macmap(i);
    }

    virtual void clear() {
        return val->clear_macmap();
    }

    virtual size_t size() {
        return val->size_macmap();
    }
};

class TrackerElementDoubleMap {
protected:
    SharedTrackerElement val;

public:
    TrackerElementDoubleMap() {
        val = NULL;
    }

    TrackerElementDoubleMap(SharedTrackerElement t) {
        val = t;
    }

    virtual ~TrackerElementDoubleMap() { }

public:
    using iterator = TrackerElement::double_map_iterator;
    using const_iterator = TrackerElement::double_map_const_iterator;
    using pair = TrackerElement::double_map_pair;

    virtual iterator begin() {
        return val->double_begin();
    }

    virtual iterator end() {
        return val->double_end();
    }

    virtual iterator find(double k) {
        return val->double_find(k);
    }

    virtual void insert(pair p) {
        return val->insert_doublemap(p);
    }

    virtual void erase(iterator i) {
        return val->del_doublemap(i);
    }

    virtual void clear() {
        return val->clear_doublemap();
    }

    virtual size_t size() {
        return val->size_doublemap();
    }
};

// Templated access functions

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
template<> TrackedDeviceKey GetTrackerValue(const SharedTrackerElement& e);

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
class tracker_component : public TrackerElement {

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
    // Build a basic component.  All basic components are maps.
    // Set the field id automatically.
    tracker_component(GlobalRegistry *in_globalreg, int in_id);

    // Build a component with existing map
    tracker_component(GlobalRegistry *in_globalreg, int in_id, 
            SharedTrackerElement e __attribute__((unused)));

	virtual ~tracker_component();

    // Clones the type and preserves that we're a tracker component.  
    // Complex subclasses will replace this to function as builders of
    // their own complex types.
    virtual SharedTrackerElement clone_type();

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

    std::vector<registered_field *> registered_fields;
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
