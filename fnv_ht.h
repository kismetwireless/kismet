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

#ifndef __HT_H__
#define __HT_H__

#include <string>
#include <stdexcept>
#include <stdint.h>

// High-speed hash lookup table using FNV; uses a hashed string
// as the key and returns a pointer to the cached string.  We never
// expire cache.
//
// fnv_ht uses raw pointers to try to opimize string cache for things 
// in Kismet like the SSID and encryption strings; using smart pointers
// means another 8 bytes lost per emtry.
//
// It should only be used for full-lifetime purposes (like global string 
// caching) because there is no way to know when the users of the cached
// strings have released them.

// FNV non-cryptographically-safe hash 
#define FNV_OFFSET  14695981039346656037UL
#define FNV_PRIME   1099511628211UL

class fnv_ht_strcache {
public:
    fnv_ht_strcache() {
        entries_ = new ht_entry[32];
        length_ = 0;
        capacity_ = 32;
    }

    ~fnv_ht_strcache() {
        // Delete the cached elements.  Because these are raw pointers, 
        // NOTHING CAN BE USING THESE at the time of destruction.
        for (size_t i = 0; i < capacity_; i++) {
            ht_entry entry = entries_[i];
            if (entry.str_ != nullptr) {
                delete entry.str_;
            }
        }

        delete[] entries_;
    }
 
    std::string *find(const char *str) {
        auto hash = hash_key(str);

        size_t index = (size_t)(hash & (uint64_t)(capacity_ - 1));
        size_t original_index = index;

        /* Look through all colliding entities for this slot */
        while (entries_[index].str_ != nullptr) {
            if (entries_[index].original_index != original_index) {
                index++;

                if (index >= capacity_) {
                    index = 0;
                }

                continue;
            }

            /* Direct match */
            if (*(entries_[index].str_) == str) {
                return entries_[index].str_;
            }

            /* Linear probing */
            index++;
            if (index >= capacity_) {
                index = 0;
            }
        }

        return nullptr;
    }

    std::string *cache(const std::string& str) {
        return cache(str.c_str());
    }

    std::string *cache(const char *str) {
        auto ret = find(str);

        if (ret != nullptr)
            return ret;

        // Insert if not found
        if (length_ >= capacity_ / 2)
            expand();

        ret = new std::string(str);

        return set_entry(entries_, capacity_, ret, length_);
    }

    const size_t length() {
        return length_;
    };

    const size_t capacity() {
        return capacity_;
    };

protected:
    typedef struct ht_entry_ {
        ht_entry_() {
            str_ = nullptr;
            original_index = 0;
        }

        std::string *str_;
        size_t original_index;
    } ht_entry;

    ht_entry *entries_;
    size_t capacity_;
    size_t length_;

    uint64_t hash_key(const char *key) {
        uint64_t hash = FNV_OFFSET;

        for (const char *p = key; *p; p++) {
            hash ^= (uint64_t)(unsigned char)(*p);
            hash *= FNV_PRIME;
        }

        return hash;
    }

    std::string *set_entry(ht_entry *entries, size_t capacity,
            std::string *key, size_t &plength) {
        uint64_t hash = hash_key(key->c_str());
        size_t index = (size_t)(hash & (uint64_t)(capacity - 1));
        size_t original_index = index;

        while (entries[index].str_ != nullptr) {
            // Update existing
            if ((*entries[index].str_) == *key) {
                entries[index].original_index = original_index;
                return entries[index].str_;
            }

            // Linear probe to find next empty slot
            index++;
            if (index >= capacity) {
                index = 0;
            }
        }

        /* Create a new entry entirely */
        auto key_d = key;
        plength++;

        entries[index].str_ = key_d;
        entries[index].original_index = original_index;

        return key_d;
    }

    void expand() {
        size_t new_capacity = capacity_ * 2;
        size_t plength = 0;

        if (new_capacity < capacity_) {
            throw std::runtime_error("Hash table is larger than size_t");
        }

        ht_entry *new_entries = new ht_entry[new_capacity];

        /* Move entry to a new hash */
        for (size_t i = 0; i < capacity_; i++) {
            ht_entry entry = entries_[i];
            if (entry.str_ != nullptr) {
                set_entry(new_entries, new_capacity, entry.str_, plength);
            }
        }

        /* Remove old entries */
        delete[] entries_;
        entries_ = new_entries;
        capacity_ = new_capacity;
    }

};

#endif
