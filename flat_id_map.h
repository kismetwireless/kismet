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

#ifndef __FLAT_ID_MAP_H__
#define __FLAT_ID_MAP_H__

#include <algorithm>
#include <utility>
#include <vector>

// Small map backed by a single vector, in insertion order with a linear search.  Field
// maps hold a few dozen entries keyed by field id, where a hash table spends more on
// buckets and growth than on the entries themselves.
template<typename K, typename V>
class flat_id_map {
public:
    using key_type = K;
    using mapped_type = V;
    using value_type = std::pair<K, V>;
    using container_type = std::vector<value_type>;
    using iterator = typename container_type::iterator;
    using const_iterator = typename container_type::const_iterator;
    using size_type = typename container_type::size_type;

    iterator begin() noexcept { return values.begin(); }
    iterator end() noexcept { return values.end(); }
    const_iterator begin() const noexcept { return values.begin(); }
    const_iterator end() const noexcept { return values.end(); }
    const_iterator cbegin() const noexcept { return values.cbegin(); }
    const_iterator cend() const noexcept { return values.cend(); }

    size_type size() const noexcept { return values.size(); }
    bool empty() const noexcept { return values.empty(); }
    void clear() noexcept { values.clear(); }

    void reserve(size_type n) { values.reserve(n); }
    void shrink_to_fit() { values.shrink_to_fit(); }

    iterator find(const K& k) noexcept {
        return std::find_if(values.begin(), values.end(),
                [&k](const value_type& v) { return v.first == k; });
    }

    const_iterator find(const K& k) const noexcept {
        return std::find_if(values.begin(), values.end(),
                [&k](const value_type& v) { return v.first == k; });
    }

    size_type count(const K& k) const noexcept {
        return find(k) == end() ? 0 : 1;
    }

    std::pair<iterator, bool> insert(const value_type& v) {
        auto i = find(v.first);
        if (i != end())
            return {i, false};
        grow();
        values.push_back(v);
        return {values.end() - 1, true};
    }

    std::pair<iterator, bool> insert(value_type&& v) {
        auto i = find(v.first);
        if (i != end())
            return {i, false};
        grow();
        values.push_back(std::move(v));
        return {values.end() - 1, true};
    }

    template<typename... Args>
    std::pair<iterator, bool> emplace(Args&&... args) {
        return insert(value_type(std::forward<Args>(args)...));
    }

    V& operator[](const K& k) {
        auto i = find(k);
        if (i != end())
            return i->second;
        grow();
        values.emplace_back(k, V{});
        return values.back().second;
    }

    iterator erase(const_iterator i) { return values.erase(i); }
    iterator erase(iterator i) { return values.erase(i); }
    iterator erase(const_iterator first, const_iterator last) { return values.erase(first, last); }

    size_type erase(const K& k) {
        auto i = find(k);
        if (i == end())
            return 0;
        values.erase(i);
        return 1;
    }

protected:
    // Grow by an eighth instead of doubling; most maps are sized once at creation and
    // gain only a few entries afterwards
    void grow() {
        if (values.size() == values.capacity())
            values.reserve(values.size() + std::max<size_type>(4, values.size() / 8));
    }

    container_type values;
};

#endif
