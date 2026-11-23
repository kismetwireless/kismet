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

#ifndef __DEVICETRACKER_VIEW_WALK_H__
#define __DEVICETRACKER_VIEW_WALK_H__

// A walk over a view's device list a batch at a time, kept apart from the view so test/ can
// build it alone.  The list keeps the order devices joined it; a device that leaves leaves an
// empty slot, and the empty slots are squeezed out now and then, which only ever moves a
// device to a lower slot.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace view_walk {

// Where a device is in the list, and which of the view's joins put it there: a device that
// leaves and joins again (or a record made again under its key) has a new serial at the end of
// the list.  32 bits each keep the view's presence map node at its old size.  A view's list
// is bounded by memory far below 2^32 slots (each slot is a device record of kilobytes).
// Serials wrap and are only ever compared for equality: a resume goes wrong only if the
// device last copied leaves and joins again exactly 2^32 joins of that view later, between
// two batches of one walk.
struct place {
    uint32_t slot = 0;
    uint32_t serial = 0;
};

template <typename Key>
struct cursor {
    size_t slot = 0;
    // The last device copied, by key and join serial
    std::optional<Key> last;
    uint32_t last_serial = 0;
    // The view's count of empty slots squeezed out as of the last batch
    uint64_t squeezed = 0;
};

// Emits the devices in up to max_slots slots of list from the cursor on, and moves it past
// them; false once it's at the end.  It goes on after the last device it copied when that one
// is still in the list from the same join, else steps back past every slot squeezed out
// since: devices in the list throughout are emitted at least once, some maybe twice.
//
// list[i] is a pointer-like device or null; place_of(key) is the optional place of a device
// in the list; key_of reads a device; emit takes one.
template <typename Key, typename List, typename PlaceOf, typename KeyOf, typename Emit>
bool batch(cursor<Key>& c, const List& list, uint64_t squeezed, size_t max_slots,
        PlaceOf&& place_of, KeyOf&& key_of, Emit&& emit) {
    bool resumed = false;

    if (c.last.has_value()) {
        const std::optional<place> p = place_of(*c.last);
        if (p.has_value() && p->serial == c.last_serial && p->slot < list.size()) {
            c.slot = static_cast<size_t>(p->slot) + 1;
            resumed = true;
        }
    }

    if (!resumed && squeezed != c.squeezed)
        c.slot -= static_cast<size_t>(std::min<uint64_t>(c.slot, squeezed - c.squeezed));
    c.squeezed = squeezed;

    const size_t end = c.slot + std::min(max_slots, list.size() - std::min(c.slot, list.size()));

    // A batch of empty slots has no device to go on after: the slot alone is safe
    c.last.reset();
    for (size_t i = c.slot; i < end; i++) {
        if (list[i] == nullptr)
            continue;
        emit(list[i]);
        c.last = key_of(list[i]);
    }

    c.slot = end;

    if (c.last.has_value()) {
        const std::optional<place> p = place_of(*c.last);
        if (p.has_value())
            c.last_serial = p->serial;
        else
            c.last.reset();
    }

    return c.slot < list.size();
}

}

#endif
