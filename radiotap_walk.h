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

#ifndef __RADIOTAP_WALK_H__
#define __RADIOTAP_WALK_H__

// Bounded walk of a radiotap header (radiotap.org): the extended presence words, the
// radiotap and vendor namespaces, and the fields in order with their alignment from the start
// of the header.  Every field handed to the caller is a span proven to lie inside the header.
//
// A field whose size isn't known ends the whole walk, since nothing after it can be located;
// so does a field or vendor namespace running past the header.  Vendor namespaces are skipped
// with their skip_length; bit 28 (TLVs) counts in the first or the last presence word, and
// anywhere else ends the walk.  Only the first 16 radiotap namespaces (per-antenna records) are
// reported; later ones are walked over.  The walk doesn't allocate or throw.

#include "config.h"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace kis_radiotap {

constexpr unsigned int bit_tsft = 0;
constexpr unsigned int bit_flags = 1;
constexpr unsigned int bit_rate = 2;
constexpr unsigned int bit_channel = 3;
constexpr unsigned int bit_fhss = 4;
constexpr unsigned int bit_dbm_antsignal = 5;
constexpr unsigned int bit_dbm_antnoise = 6;
constexpr unsigned int bit_lock_quality = 7;
constexpr unsigned int bit_tx_attenuation = 8;
constexpr unsigned int bit_db_tx_attenuation = 9;
constexpr unsigned int bit_dbm_tx_power = 10;
constexpr unsigned int bit_antenna = 11;
constexpr unsigned int bit_db_antsignal = 12;
constexpr unsigned int bit_db_antnoise = 13;
constexpr unsigned int bit_rx_flags = 14;
constexpr unsigned int bit_tx_flags = 15;
constexpr unsigned int bit_rts_retries = 16;
constexpr unsigned int bit_data_retries = 17;
constexpr unsigned int bit_xchannel = 18;
constexpr unsigned int bit_mcs = 19;
constexpr unsigned int bit_ampdu_status = 20;
constexpr unsigned int bit_vht = 21;
constexpr unsigned int bit_timestamp = 22;
constexpr unsigned int bit_he = 23;
constexpr unsigned int bit_he_mu = 24;
constexpr unsigned int bit_he_mu_other_user = 25;
constexpr unsigned int bit_zero_len_psdu = 26;
constexpr unsigned int bit_lsig = 27;
constexpr unsigned int bit_tlv = 28;
constexpr unsigned int bit_radiotap_namespace = 29;
constexpr unsigned int bit_vendor_namespace = 30;
constexpr unsigned int bit_ext = 31;

// OpenBSD's own meanings of bits 14-16 (net80211/ieee80211_radiotap.h)
constexpr unsigned int bit_openbsd_fcs = 14;
constexpr unsigned int bit_openbsd_hwqueue = 15;
constexpr unsigned int bit_openbsd_rssi = 16;

#if defined(SYS_OPENBSD)
constexpr bool openbsd_bits = true;
#else
constexpr bool openbsd_bits = false;
#endif

// Version, pad, it_len, first presence word
constexpr size_t header_min_len = 8;
constexpr size_t max_records = 16;

// align 0 marks a field of unknown size
struct field_layout {
    uint8_t align = 0;
    uint8_t size = 0;
};

constexpr std::array<field_layout, 28> radiotap_layouts = {{
    {8, 8},     // 0 TSFT
    {1, 1},     // 1 flags
    {1, 1},     // 2 rate
    {2, 4},     // 3 channel
    {2, 2},     // 4 FHSS
    {1, 1},     // 5 dBm antenna signal
    {1, 1},     // 6 dBm antenna noise
    {2, 2},     // 7 lock quality
    {2, 2},     // 8 TX attenuation
    {2, 2},     // 9 dB TX attenuation
    {1, 1},     // 10 dBm TX power
    {1, 1},     // 11 antenna
    {1, 1},     // 12 dB antenna signal
    {1, 1},     // 13 dB antenna noise
    {2, 2},     // 14 RX flags
    {2, 2},     // 15 TX flags
    {1, 1},     // 16 RTS retries
    {1, 1},     // 17 data retries
    {4, 8},     // 18 XChannel (BSDs; radiotap.org lists it as suggested)
    {1, 3},     // 19 MCS
    {4, 8},     // 20 A-MPDU status
    {2, 12},    // 21 VHT
    {8, 12},    // 22 timestamp
    {2, 12},    // 23 HE
    {2, 12},    // 24 HE-MU
    {2, 6},     // 25 HE-MU other user
    {1, 1},     // 26 0-length PSDU
    {2, 4},     // 27 L-SIG
}};

constexpr field_layout layout_of(unsigned int bit, bool openbsd) noexcept {
    if (openbsd) {
        if (bit == bit_openbsd_fcs)
            return {4, 4};
        // Hardware queue: never decoded, so stays unknown as it always was
        if (bit == bit_openbsd_hwqueue)
            return {};
        if (bit == bit_openbsd_rssi)
            return {1, 2};
    }

    if (bit >= radiotap_layouts.size())
        return {};

    return radiotap_layouts[bit];
}

constexpr bool layouts_valid() noexcept {
    for (unsigned int b = 0; b < 64; b++) {
        for (const bool o : {false, true}) {
            const auto l = layout_of(b, o);
            if (l.align == 0 && l.size == 0)
                continue;
            if (!std::has_single_bit(static_cast<unsigned int>(l.align)) || l.size == 0)
                return false;
        }
    }
    return true;
}
static_assert(layouts_valid(), "radiotap layouts need a power of two alignment and a size");

enum class walk_status : uint8_t {
    // Every present field was walked
    complete,
    // Stopped at an unknown field, or a field or vendor namespace past the header; the fields
    // before it were reported
    stopped,
    // Shorter than a radiotap header, or presence words past it; nothing was reported
    malformed,
};

struct walk_result {
    walk_status status = walk_status::malformed;
    // The TLV list (bit 28 in the first or last presence word, in the radiotap namespace),
    // 4-aligned after every other field; only when the walk completed
    std::optional<size_t> tlv_offset;
};

namespace detail {
    constexpr uint32_t read_le32(std::span<const uint8_t> b, size_t off) noexcept {
        return static_cast<uint32_t>(b[off]) |
            (static_cast<uint32_t>(b[off + 1]) << 8) |
            (static_cast<uint32_t>(b[off + 2]) << 16) |
            (static_cast<uint32_t>(b[off + 3]) << 24);
    }

    // Aligns offset from the start of the header and checks size bytes fit after it
    constexpr bool align_fits(size_t& offset, size_t align, size_t size, size_t len) noexcept {
        const size_t aligned = (offset + align - 1) & ~(align - 1);
        if (aligned > len || size > len - aligned)
            return false;
        offset = aligned;
        return true;
    }

    constexpr uint32_t mask_of(unsigned int bit) noexcept {
        return uint32_t{1} << bit;
    }

    // Field bits of a presence word, below the namespace and extension bits
    constexpr uint32_t field_mask = mask_of(bit_radiotap_namespace) - 1;
}

// hdr is the radiotap header itself (it_len bytes).  on_field(bit, record, field) is called
// for each field of a radiotap namespace in order; bit is the field's number in the namespace
// (0-27), record counts the radiotap namespaces from 0 (one per antenna on mac80211), and
// field is exactly the field's bytes.
template <typename F>
walk_result walk(std::span<const uint8_t> hdr, F&& on_field, bool openbsd = openbsd_bits) {
    using namespace detail;

    walk_result result;

    if (hdr.size() < header_min_len)
        return result;

    // Presence words: the first at offset 4, one more for each extension bit
    size_t n_words = 1;
    while (read_le32(hdr, 4 + 4 * (n_words - 1)) & mask_of(bit_ext)) {
        if (4 + 4 * (n_words + 1) > hdr.size())
            return result;
        n_words++;
    }

    result.status = walk_status::stopped;

    size_t offset = 4 + 4 * n_words;
    bool in_vendor = false;
    bool continued = false;
    size_t record = 0;
    bool tlv_present = false;

    for (size_t w = 0; w < n_words; w++) {
        const uint32_t present = read_le32(hdr, 4 + 4 * w);
        const bool next_radiotap = present & mask_of(bit_radiotap_namespace);
        const bool next_vendor = present & mask_of(bit_vendor_namespace);

        if (next_radiotap && next_vendor)
            return result;

        // Vendor namespace fields are inside the skip_length already passed over
        if (!in_vendor) {
            for (uint32_t bits = present & field_mask; bits != 0; bits &= bits - 1) {
                const auto b = static_cast<unsigned int>(std::countr_zero(bits));

                // Past bit 31 of a namespace's first word the bits count on from 32, and no
                // radiotap field is defined there
                if (continued)
                    return result;

                // The TLV bit: mainline mac80211 sets it in the last presence word (after the
                // per-chain words), Kismet's own helpers in the first
                if (b == bit_tlv && (w == 0 || w + 1 == n_words)) {
                    tlv_present = true;
                    continue;
                }

                const auto layout = layout_of(b, openbsd);
                if (layout.align == 0)
                    return result;

                if (!align_fits(offset, layout.align, layout.size, hdr.size()))
                    return result;

                if (record < max_records)
                    on_field(b, record, hdr.subspan(offset, layout.size));

                offset += layout.size;
            }
        }

        if (next_vendor) {
            // OUI[3], sub namespace, skip_length, then skip_length bytes of vendor data
            constexpr size_t vendor_ns_len = 6;
            if (!align_fits(offset, 2, vendor_ns_len, hdr.size()))
                return result;

            const size_t skip = static_cast<size_t>(hdr[offset + 4]) |
                (static_cast<size_t>(hdr[offset + 5]) << 8);
            offset += vendor_ns_len;

            if (skip > hdr.size() - offset)
                return result;
            offset += skip;

            in_vendor = true;
            continued = false;
        } else if (next_radiotap) {
            in_vendor = false;
            continued = false;
            record++;
        } else {
            continued = true;
        }
    }

    result.status = walk_status::complete;

    if (tlv_present && align_fits(offset, 4, 0, hdr.size()))
        result.tlv_offset = offset;

    return result;
}

}

#endif
