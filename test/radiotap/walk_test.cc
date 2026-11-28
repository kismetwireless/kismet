/* Tests for kis_radiotap::walk (radiotap_walk.h): mac80211-shaped headers with several
 * presence words, every field's size and alignment, vendor namespaces, unknown bits, the
 * antenna record cap, presence words past the header, the TLV list start, and every
 * truncated length of each header.
 *
 *   tools/unit.sh <tree> test/radiotap/walk_test.cc --flavor asan
 *
 * With --master the header vectors run through a copy of the walk loop kis_dlt_radiotap.cc
 * had before radiotap_walk.h; the TLV and fields-after-A-MPDU cases fail there.
 */

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "radiotap_walk.h"

using namespace kis_radiotap;

namespace {

int failures = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s [%s]\n", __FILE__, __LINE__, #cond, current_case.c_str()); \
        failures++; \
    } \
} while (0)

std::string current_case;

struct field_rec {
    unsigned int bit;
    size_t record;
    size_t offset;
    size_t size;

    bool operator==(const field_rec& o) const {
        return bit == o.bit && record == o.record && offset == o.offset && size == o.size;
    }
};

struct walk_out {
    walk_status status = walk_status::malformed;
    std::optional<size_t> tlv_offset;
    std::vector<field_rec> fields;
};

using walker = std::function<walk_out(const std::vector<uint8_t>&, bool)>;

uint8_t marker(unsigned int bit, size_t record, size_t i) {
    return static_cast<uint8_t>(0x40 + bit * 3 + record * 7 + i);
}

walk_out walk_new(const std::vector<uint8_t>& hdr, bool openbsd) {
    walk_out out;
    const std::span<const uint8_t> view(hdr.data(), hdr.size());

    auto r = walk(view, [&](unsigned int bit, size_t record, std::span<const uint8_t> field) {
            // Every span lies inside the header
            const auto off = static_cast<size_t>(field.data() - hdr.data());
            if (field.data() < hdr.data() || off > hdr.size() || field.size() > hdr.size() - off) {
                fprintf(stderr, "FAIL span outside header bit %u off %zu size %zu\n", bit, off, field.size());
                abort();
            }
            out.fields.push_back({bit, record, off, field.size()});
        }, openbsd);

    out.status = r.status;
    out.tlv_offset = r.tlv_offset;
    return out;
}

/* The walk loop of kis_dlt_radiotap.cc at a407cf852 (Linux bit meanings), reporting the
 * fields it located instead of applying them */
walk_out walk_master(const std::vector<uint8_t>& hdr, bool) {
    walk_out out;

    if (hdr.size() < 8)
        return out;

    auto le32 = [&](size_t o) {
        return static_cast<uint32_t>(hdr[o]) | (static_cast<uint32_t>(hdr[o + 1]) << 8) |
            (static_cast<uint32_t>(hdr[o + 2]) << 16) | (static_cast<uint32_t>(hdr[o + 3]) << 24);
    };

    const size_t radiotap_len = hdr[2] | (hdr[3] << 8);
    if (radiotap_len < 8 || hdr.size() < radiotap_len)
        return out;

    size_t last = 4;
    size_t bitmap_remaining = radiotap_len - 8;
    while ((le32(last) & (1u << 31)) && bitmap_remaining >= 4) {
        last += 4;
        bitmap_remaining -= 4;
    }
    if (le32(last) & (1u << 31))
        return out;

    out.status = walk_status::complete;

    size_t iter = last + 4;
    bool truncated = false;
    auto field_fits = [&](size_t align, size_t size) {
        iter += ((iter + align - 1) & ~(align - 1)) - iter;
        if (iter > radiotap_len || size > radiotap_len - iter) {
            truncated = true;
            return false;
        }
        return true;
    };

    bool tlv_present = false;
    size_t record = 0;

    for (size_t p = 4, bit0 = 0; p <= last && !truncated; p += 4, bit0 += 32, record++) {
        for (uint32_t present = le32(p), next; present; present = next) {
            next = present & (present - 1);
            const unsigned int bit = (bit0 + __builtin_ctz(present)) % 32;

            if (bit0 == 0 && bit == 28) {
                tlv_present = true;
                continue;
            }

            size_t align = 0, size = 0;
            switch (bit) {
                case 1: case 2: case 11: case 5: case 6: case 10:
                    align = 1; size = 1; break;
                case 3:
                    align = 2; size = 4; break;
                case 4: case 7: case 8: case 9: case 14:
                    align = 2; size = 2; break;
                case 0:
                    align = 8; size = 8; break;
                case 21:
                    align = 2; size = 12; break;
                case 19:
                    align = 1; size = 3; break;
                case 29: case 31:
                    continue;
                default:
                    next = 0;
                    continue;
            }

            if (!field_fits(align, size)) {
                next = 0;
                continue;
            }

            out.fields.push_back({bit, record, iter, size});
            iter += size;
        }
    }

    if (truncated)
        out.status = walk_status::stopped;

    if (tlv_present && !truncated && field_fits(4, 0))
        out.tlv_offset = iter;

    return out;
}

// Builds a header: presence words first, then fields in order with their alignment from the
// header start, filled with marker bytes
struct builder {
    std::vector<uint8_t> buf;
    std::vector<field_rec> expect;
    std::optional<size_t> tlv;
    bool openbsd = false;

    explicit builder(const std::vector<uint32_t>& words, bool obsd = false) : openbsd(obsd) {
        buf = {0, 0, 0, 0};
        for (auto w : words)
            for (int i = 0; i < 4; i++)
                buf.push_back(static_cast<uint8_t>(w >> (8 * i)));
    }

    void pad_to(size_t align) {
        while (buf.size() % align)
            buf.push_back(0xee);
    }

    void field(unsigned int bit, size_t record, bool reported = true) {
        const auto l = layout_of(bit, openbsd);
        pad_to(l.align);
        if (reported)
            expect.push_back({bit, record, buf.size(), l.size});
        for (size_t i = 0; i < l.size; i++)
            buf.push_back(marker(bit, record, i));
    }

    void vendor(uint16_t skip, uint8_t fill = 0xa5) {
        pad_to(2);
        const uint8_t ns[6] = {0x02, 0x00, 0x5e, 0x01, static_cast<uint8_t>(skip), static_cast<uint8_t>(skip >> 8)};
        buf.insert(buf.end(), ns, ns + 6);
        buf.insert(buf.end(), skip, fill);
    }

    // An S1G TLV (type 32, 6 bytes, padded to 8)
    void tlv_list() {
        pad_to(4);
        tlv = buf.size();
        const uint8_t t[12] = {32, 0, 6, 0, 1, 2, 3, 4, 5, 6, 0, 0};
        buf.insert(buf.end(), t, t + sizeof(t));
    }

    std::vector<uint8_t> done() {
        buf[2] = static_cast<uint8_t>(buf.size());
        buf[3] = static_cast<uint8_t>(buf.size() >> 8);
        return buf;
    }
};

constexpr uint32_t m(unsigned int bit) {
    return uint32_t{1} << bit;
}

constexpr uint32_t ns_rt = m(bit_radiotap_namespace) | m(bit_ext);

void check_fields(const walk_out& got, const builder& b, const std::vector<uint8_t>& hdr) {
    CHECK(got.fields.size() == b.expect.size());
    for (size_t i = 0; i < got.fields.size() && i < b.expect.size(); i++) {
        if (!(got.fields[i] == b.expect[i])) {
            fprintf(stderr, "  field %zu: got bit %u rec %zu off %zu size %zu, want bit %u rec %zu off %zu size %zu\n",
                    i, got.fields[i].bit, got.fields[i].record, got.fields[i].offset, got.fields[i].size,
                    b.expect[i].bit, b.expect[i].record, b.expect[i].offset, b.expect[i].size);
            CHECK(got.fields[i] == b.expect[i]);
            continue;
        }
        const auto& f = got.fields[i];
        for (size_t j = 0; j < f.size; j++)
            CHECK(hdr[f.offset + j] == marker(f.bit, f.record, j));
    }
}

// Every captured length short of the whole header: no span outside the bytes given, never a
// completed walk, and the fields reported are a prefix of the full header's
void check_truncations(const walker& w, const std::vector<uint8_t>& hdr, bool openbsd) {
    const auto full = w(hdr, openbsd);

    for (size_t len = 0; len < hdr.size(); len++) {
        // The header as cut, with it_len shortened to match, like a header claiming less
        std::vector<uint8_t> cut(hdr.begin(), hdr.begin() + len);
        if (len >= 4) {
            cut[2] = static_cast<uint8_t>(len);
            cut[3] = static_cast<uint8_t>(len >> 8);
        }

        const auto got = w(cut, openbsd);

        CHECK(got.fields.size() <= full.fields.size());
        for (size_t i = 0; i < got.fields.size() && i < full.fields.size(); i++)
            CHECK(got.fields[i] == full.fields[i]);

        if (got.status == walk_status::complete) {
            // Only possible when everything cut off was TLV data or padding after the fields
            CHECK(got.fields.size() == full.fields.size());
        }
        if (got.tlv_offset)
            CHECK(*got.tlv_offset <= len);
    }
}

void run_case(const char *name, const walker& w, builder& b, walk_status want_status) {
    current_case = name;
    const auto hdr = b.done();
    const auto got = w(hdr, b.openbsd);

    CHECK(got.status == want_status);
    check_fields(got, b, hdr);
    CHECK(got.tlv_offset == b.tlv);
    if (got.tlv_offset && b.tlv && *got.tlv_offset != *b.tlv)
        fprintf(stderr, "  tlv offset got %zu want %zu\n", *got.tlv_offset, *b.tlv);

    check_truncations(w, hdr, b.openbsd);
}

// mac80211 rx header of an HE A-MPDU subframe with three antenna records and a TLV list
void case_mac80211_he(const walker& w) {
    const uint32_t w0 = m(bit_tsft) | m(bit_flags) | m(bit_channel) | m(bit_dbm_antsignal) |
        m(bit_rx_flags) | m(bit_ampdu_status) | m(bit_timestamp) | m(bit_he) | m(bit_he_mu) |
        m(bit_tlv) | ns_rt;
    const uint32_t wa = m(bit_dbm_antsignal) | m(bit_antenna);
    builder b({w0, wa | ns_rt, wa});

    for (auto bit : {bit_tsft, bit_flags, bit_channel, bit_dbm_antsignal, bit_rx_flags,
            bit_ampdu_status, bit_timestamp, bit_he, bit_he_mu})
        b.field(bit, 0);
    b.field(bit_dbm_antsignal, 1);
    b.field(bit_antenna, 1);
    b.field(bit_dbm_antsignal, 2);
    b.field(bit_antenna, 2);
    b.tlv_list();

    run_case("mac80211 HE with antennas and TLV", w, b, walk_status::complete);
}

// VHT after A-MPDU status: master stopped at A-MPDU and never reached VHT
void case_vht_after_ampdu(const walker& w) {
    const uint32_t w0 = m(bit_flags) | m(bit_rate) | m(bit_channel) | m(bit_dbm_antsignal) |
        m(bit_rx_flags) | m(bit_ampdu_status) | m(bit_vht) | ns_rt;
    builder b({w0, m(bit_dbm_antsignal) | m(bit_antenna)});

    for (auto bit : {bit_flags, bit_rate, bit_channel, bit_dbm_antsignal, bit_rx_flags,
            bit_ampdu_status, bit_vht})
        b.field(bit, 0);
    b.field(bit_dbm_antsignal, 1);
    b.field(bit_antenna, 1);

    run_case("VHT after A-MPDU", w, b, walk_status::complete);
}

// HaLow: channel, signal, timestamp, then the S1G TLV
void case_s1g_tlv_after_timestamp(const walker& w) {
    builder b({m(bit_flags) | m(bit_channel) | m(bit_dbm_antsignal) | m(bit_timestamp) | m(bit_tlv)});
    for (auto bit : {bit_flags, bit_channel, bit_dbm_antsignal, bit_timestamp})
        b.field(bit, 0);
    b.tlv_list();
    run_case("S1G TLV after timestamp", w, b, walk_status::complete);
}

// Mainline mac80211 with chains: the TLV bit goes in the last (per-chain) presence word
void case_tlv_last_word(const walker& w) {
    builder b({m(bit_flags) | m(bit_channel) | m(bit_rx_flags) | ns_rt,
            m(bit_dbm_antsignal) | m(bit_antenna) | m(bit_tlv)});
    b.field(bit_flags, 0);
    b.field(bit_channel, 0);
    b.field(bit_rx_flags, 0);
    b.field(bit_dbm_antsignal, 1);
    b.field(bit_antenna, 1);
    b.tlv_list();
    run_case("TLV bit in the last chain word", w, b, walk_status::complete);
    current_case = "TLV bit in the last chain word";
    CHECK(b.tlv && *b.tlv == 24);

    const uint32_t w0 = m(bit_tsft) | m(bit_flags) | m(bit_channel) | m(bit_dbm_antsignal) |
        m(bit_rx_flags) | m(bit_ampdu_status) | m(bit_he) | ns_rt;
    const uint32_t wa = m(bit_dbm_antsignal) | m(bit_antenna);
    builder b2({w0, wa | ns_rt, wa | m(bit_tlv)});
    for (auto bit : {bit_tsft, bit_flags, bit_channel, bit_dbm_antsignal, bit_rx_flags,
            bit_ampdu_status, bit_he})
        b2.field(bit, 0);
    b2.field(bit_dbm_antsignal, 1);
    b2.field(bit_antenna, 1);
    b2.field(bit_dbm_antsignal, 2);
    b2.field(bit_antenna, 2);
    b2.tlv_list();
    run_case("HE, two chains, TLV bit in the last word", w, b2, walk_status::complete);
}

void case_tlv_after_ampdu(const walker& w) {
    builder b({m(bit_tsft) | m(bit_flags) | m(bit_ampdu_status) | m(bit_tlv)});
    for (auto bit : {bit_tsft, bit_flags, bit_ampdu_status})
        b.field(bit, 0);
    b.tlv_list();
    run_case("TLV after A-MPDU", w, b, walk_status::complete);
}

void case_vendor_namespace(const walker& w) {
    // radiotap fields, a vendor namespace with 3 of its own fields, back to radiotap
    const uint32_t w0 = m(bit_flags) | m(bit_channel) | m(bit_vendor_namespace) | m(bit_ext);
    const uint32_t wv = m(0) | m(1) | m(2) | ns_rt;
    builder b({w0, wv, m(bit_dbm_antsignal) | m(bit_antenna)});
    b.field(bit_flags, 0);
    b.field(bit_channel, 0);
    b.vendor(13);
    b.field(bit_dbm_antsignal, 1);
    b.field(bit_antenna, 1);
    run_case("vendor namespace mid-header", w, b, walk_status::complete);

    // Two vendor namespaces in a row, the second skipping 0 bytes, then the TLV list
    builder b2({m(bit_flags) | m(bit_tlv) | m(bit_vendor_namespace) | m(bit_ext),
            m(5) | m(bit_vendor_namespace) | m(bit_ext), m(7) | ns_rt, m(bit_dbm_antsignal)});
    b2.field(bit_flags, 0);
    b2.vendor(5);
    b2.vendor(0);
    b2.field(bit_dbm_antsignal, 1);
    b2.tlv_list();
    run_case("two vendor namespaces", w, b2, walk_status::complete);
}

void case_vendor_bad(const walker& w) {
    // skip_length past the header
    builder b({m(bit_flags) | m(bit_vendor_namespace) | m(bit_ext), m(0)});
    b.field(bit_flags, 0);
    b.vendor(4);
    auto hdr = b.done();
    const size_t skip_at = hdr.size() - 4 - 2;
    hdr[skip_at] = 5;
    current_case = "vendor skip past header";
    auto got = w(hdr, false);
    CHECK(got.status == walk_status::stopped);
    CHECK(got.fields.size() == 1);
    CHECK(!got.tlv_offset);

    // Both namespace bits in one word
    builder b2({m(bit_flags) | m(bit_radiotap_namespace) | m(bit_vendor_namespace) | m(bit_ext), m(bit_flags)});
    b2.field(bit_flags, 0);
    b2.vendor(0);
    current_case = "both namespace bits";
    got = w(b2.done(), false);
    CHECK(got.status == walk_status::stopped);
}

// Bit 28 of a vendor namespace's presence word is the vendor's own bit, not the TLV bit, even
// as the last word (the vendor data layout of older mac80211 drivers): no TLV list
void case_tlv_bit_in_vendor_word(const walker& w) {
    builder b({m(bit_flags) | m(bit_channel) | m(bit_vendor_namespace) | m(bit_ext), m(0) | m(bit_tlv)});
    b.field(bit_flags, 0);
    b.field(bit_channel, 0);
    b.vendor(8);
    // Bytes that would read as a TLV list if the bit were taken as one
    b.buf.insert(b.buf.end(), {32, 0, 6, 0, 1, 2, 3, 4, 5, 6, 0, 0});
    run_case("TLV bit in a vendor namespace word", w, b, walk_status::complete);
}

// Every field alone after a 1 byte field, so each needs its own padding, with a TLV list
// after it to show the walk went past it
void case_every_field(const walker& w) {
    for (unsigned int bit = 0; bit < 28; bit++) {
        for (const bool obsd : {false, true}) {
            const auto l = layout_of(bit, obsd);
            if (bit == bit_flags || l.align == 0)
                continue;
            builder b({m(bit_flags) | m(bit) | m(bit_tlv)}, obsd);
            if (bit < bit_flags) {
                b.field(bit, 0);
                b.field(bit_flags, 0);
            } else {
                b.field(bit_flags, 0);
                b.field(bit, 0);
            }
            b.tlv_list();
            const std::string name = std::string("field ") + std::to_string(bit) + (obsd ? " openbsd" : "");
            run_case(name.c_str(), w, b, walk_status::complete);
            for (const auto& f : b.expect)
                CHECK(f.offset % layout_of(f.bit, obsd).align == 0);
        }
    }
}

void case_layouts() {
    current_case = "layout table";
    CHECK(layout_of(bit_tsft, false).align == 8 && layout_of(bit_tsft, false).size == 8);
    CHECK(layout_of(bit_channel, false).align == 2 && layout_of(bit_channel, false).size == 4);
    CHECK(layout_of(bit_mcs, false).align == 1 && layout_of(bit_mcs, false).size == 3);
    CHECK(layout_of(bit_ampdu_status, false).align == 4 && layout_of(bit_ampdu_status, false).size == 8);
    CHECK(layout_of(bit_vht, false).align == 2 && layout_of(bit_vht, false).size == 12);
    CHECK(layout_of(bit_timestamp, false).align == 8 && layout_of(bit_timestamp, false).size == 12);
    CHECK(layout_of(bit_he, false).size == 12 && layout_of(bit_he_mu, false).size == 12);
    CHECK(layout_of(bit_he_mu_other_user, false).align == 2 && layout_of(bit_he_mu_other_user, false).size == 6);
    CHECK(layout_of(bit_zero_len_psdu, false).size == 1 && layout_of(bit_lsig, false).size == 4);
    CHECK(layout_of(bit_rx_flags, false).size == 2 && layout_of(bit_rx_flags, true).size == 4);
    CHECK(layout_of(bit_openbsd_hwqueue, true).align == 0);
    CHECK(layout_of(bit_openbsd_rssi, true).align == 1 && layout_of(bit_openbsd_rssi, true).size == 2);
    for (unsigned int bit = 28; bit < 64; bit++)
        CHECK(layout_of(bit, false).align == 0 && layout_of(bit, true).align == 0);
}

void case_unknown_stops(const walker& w) {
    // OpenBSD hardware queue: nothing after it, in this word or the next, is reported
    builder b({m(bit_flags) | m(bit_openbsd_hwqueue) | m(bit_openbsd_rssi) | m(bit_tlv) | ns_rt,
            m(bit_dbm_antsignal)}, true);
    b.field(bit_flags, 0);
    current_case = "openbsd hwqueue stops";
    auto got = w(b.done(), true);
    CHECK(got.status == walk_status::stopped);
    check_fields(got, b, b.buf);
    CHECK(!got.tlv_offset);

    // A radiotap word continued without a namespace bit numbers its fields from 32
    builder b2({m(bit_flags) | m(bit_ext), m(bit_flags) | m(bit_ext), m(bit_dbm_antsignal)});
    b2.field(bit_flags, 0);
    current_case = "continued radiotap word";
    got = w(b2.done(), false);
    CHECK(got.status == walk_status::stopped);
    check_fields(got, b2, b2.buf);

    // Bit 28 in a middle word is no TLV marker
    builder b3({m(bit_flags) | ns_rt, m(bit_tlv) | m(bit_dbm_antsignal) | ns_rt, m(bit_dbm_antsignal)});
    b3.field(bit_flags, 0);
    current_case = "bit 28 in a middle word";
    got = w(b3.done(), false);
    CHECK(got.status == walk_status::stopped);
    check_fields(got, b3, b3.buf);
    CHECK(!got.tlv_offset);

    // A continued word with only the namespace bits is fine
    builder b4({m(bit_flags) | m(bit_ext), ns_rt, m(bit_dbm_antsignal)});
    b4.field(bit_flags, 0);
    b4.field(bit_dbm_antsignal, 1);
    run_case("continued word without fields", w, b4, walk_status::complete);
}

void case_records_cap(const walker& w) {
    constexpr size_t n = max_records + 4;
    std::vector<uint32_t> words = {m(bit_flags) | m(bit_tlv) | ns_rt};
    for (size_t i = 1; i < n; i++)
        words.push_back(m(bit_dbm_antsignal) | m(bit_antenna) | (i + 1 < n ? ns_rt : 0));
    builder b(words);
    b.field(bit_flags, 0);
    for (size_t i = 1; i < n; i++) {
        b.field(bit_dbm_antsignal, i, i < max_records);
        b.field(bit_antenna, i, i < max_records);
    }
    b.tlv_list();
    run_case("antenna records past the cap", w, b, walk_status::complete);
}

void case_malformed(const walker& w) {
    current_case = "short header";
    for (size_t len = 0; len < header_min_len; len++) {
        std::vector<uint8_t> hdr(len, 0);
        CHECK(w(hdr, false).status == walk_status::malformed);
        CHECK(w(hdr, false).fields.empty());
    }

    current_case = "extension past header";
    std::vector<uint8_t> hdr = {0, 0, 8, 0, 0x02, 0, 0, 0x80};
    CHECK(w(hdr, false).status == walk_status::malformed);

    hdr = {0, 0, 12, 0, 0x02, 0, 0, 0x80, 0, 0, 0, 0x80};
    auto got = w(hdr, false);
    CHECK(got.status == walk_status::malformed);
    CHECK(got.fields.empty());

    current_case = "empty header";
    hdr = {0, 0, 8, 0, 0, 0, 0, 0};
    got = w(hdr, false);
    CHECK(got.status == walk_status::complete);
    CHECK(got.fields.empty() && !got.tlv_offset);

    current_case = "TLV bit alone";
    hdr = {0, 0, 8, 0, 0, 0, 0, 0x10};
    got = w(hdr, false);
    CHECK(got.status == walk_status::complete);
    CHECK(got.tlv_offset && *got.tlv_offset == 8);
}

}

int main(int argc, char **argv) {
    const bool master = argc > 1 && strcmp(argv[1], "--master") == 0;
    const walker w = master ? walker(walk_master) : walker(walk_new);

    case_mac80211_he(w);
    case_vht_after_ampdu(w);
    case_s1g_tlv_after_timestamp(w);
    case_tlv_after_ampdu(w);
    case_tlv_last_word(w);
    case_vendor_namespace(w);
    if (!master) {
        case_vendor_bad(w);
        case_tlv_bit_in_vendor_word(w);
        case_every_field(w);
        case_layouts();
        case_unknown_stops(w);
        case_records_cap(w);
        case_malformed(w);
    }

    if (failures) {
        printf("walk_test%s: %d failures\n", master ? " (master loop)" : "", failures);
        return 1;
    }

    printf("walk_test%s: all passed\n", master ? " (master loop)" : "");
    return 0;
}
