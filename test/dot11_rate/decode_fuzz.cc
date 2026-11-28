/* libFuzzer harness for the 802.11 PHY rate decoders (dot11_phy_rate.cc).  The first byte
 * picks the decoder, the rest is the field or TLV (for the collector, a list of bit/TLV
 * records).  Every result has a mode, MCS, streams, width, RU and rate in range; the same
 * input decodes the same way twice; a collector with a bad PLCP flag has no rate.
 *
 *   tools/unit.sh <tree> test/dot11_rate/decode_fuzz.cc dot11_phy_rate.cc --flavor fuzz --time 60 -- -max_len=256
 *
 * Built without KIS_UNIT_FUZZ it runs seeded random fields instead, for the normal, asan and
 * ubsan flavors.
 */

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

#include "dot11_phy_rate.h"
#include "radiotap_walk.h"

namespace {

void fail(const char *what) {
    fprintf(stderr, "decode_fuzz: %s\n", what);
    abort();
}

void check(const dot11_phy_rate& r) {
    if (static_cast<unsigned int>(r.mode) > static_cast<unsigned int>(dot11_phy_mode::s1g))
        fail("mode out of range");
    if (r.mcs > 15)
        fail("mcs out of range");
    if (r.nss > 16)
        fail("nss out of range");
    if (static_cast<unsigned int>(r.gi_code) > 3)
        fail("gi out of range");
    if (static_cast<unsigned int>(r.ru_code) > static_cast<unsigned int>(dot11_ru::mru3x996_484))
        fail("ru out of range");
    if (r.rate_kbps > max_phy_rate_kbps)
        fail("rate past the cap");

    switch (r.bw_mhz) {
        case 0: case 20: case 40: case 80: case 160: case 320:
            break;
        case 1: case 2: case 4: case 8: case 16:
            if (r.mode != dot11_phy_mode::s1g)
                fail("S1G width outside S1G");
            break;
        default:
            fail("width out of range");
    }

    if (r.mode == dot11_phy_mode::none && (r.rate_kbps != 0 || r.nss != 0 || r.flags != 0))
        fail("data in an empty record");
    if (r.rate_kbps != 0 && r.nss == 0)
        fail("rate without streams");
    if (r.rate_kbps != 0 && dot11_gi_ns(r.mode, r.gi_code) == 0 && r.mode != dot11_phy_mode::legacy)
        fail("rate without a GI");
}

bool same(const dot11_phy_rate& a, const dot11_phy_rate& b) {
    return memcmp(&a, &b, sizeof(a)) == 0;
}

dot11_phy_rate decode(uint8_t which, std::span<const uint8_t> d) {
    switch (which % 8) {
        case 0: return dot11_rate_radiotap_mcs(d.first(std::min<size_t>(d.size(), 3)));
        case 1: return dot11_rate_radiotap_vht(d.first(std::min<size_t>(d.size(), 12)));
        case 2: return dot11_rate_radiotap_he(d.first(std::min<size_t>(d.size(), 12)));
        case 3: return dot11_rate_radiotap_s1g(d);
        case 4: {
            // U-SIG length from the first byte, then the EHT TLV
            if (d.empty())
                return {};
            const size_t ulen = std::min<size_t>(d[0] % 13, d.size() - 1);
            return dot11_rate_radiotap_eht(d.subspan(1 + ulen), d.subspan(1, ulen));
        }
        case 5: return dot11_rate_ppi_11n(d);
        case 6: return d.empty() ? dot11_phy_rate{} : dot11_rate_legacy(static_cast<uint16_t>(d[0] | (d.size() > 1 ? d[1] << 8 : 0)));
        default: {
            // Collector: records of [kind, len, bytes...]; kind < 32 a field bit, else a TLV
            dot11_radiotap_rate c(which & 0x80);
            bool badplcp = false;
            size_t off = 0;
            while (off + 2 <= d.size()) {
                const uint8_t kind = d[off];
                const size_t len = std::min<size_t>(d[off + 1], d.size() - off - 2);
                const auto data = d.subspan(off + 2, len);
                if (kind < 32) {
                    const auto bit = static_cast<unsigned int>(kind % 28);
                    if (bit == kis_radiotap::bit_rx_flags && !(which & 0x80) && len == 2 && (data[0] & 0x02))
                        badplcp = true;
                    c.field(bit, data);
                } else {
                    c.tlv(static_cast<uint16_t>(28 + kind % 8), data);
                }
                off += 2 + len;
            }
            const auto r = c.finish();
            if (badplcp && r.mode != dot11_phy_mode::none)
                fail("rate from a bad PLCP frame");
            return r;
        }
    }
}

void run(const uint8_t *data, size_t size) {
    if (size < 1)
        return;

    // A copy of exactly the input, so ASan sees any read past it
    const std::vector<uint8_t> buf(data + 1, data + size);
    const std::span<const uint8_t> view(buf.data(), buf.size());

    const auto a = decode(data[0], view);
    check(a);
    if (!same(a, decode(data[0], view)))
        fail("not deterministic");
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    run(data, size);
    return 0;
}

#ifndef KIS_UNIT_FUZZ
int main(int argc, char **argv) {
    const unsigned runs = argc > 1 ? static_cast<unsigned>(atoi(argv[1])) : 500000;
    std::mt19937 rng(42);
    std::vector<uint8_t> buf;

    for (unsigned i = 0; i < runs; i++) {
        buf.resize(1 + rng() % 128);
        for (auto& b : buf)
            b = static_cast<uint8_t>(rng());

        // Mostly well-formed sizes: exact field sizes and EHT TLVs of 44 + 4n bytes
        if (rng() % 2) {
            static constexpr size_t sizes[] = { 3, 12, 12, 6, 0, 52, 2, 0 };
            const size_t which = buf[0] % 8;
            if (which == 4)
                buf.resize(2 + buf[1] % 13 + 44 + 4 * (rng() % 4));
            else if (sizes[which])
                buf.resize(1 + sizes[which]);
        }

        run(buf.data(), buf.size());
    }

    printf("decode_fuzz: %u random fields passed\n", runs);
    return 0;
}
#endif
