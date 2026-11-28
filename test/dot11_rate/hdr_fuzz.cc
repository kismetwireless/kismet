/* libFuzzer harness for whole capture headers: radiotap (walk, TLV list and rate collector,
 * as kis_dlt_radiotap.cc handle_packet feeds them) and PPI (field loop and the 802.11n
 * decoders, as kis_dlt_ppi.cc), on an exact-size copy so ASan sees any over-read.  First
 * byte: bit 0 picks radiotap (0) or PPI (1), bit 1 the OpenBSD bit meanings.
 *
 *   tools/unit.sh <tree> test/dot11_rate/hdr_fuzz.cc dot11_phy_rate.cc --flavor fuzz --time 60 -- -max_len=512
 *
 * Built without KIS_UNIT_FUZZ it runs seeded random headers instead. */

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
    fprintf(stderr, "hdr_fuzz: %s\n", what);
    abort();
}

void check(const dot11_phy_rate& r) {
    if (static_cast<unsigned>(r.mode) > static_cast<unsigned>(dot11_phy_mode::s1g)) fail("mode");
    if (r.mcs > 15) fail("mcs");
    if (r.nss > 16) fail("nss");
    if (static_cast<unsigned>(r.gi_code) > 3) fail("gi");
    if (static_cast<unsigned>(r.ru_code) > static_cast<unsigned>(dot11_ru::mru3x996_484)) fail("ru");
    if (r.rate_kbps > max_phy_rate_kbps) fail("rate cap");
    if (r.mode == dot11_phy_mode::none && (r.rate_kbps || r.nss || r.flags)) fail("empty record data");
    const double dr = dot11_datarate_of(r.rate_kbps);
    (void) dot11_ppi_rate_of(dr);
    (void) dot11_ppi_rate_of(dr * 1e6);
    if (r.mode != dot11_phy_mode::none && r.mode != dot11_phy_mode::legacy && dot11_ppi_common_rate(dr, r) != 0)
        fail("HT+ rate in the PPI common rate field");
}

void tlvs(const uint8_t *p, const uint8_t *end, dot11_radiotap_rate& rate) {
    while (end - p >= 4) {
        const uint16_t type = p[0] | (p[1] << 8);
        const uint16_t len = p[2] | (p[3] << 8);
        p += 4;
        if (len > end - p)
            return;
        rate.tlv(type, std::span<const uint8_t>(p, len));
        const size_t padded = (static_cast<size_t>(len) + 3) & ~static_cast<size_t>(3);
        if (padded > static_cast<size_t>(end - p))
            return;
        p += padded;
    }
}

void radiotap(std::span<const uint8_t> hdr, bool openbsd) {
    dot11_radiotap_rate rate(openbsd);
    const auto w = kis_radiotap::walk(hdr,
            [&](unsigned int bit, size_t, std::span<const uint8_t> f) {
                if (f.data() < hdr.data() || f.data() + f.size() > hdr.data() + hdr.size())
                    fail("field outside header");
                rate.field(bit, f);
            }, openbsd);
    if (w.status == kis_radiotap::walk_status::malformed)
        return;
    if (w.tlv_offset) {
        if (*w.tlv_offset > hdr.size())
            fail("tlv offset");
        tlvs(hdr.data() + *w.tlv_offset, hdr.data() + hdr.size(), rate);
    }
    check(rate.finish());
}

void ppi(std::span<const uint8_t> hdr) {
    if (hdr.size() < 8)
        return;
    unsigned int ph_len = hdr[2] | (hdr[3] << 8);
    if (ph_len < 8 || ph_len > hdr.size())
        return;
    if (ph_len == 24 && hdr.size() > 32 && (hdr[8] | (hdr[9] << 8)) == 2)
        ph_len = 32;
    unsigned int off = 8;
    dot11_phy_rate pr;
    while (off < ph_len) {
        const unsigned int remaining = ph_len - off;
        if (remaining < 4)
            return;
        const unsigned int type = hdr[off] | (hdr[off + 1] << 8);
        const unsigned int fh_len = hdr[off + 2] | (hdr[off + 3] << 8);
        if (fh_len > remaining - 4)
            return;
        const auto field = hdr.subspan(off, fh_len + 4);
        off += fh_len + 4;
        if (type == 2) {
            if (fh_len < 24 - 4)
                return;
            if (pr.mode == dot11_phy_mode::none)
                pr = dot11_rate_legacy(static_cast<uint16_t>(field[14] | (field[15] << 8)));
        } else if (type == 3) {
            if (fh_len < 16 - 4)
                return;
            if (pr.mode == dot11_phy_mode::none || pr.mode == dot11_phy_mode::legacy)
                pr = dot11_rate_ppi_11n_mac(field);
        } else if (type == 4) {
            if (fh_len < 52 - 4)
                return;
            (void) dot11_ppi_11n_flags(field);
            pr = dot11_rate_ppi_11n(field);
        }
    }
    check(pr);
}

void run(const uint8_t *data, size_t size) {
    if (size < 1)
        return;
    const std::vector<uint8_t> buf(data + 1, data + size);
    const std::span<const uint8_t> view(buf.data(), buf.size());
    if (data[0] & 1)
        ppi(view);
    else
        radiotap(view, data[0] & 2);
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    run(data, size);
    return 0;
}

#ifndef KIS_UNIT_FUZZ
int main() {
    std::mt19937 rng(7);
    std::vector<uint8_t> b;
    for (int i = 0; i < 200000; i++) {
        b.resize(1 + rng() % 200);
        for (auto& x : b)
            x = static_cast<uint8_t>(rng());
        run(b.data(), b.size());
    }
    printf("hdr_fuzz: pass\n");
    return 0;
}
#endif
