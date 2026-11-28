/* libFuzzer harness for kis_radiotap::walk (radiotap_walk.h).  The first byte picks the
 * OpenBSD bit meanings, the rest is the radiotap header.  Every field handed out lies inside
 * the header, has its layout's size and alignment, comes in order without overlapping the
 * one before, and belongs to one of the first max_records records; a TLV offset is 4-aligned,
 * inside the header and after every field.
 *
 *   tools/unit.sh <tree> test/radiotap/walk_fuzz.cc --flavor fuzz --time 60 -- -max_len=512
 *
 * Built without KIS_UNIT_FUZZ it runs seeded random headers instead, for the normal, asan
 * and ubsan flavors.
 */

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <vector>

#include "radiotap_walk.h"

using namespace kis_radiotap;

namespace {

void fail(const char *what) {
    fprintf(stderr, "walk_fuzz: %s\n", what);
    abort();
}

void run(const uint8_t *data, size_t size) {
    if (size < 1)
        return;

    const bool openbsd = data[0] & 1;

    // A copy of exactly the header bytes, so ASan sees any read past them
    const std::vector<uint8_t> hdr(data + 1, data + size);
    const std::span<const uint8_t> view(hdr.data(), hdr.size());

    size_t end_prev = 0;
    size_t record_prev = 0;
    size_t n_fields = 0;

    const auto r = walk(view, [&](unsigned int bit, size_t record, std::span<const uint8_t> field) {
            const auto l = layout_of(bit, openbsd);
            if (l.align == 0 || field.size() != l.size)
                fail("field of an unknown or wrong size");

            if (field.data() < hdr.data())
                fail("field before the header");
            const auto off = static_cast<size_t>(field.data() - hdr.data());
            if (off > hdr.size() || field.size() > hdr.size() - off)
                fail("field past the header");
            if (off % l.align != 0)
                fail("field not aligned");
            if (off < end_prev)
                fail("field overlaps the one before");
            if (record >= max_records || record < record_prev)
                fail("record out of order or past the cap");

            end_prev = off + field.size();
            record_prev = record;
            n_fields++;
        }, openbsd);

    if (r.status == walk_status::malformed && n_fields != 0)
        fail("fields reported from a malformed header");
    if (r.tlv_offset) {
        if (r.status != walk_status::complete)
            fail("TLV offset from an incomplete walk");
        if (*r.tlv_offset % 4 != 0 || *r.tlv_offset > hdr.size() || *r.tlv_offset < end_prev)
            fail("TLV offset out of place");
    }
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    run(data, size);
    return 0;
}

#ifndef KIS_UNIT_FUZZ
int main(int argc, char **argv) {
    const unsigned runs = argc > 1 ? static_cast<unsigned>(atoi(argv[1])) : 200000;
    std::mt19937 rng(42);
    std::vector<uint8_t> buf;

    for (unsigned i = 0; i < runs; i++) {
        buf.resize(1 + rng() % 160);
        for (auto& b : buf)
            b = static_cast<uint8_t>(rng());

        // Mostly plausible presence words: a few set bits, namespace and extension bits
        if (buf.size() >= 9) {
            const size_t words = 1 + rng() % 4;
            for (size_t w = 0; w < words && 5 + 4 * w + 4 <= buf.size(); w++) {
                uint32_t p = 0;
                for (int k = 0; k < 4; k++)
                    p |= uint32_t{1} << (rng() % 29);
                if (rng() % 3 == 0)
                    p |= uint32_t{1} << 28;
                if (w + 1 < words)
                    p |= (uint32_t{1} << 31) | (uint32_t{1} << (29 + rng() % 2));
                for (int k = 0; k < 4; k++)
                    buf[5 + 4 * w + k] = static_cast<uint8_t>(p >> (8 * k));
            }
        }

        run(buf.data(), buf.size());
    }

    printf("walk_fuzz: %u random headers passed\n", runs);
    return 0;
}
#endif
