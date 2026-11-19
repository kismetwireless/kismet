/* libFuzzer harness for kis_l3::decode_dns_name.  The first byte is the offset of the name in
 * the rest of the input.  Build as frame_fuzz.cc; run 10M iterations.
 */

#include <cstdint>
#include <cstdlib>
#include <vector>

#include "kis_l3_parse.h"

using namespace kis_l3;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1)
        return 0;

    std::vector<uint8_t> buf(data + 1, data + size);
    bstr<max_dns_name> out;

    const bool ok = decode_dns_name(buf.empty() ? nullptr : buf.data(), buf.size(), data[0], out);

    if (out.len > max_dns_name)
        abort();

    // A failed decode leaves no partial name behind
    if (!ok && out.len != 0)
        abort();

    return 0;
}
