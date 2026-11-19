/* libFuzzer harness for env_report_parse, the datasource sensor report parser.
 *
 *   SAN="-g -O1 -fsanitize=address,undefined,float-cast-overflow -fno-sanitize-recover=all"
 *   clang $SAN -fsanitize=fuzzer-no-link -I. -c mpack/mpack.c -o <scratch>/mpack.o
 *   clang++ -std=c++20 $SAN -fsanitize=fuzzer -I. test/environment/env_report_fuzz.cc \
 *       environment_report.cc <scratch>/mpack.o -o <scratch>/env_report_fuzz
 *   <scratch>/env_report_fuzz <corpus dir>
 *
 * Seed the corpus with encoder output (cf_env_encode) for a fair start.
 */

#include "config.h"

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <string_view>

#include "environment_report.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    env_report r;
    std::string err;

    if (!env_report_parse(std::string_view((const char *) data, size), r, err))
        return 0;

    // What the parser promises its callers
    if (r.readings.size() > env_max_readings)
        abort();

    for (const auto& rd : r.readings) {
        double v = rd.value;

        if (!env_valid_id(rd.id) || !env_check_value(rd.kind, v) || v != rd.value)
            abort();

        if (rd.label.length() > env_max_label_len)
            abort();

        for (auto c : rd.label)
            if ((unsigned char) c < 0x20 || (unsigned char) c > 0x7e)
                abort();

        if (rd.kind == env_kind::battery &&
                (rd.batt_state > KIS_EXTERNAL_V3_ENV_BATT_NOT_CHARGING || rd.remaining_s > env_max_remaining_s ||
                 !std::isfinite(rd.voltage) || rd.voltage < 0 || rd.voltage > 100 ||
                 rd.ext_power < -1 || rd.ext_power > 1))
            abort();
    }

    return 0;
}
