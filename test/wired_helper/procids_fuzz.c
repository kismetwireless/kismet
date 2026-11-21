/* libFuzzer harness for the wired helper's /proc readers the privilege drop trusts:
 * wired_id_map_outer (uid_map, gid_map) and wired_status_caps (/proc/self/status).
 *
 *   tools/unit.sh <tree> test/wired_helper/procids_fuzz.c --src capture_wired/wired_util.c \
 *       --set framework --libs "-llzma -lpcap -lcap" --flavor fuzz
 *
 * Built without -DKIS_UNIT_FUZZ it runs its seeds once from main.
 *
 * Input: [0..3] the id looked up, little endian; the rest is the text, copied to a
 * buffer of exactly its length, so a read past it is caught.
 *
 * Checked on every input:
 *   - wired_id_map_outer gives -1, 0 or 1, and 1 only when a line of the text maps
 *     the id, found again here with a plain sscanf of each line
 *   - wired_status_caps gives 0 only when the text has a CapPrm and a CapEff line,
 *     and the values are what strtoull reads from them
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../capture_wired/wired_util.h"

/* What follows key on the first line starting with it, or NULL; other lines may
 * hold NULs */
static const char *pf_line(const char *text, size_t len, const char *key) {
    const char *p = text, *end = text + len;
    size_t kl = strlen(key);

    while (p < end) {
        const char *eol = memchr(p, '\n', (size_t) (end - p));

        if ((size_t) ((eol != NULL ? eol : end) - p) >= kl && memcmp(p, key, kl) == 0)
            return p + kl;

        if (eol == NULL)
            break;

        p = eol + 1;
    }

    return NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint32_t id, outer = 0;
    uint64_t prm = 0, eff = 0;
    char *text;
    size_t len;
    int r;

    if (size < 4)
        return 0;

    id = (uint32_t) data[0] | ((uint32_t) data[1] << 8) | ((uint32_t) data[2] << 16) |
        ((uint32_t) data[3] << 24);
    len = size - 4;

    if ((text = malloc(len > 0 ? len : 1)) == NULL)
        return 0;

    memcpy(text, data + 4, len);

    r = wired_id_map_outer(text, len, id, &outer);

    if (r < -1 || r > 1)
        abort();

    /* Cross-check a found mapping with sscanf on a NUL-terminated copy */
    if (r == 1) {
        char *copy = malloc(len + 1);
        const char *p;
        int seen = 0;

        if (copy == NULL) {
            free(text);
            return 0;
        }

        memcpy(copy, text, len);
        copy[len] = 0;

        if (memchr(text, 0, len) != NULL)
            abort();

        for (p = copy; p != NULL && *p != 0; ) {
            unsigned long long a, b, c;

            if (sscanf(p, "%llu %llu %llu", &a, &b, &c) == 3 && id >= a && id - a < c &&
                    b + (id - a) == outer)
                seen = 1;

            p = strchr(p, '\n');

            if (p != NULL)
                p++;
        }

        free(copy);

        if (!seen)
            abort();
    }

    r = wired_status_caps(text, len, &prm, &eff);

    if (r != 0 && r != -1)
        abort();

    if (r == 0) {
        char *copy = malloc(len + 1);
        const char *pp, *ep;

        if (copy == NULL) {
            free(text);
            return 0;
        }

        memcpy(copy, text, len);
        copy[len] = 0;

        pp = pf_line(copy, len, "CapPrm:");
        ep = pf_line(copy, len, "CapEff:");

        if (pp == NULL || ep == NULL || strtoull(pp, NULL, 16) != prm || strtoull(ep, NULL, 16) != eff)
            abort();

        free(copy);
    }

    free(text);
    return 0;
}

#ifndef KIS_UNIT_FUZZ
int main(void) {
    static const char *const seeds[] = {
        "\0\0\0\0         0       1000          1\n",
        "\0\0\0\0         0          0 4294967295\n",
        "\5\0\0\0         0     100000      65536\n     65536       1000          1\n",
        "\0\0\0\0CapPrm:\t0000000000002000\nCapEff:\t0000000000002000\n",
    };
    size_t i;

    for (i = 0; i < sizeof(seeds) / sizeof(seeds[0]); i++)
        LLVMFuzzerTestOneInput((const uint8_t *) seeds[i], 4 + strlen(seeds[i] + 4));

    printf("ok\n");
    return 0;
}
#endif
