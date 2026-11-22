/* Reserve/commit across the end of simple_ringbuf_c's ring.
 *
 *   tools/unit.sh <tree> test/ringbuf_c/ringbuf_wrap_test.c --src simple_ringbuf_c.c --flavor asan
 *
 * A reserve that wraps the ring hands out a separately allocated buffer; commit
 * (and reserve_free) must copy it into both ends of the ring and free it, so
 * LSan reports a leak on the broken version.  Also checks the data comes back
 * in order, a zero-length commit releases a wrapped reserve (cf_cancel_packet),
 * and the zero-copy reserve still points into the ring.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "simple_ringbuf_c.h"

#define RING_SZ 64

static int failures = 0;

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

/* Move the write position to off bytes before the end of the ring, empty */
static void position(kis_simple_ringbuf_t *rb, size_t off) {
    uint8_t junk[RING_SZ];

    kis_simple_ringbuf_clear(rb);
    memset(junk, 0, sizeof(junk));
    CHECK(kis_simple_ringbuf_write(rb, junk, RING_SZ - off) == RING_SZ - off);
    CHECK(kis_simple_ringbuf_read(rb, NULL, RING_SZ - off) == RING_SZ - off);
}

static void fill(uint8_t *p, size_t len, uint8_t seed) {
    size_t i;

    for (i = 0; i < len; i++)
        p[i] = (uint8_t) (seed + i);
}

static void wrap_commit(kis_simple_ringbuf_t *rb, size_t off, size_t len) {
    uint8_t *buf = NULL;
    uint8_t want[RING_SZ], got[RING_SZ];

    position(rb, off);

    CHECK(kis_simple_ringbuf_reserve(rb, (void **) &buf, len) == len);
    CHECK(buf != NULL);
    if (buf == NULL)
        return;

    fill(buf, len, (uint8_t) off);
    fill(want, len, (uint8_t) off);

    CHECK(kis_simple_ringbuf_commit(rb, buf, len) == len);
    CHECK(kis_simple_ringbuf_used(rb) == len);
    CHECK(kis_simple_ringbuf_read(rb, got, len) == len);
    CHECK(memcmp(want, got, len) == 0);
}

int main(void) {
    kis_simple_ringbuf_t *rb = kis_simple_ringbuf_create(RING_SZ);
    uint8_t *buf = NULL;
    size_t off;
    int round;

    CHECK(rb != NULL);
    if (rb == NULL)
        return 1;

    /* Every split point, many times over, so a per-commit leak is large */
    for (round = 0; round < 50; round++) {
        for (off = 1; off < 40; off++)
            wrap_commit(rb, off, 40);
    }

    /* No wrap: reserve is the ring itself */
    position(rb, 50);
    CHECK(kis_simple_ringbuf_reserve(rb, (void **) &buf, 40) == 40);
    CHECK(kis_simple_ringbuf_commit(rb, buf, 40) == 40);
    CHECK(kis_simple_ringbuf_used(rb) == 40);

    /* Wrapped reserve released with a zero-length commit */
    position(rb, 10);
    CHECK(kis_simple_ringbuf_reserve(rb, (void **) &buf, 40) == 40);
    CHECK(kis_simple_ringbuf_commit(rb, buf, 0) == 0);
    CHECK(kis_simple_ringbuf_used(rb) == 0);

    /* ...and with reserve_free */
    position(rb, 10);
    CHECK(kis_simple_ringbuf_reserve(rb, (void **) &buf, 40) == 40);
    kis_simple_ringbuf_reserve_free(rb, buf);
    CHECK(kis_simple_ringbuf_used(rb) == 0);

    /* The ring takes a new reserve after each of those */
    wrap_commit(rb, 10, 40);

    /* Zero-copy reserve across the end gets only the contiguous part */
    position(rb, 10);
    CHECK(kis_simple_ringbuf_reserve_zcopy(rb, (void **) &buf, 40) == 10);
    memset(buf, 0xAA, 10);
    CHECK(kis_simple_ringbuf_commit(rb, buf, 10) == 10);
    CHECK(kis_simple_ringbuf_used(rb) == 10);

    /* Too big for the free space */
    position(rb, 10);
    CHECK(kis_simple_ringbuf_write(rb, (uint8_t[60]) { 0 }, 60) == 60);
    CHECK(kis_simple_ringbuf_reserve(rb, (void **) &buf, 40) == 0);

    kis_simple_ringbuf_free(rb);

    if (failures) {
        fprintf(stderr, "ringbuf_wrap_test: %d failure(s)\n", failures);
        return 1;
    }

    printf("ringbuf_wrap_test: ok\n");
    return 0;
}
