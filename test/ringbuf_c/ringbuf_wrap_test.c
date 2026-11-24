/* Reserve/commit across the end of simple_ringbuf_c's ring.
 *
 *   tools/unit.sh <tree> test/ringbuf_c/ringbuf_wrap_test.c --src simple_ringbuf_c.c --flavor asan
 *
 * A reserve that wraps the ring hands out a separately allocated buffer; commit
 * (and reserve_free) must copy it into both ends of the ring and free it, so
 * LSan reports a leak on the broken version.  Also checks the data comes back
 * in order, a zero-length commit releases a wrapped reserve (cf_cancel_packet),
 * and the zero-copy reserve still points into the ring.  Peeks: short, empty and
 * refused peeks are released like any other without ending someone else's peek.
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

    /* A wrapped peek, then a peek of an empty ring: it returns NULL, and freeing
     * it must not free the earlier copy again (the caller's pointer still holds it) */
    position(rb, 10);
    CHECK(kis_simple_ringbuf_write(rb, (uint8_t[40]) { 0 }, 40) == 40);
    CHECK(kis_simple_ringbuf_peek_zc(rb, (void **) &buf, 40) == 40);
    kis_simple_ringbuf_peek_free(rb, buf);
    CHECK(kis_simple_ringbuf_read(rb, NULL, 40) == 40);
    CHECK(kis_simple_ringbuf_peek_zc(rb, (void **) &buf, 40) == 0);
    CHECK(buf == NULL);
    kis_simple_ringbuf_peek_free(rb, buf);

    /* A short wrapped peek is released like a full one, and the ring peeks again */
    position(rb, 10);
    CHECK(kis_simple_ringbuf_write(rb, (uint8_t[20]) { 0 }, 20) == 20);
    CHECK(kis_simple_ringbuf_peek_zc(rb, (void **) &buf, 40) == 20);
    kis_simple_ringbuf_peek_free(rb, buf);
    CHECK(rb->mid_peek == 0);
    CHECK(kis_simple_ringbuf_peek_zc(rb, (void **) &buf, 20) == 20);
    kis_simple_ringbuf_peek_free(rb, buf);

    /* A peek while another is open is refused with a NULL pointer and leaves the
     * open (wrapped, copied) peek to its owner, whose release frees the copy */
    {
        uint8_t *other = (uint8_t *) &failures;

        position(rb, 10);
        CHECK(kis_simple_ringbuf_write(rb, (uint8_t[40]) { 0 }, 40) == 40);
        CHECK(kis_simple_ringbuf_peek_zc(rb, (void **) &buf, 40) == 40);
        CHECK(kis_simple_ringbuf_peek_zc(rb, (void **) &other, 40) == 0);
        CHECK(other == NULL);
        CHECK(rb->mid_peek == 1 && rb->free_peek == 1);
        kis_simple_ringbuf_peek_free(rb, buf);
        CHECK(rb->mid_peek == 0);
    }

    /* Every peek is released, whatever it returned: releasing a refused peek
     * must leave the open one to its owner, whose release still frees the copy */
    {
        uint8_t *other = NULL;

        position(rb, 10);
        CHECK(kis_simple_ringbuf_write(rb, (uint8_t[40]) { 0 }, 40) == 40);
        CHECK(kis_simple_ringbuf_peek_zc(rb, (void **) &buf, 40) == 40);
        CHECK(kis_simple_ringbuf_peek_zc(rb, (void **) &other, 40) == 0);
        kis_simple_ringbuf_peek_free(rb, other);
        CHECK(rb->mid_peek == 1 && rb->free_peek == 1);
        kis_simple_ringbuf_peek_free(rb, buf);
        CHECK(rb->mid_peek == 0);
    }

    /* A peek of nothing holds nothing, so a later peek works with or without its release */
    kis_simple_ringbuf_clear(rb);
    CHECK(kis_simple_ringbuf_peek_zc(rb, (void **) &buf, 40) == 0);
    CHECK(buf == NULL && rb->mid_peek == 0);
    CHECK(kis_simple_ringbuf_write(rb, (uint8_t[8]) { 0 }, 8) == 8);
    CHECK(kis_simple_ringbuf_peek_zc(rb, (void **) &buf, 8) == 8);
    kis_simple_ringbuf_peek_free(rb, buf);
    CHECK(rb->mid_peek == 0);

    kis_simple_ringbuf_free(rb);

    if (failures) {
        fprintf(stderr, "ringbuf_wrap_test: %d failure(s)\n", failures);
        return 1;
    }

    printf("ringbuf_wrap_test: ok\n");
    return 0;
}
