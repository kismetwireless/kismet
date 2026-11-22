/* Reserve/commit bounds in simple_ringbuf_c, built with the source included so
 * malloc can be made to fail.
 *
 *   tools/unit.sh <tree> test/ringbuf_c/ringbuf_reserve_test.c --flavor asan
 *
 * A commit larger than its reserve is refused and ends the reserve (it would read
 * past a split-op buffer and push length past the ring), so is a commit of a
 * buffer that wasn't reserved; reserve_free twice, or without a reserve, frees
 * nothing; a failed split-op malloc leaves the ring able to reserve again.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail_malloc = 0;

static void *test_malloc(size_t sz) {
    if (fail_malloc)
        return NULL;
    return malloc(sz);
}

#define malloc(sz) test_malloc(sz)
#include "../../simple_ringbuf_c.c"
#undef malloc

#define RING_SZ 64

static int failures = 0;

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

/* Empty ring, write position off bytes before the end */
static void position(kis_simple_ringbuf_t *rb, size_t off) {
    uint8_t junk[RING_SZ];

    kis_simple_ringbuf_clear(rb);
    memset(junk, 0, sizeof(junk));
    CHECK(kis_simple_ringbuf_write(rb, junk, RING_SZ - off) == RING_SZ - off);
    CHECK(kis_simple_ringbuf_read(rb, NULL, RING_SZ - off) == RING_SZ - off);
}

int main(void) {
    kis_simple_ringbuf_t *rb = kis_simple_ringbuf_create(RING_SZ);
    uint8_t *buf = NULL;
    uint8_t other[8];

    CHECK(rb != NULL);
    if (rb == NULL)
        return 1;

    /* Oversized commit of a split (malloc'd) reserve: refused, buffer freed */
    position(rb, 10);
    CHECK(kis_simple_ringbuf_reserve(rb, (void **) &buf, 20) == 20);
    CHECK(kis_simple_ringbuf_commit(rb, buf, 40) == 0);
    CHECK(kis_simple_ringbuf_used(rb) == 0);
    CHECK(rb->mid_commit == 0 && rb->free_commit == 0 && rb->reserve_data == NULL);

    /* Oversized commit of an in-ring reserve, larger than the ring */
    position(rb, 50);
    CHECK(kis_simple_ringbuf_reserve(rb, (void **) &buf, 20) == 20);
    CHECK(kis_simple_ringbuf_commit(rb, buf, RING_SZ * 2) == 0);
    CHECK(kis_simple_ringbuf_used(rb) == 0);

    /* zcopy reserve across the end: only the contiguous part may be committed */
    position(rb, 10);
    CHECK(kis_simple_ringbuf_reserve_zcopy(rb, (void **) &buf, 40) == 10);
    CHECK(kis_simple_ringbuf_commit(rb, buf, 40) == 0);
    CHECK(kis_simple_ringbuf_used(rb) == 0);
    CHECK(kis_simple_ringbuf_reserve_zcopy(rb, (void **) &buf, 40) == 10);
    CHECK(kis_simple_ringbuf_commit(rb, buf, 10) == 10);
    CHECK(kis_simple_ringbuf_used(rb) == 10);

    /* Commit of a pointer that isn't the reserve */
    position(rb, 10);
    CHECK(kis_simple_ringbuf_reserve(rb, (void **) &buf, 20) == 20);
    CHECK(kis_simple_ringbuf_commit(rb, other, 8) == 0);
    CHECK(kis_simple_ringbuf_used(rb) == 0);

    /* Exact and short commits still work */
    position(rb, 10);
    CHECK(kis_simple_ringbuf_reserve(rb, (void **) &buf, 20) == 20);
    memset(buf, 0x55, 20);
    CHECK(kis_simple_ringbuf_commit(rb, buf, 15) == 15);
    CHECK(kis_simple_ringbuf_used(rb) == 15);

    /* reserve_free twice and without a reserve: one free, then nothing */
    position(rb, 10);
    CHECK(kis_simple_ringbuf_reserve(rb, (void **) &buf, 20) == 20);
    kis_simple_ringbuf_reserve_free(rb, buf);
    kis_simple_ringbuf_reserve_free(rb, buf);
    CHECK(rb->mid_commit == 0 && rb->free_commit == 0 && rb->reserve_data == NULL);
    kis_simple_ringbuf_reserve_free(rb, other);
    CHECK(kis_simple_ringbuf_commit(rb, buf, 0) == 0);

    /* Failed split-op malloc: no reserve held, the next one works */
    position(rb, 10);
    fail_malloc = 1;
    buf = NULL;
    CHECK(kis_simple_ringbuf_reserve(rb, (void **) &buf, 20) == 0);
    fail_malloc = 0;
    CHECK(rb->mid_commit == 0 && rb->free_commit == 0);
    CHECK(kis_simple_ringbuf_reserve(rb, (void **) &buf, 20) == 20);
    CHECK(buf != NULL);
    CHECK(kis_simple_ringbuf_commit(rb, buf, 20) == 20);
    CHECK(kis_simple_ringbuf_used(rb) == 20);
    CHECK(rb->length <= rb->buffer_sz);

    /* A zero-size zcopy reserve, or one on a full ring, fails and holds no reserve */
    position(rb, 10);
    CHECK(kis_simple_ringbuf_reserve_zcopy(rb, (void **) &buf, 0) == 0);
    CHECK(rb->mid_commit == 0);
    {
        uint8_t fill[RING_SZ];

        memset(fill, 0, sizeof(fill));
        kis_simple_ringbuf_clear(rb);
        CHECK(kis_simple_ringbuf_write(rb, fill, RING_SZ) == RING_SZ);
        CHECK(kis_simple_ringbuf_available(rb) == 0);
        CHECK(kis_simple_ringbuf_reserve_zcopy(rb, (void **) &buf,
                    kis_simple_ringbuf_available(rb)) == 0);
        CHECK(rb->mid_commit == 0);
    }
    kis_simple_ringbuf_clear(rb);
    CHECK(kis_simple_ringbuf_reserve_zcopy(rb, (void **) &buf, 8) == 8);
    CHECK(kis_simple_ringbuf_commit(rb, buf, 8) == 8);

    kis_simple_ringbuf_free(rb);

    if (failures) {
        fprintf(stderr, "ringbuf_reserve_test: %d failure(s)\n", failures);
        return 1;
    }

    printf("ringbuf_reserve_test: ok\n");
    return 0;
}
