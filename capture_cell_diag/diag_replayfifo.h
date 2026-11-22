/* diag_replayfifo.h - tells a replay FIFO's closed writer from a quiet one.
 *
 * A replay FIFO outlives its writers: when one closes, the frame it left
 * partial is flushed so the next writer's bytes never join onto it. Linux
 * reports the close as POLLHUP. macOS reports nothing: poll(POLLIN) on the
 * blocking read end just times out. So on an idle tick the fd is read once
 * non-blocking: EAGAIN means the writer is still open, 0 means it closed.
 *
 * The writer_gone flag makes that flush happen once per writer, not on every
 * idle tick, and stops the probing until bytes arrive again.
 *
 * Pure libc, tested standalone in test_diag_replayfifo.c.
 */
#ifndef DIAG_REPLAYFIFO_H
#define DIAG_REPLAYFIFO_H

#include <stddef.h>

typedef struct {
    int writer_gone;
    int pending_errno;  /* a restore that failed after a read, not yet reported */
} diag_replayfifo_t;

typedef enum {
    DIAG_REPLAYFIFO_IDLE = 0,   /* nothing to read; the writer is still open */
    DIAG_REPLAYFIFO_DATA,       /* *n bytes were read into buf: feed them */
    DIAG_REPLAYFIFO_CLOSED,     /* the writer closed: flush the partial frame */
    DIAG_REPLAYFIFO_ERROR       /* fcntl or read failed; errno is set. A restore
                                 * that failed after a read comes here on the
                                 * next call, the bytes having gone out as DATA */
} diag_replayfifo_rc;

void diag_replayfifo_init(diag_replayfifo_t *w);

/* Bytes arrived from a writer. */
void diag_replayfifo_bytes(diag_replayfifo_t *w);

/* The platform reported the writer's close (POLLHUP or an EOF read).
 * Returns 1 the first time for a writer (flush now), 0 after. */
int diag_replayfifo_writer_closed(diag_replayfifo_t *w);

/* An idle tick on blocking FIFO read end fd. Reads at most len bytes
 * non-blocking, then restores the fd's flags. Once the writer is known gone
 * it returns IDLE without reading. */
diag_replayfifo_rc diag_replayfifo_idle(diag_replayfifo_t *w, int fd,
                                        void *buf, size_t len, size_t *n);

/* fcntl(fd, F_SETFL, flags): 0, or -1 with errno set. */
typedef int (*diag_replayfifo_setfl_fn)(int fd, int flags);
diag_replayfifo_rc diag_replayfifo_idle_with(diag_replayfifo_t *w,
                                             diag_replayfifo_setfl_fn setfl, int fd,
                                             void *buf, size_t len, size_t *n);

#endif /* DIAG_REPLAYFIFO_H */
