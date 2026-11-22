/* diag_replayfifo.c - see diag_replayfifo.h. */

#include "diag_replayfifo.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

void diag_replayfifo_init(diag_replayfifo_t *w) {
    w->writer_gone = 0;
    w->pending_errno = 0;
}

void diag_replayfifo_bytes(diag_replayfifo_t *w) {
    w->writer_gone = 0;
}

int diag_replayfifo_writer_closed(diag_replayfifo_t *w) {
    if (w->writer_gone)
        return 0;
    w->writer_gone = 1;
    return 1;
}

static int sys_setfl(int fd, int flags) {
    return fcntl(fd, F_SETFL, flags) < 0 ? -1 : 0;
}

diag_replayfifo_rc diag_replayfifo_idle(diag_replayfifo_t *w, int fd,
                                        void *buf, size_t len, size_t *n) {
    return diag_replayfifo_idle_with(w, sys_setfl, fd, buf, len, n);
}

diag_replayfifo_rc diag_replayfifo_idle_with(diag_replayfifo_t *w,
                                             diag_replayfifo_setfl_fn setfl, int fd,
                                             void *buf, size_t len, size_t *n) {
    *n = 0;
    if (w->pending_errno) {
        errno = w->pending_errno;
        w->pending_errno = 0;
        return DIAG_REPLAYFIFO_ERROR;
    }
    if (w->writer_gone)
        return DIAG_REPLAYFIFO_IDLE;

    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || setfl(fd, fl | O_NONBLOCK) < 0)
        return DIAG_REPLAYFIFO_ERROR;
    ssize_t r = read(fd, buf, len);
    int rerr = errno;
    /* Restored before anything is reported: the read loop's fd blocks. A
     * failed restore after a read still hands over the bytes, and is reported
     * on the next call. */
    if (setfl(fd, fl) < 0) {
        int serr = errno;
        if (r <= 0)
            return DIAG_REPLAYFIFO_ERROR;
        w->pending_errno = serr != 0 ? serr : EIO;
    }

    if (r > 0) {
        w->writer_gone = 0;
        *n = (size_t)r;
        return DIAG_REPLAYFIFO_DATA;
    }
    if (r == 0) {
        w->writer_gone = 1;
        return DIAG_REPLAYFIFO_CLOSED;
    }
    if (rerr == EAGAIN || rerr == EWOULDBLOCK || rerr == EINTR)
        return DIAG_REPLAYFIFO_IDLE;
    errno = rerr;
    return DIAG_REPLAYFIFO_ERROR;
}
