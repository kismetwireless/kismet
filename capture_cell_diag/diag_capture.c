/* diag_capture.c - reusable DIAG capture core. See diag_capture.h. */
/* cfmakeraw / CRTSCTS / O_CLOEXEC are BSD/POSIX extensions gated behind a
 * feature-test macro under strict -std=c11; the Kismet build uses -std=gnu11
 * where they are visible by default. */
#define _DEFAULT_SOURCE
#include "diag_capture.h"
#include "diag_hdlc.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define DIAG_FLAG              0x7E
#define DIAG_CAPTURE_IDLE_TIMEOUTS 12   /* ~12 * VTIME (5s) = 60s of silence */

int diag_capture_open(const char *port) {
    struct termios tio;
    int fd = open(port, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    if (tcgetattr(fd, &tio) != 0) {
        close(fd);
        return -1;
    }
    cfmakeraw(&tio);
    cfsetispeed(&tio, B115200);
    cfsetospeed(&tio, B115200);
    tio.c_cflag |= (CLOCAL | CREAD);
    tio.c_cflag &= ~CRTSCTS;
    tio.c_cc[VMIN] = 0;
    tio.c_cc[VTIME] = 50;              /* 5.0s per-read timeout */
    if (tcsetattr(fd, TCSANOW, &tio) != 0) {
        close(fd);
        return -1;
    }
    tcflush(fd, TCIOFLUSH);
    return fd;
}

/* Return the next raw byte from the buffered reader: 1 on byte (*b set),
 * 0 on read timeout (no data this interval), -1 on error/EOF. */
static int next_byte(int fd, diag_reader_t *r, uint8_t *b) {
    if (r->pos >= r->len) {
        ssize_t n = read(fd, r->buf, sizeof(r->buf));
        if (n < 0) {
            if (errno == EINTR)
                return 0;
            return -1;
        }
        if (n == 0)
            return 0;                  /* VTIME timeout */
        r->len = (size_t)n;
        r->pos = 0;
    }
    *b = r->buf[r->pos++];
    return 1;
}

int diag_read_frame(int fd, diag_reader_t *r,
                    uint8_t *out, size_t outcap, size_t *len) {
    uint8_t raw[2048];
    size_t rawlen = 0;
    int idle = 0;

    for (;;) {
        uint8_t b;
        int rc = next_byte(fd, r, &b);
        if (rc < 0)
            return -1;
        if (rc == 0) {
            if (++idle >= DIAG_CAPTURE_IDLE_TIMEOUTS)
                return -1;
            continue;
        }
        idle = 0;

        if (b == DIAG_FLAG) {
            size_t n;
            if (rawlen == 0)
                continue;              /* skip leading / back-to-back flags */
            n = diag_hdlc_unescape(raw, rawlen, out, outcap);
            rawlen = 0;
            if (n == 0)
                continue;              /* empty: skip */
            if (!diag_hdlc_check_crc(out, &n))
                continue;              /* partial (joined mid-frame) or corrupt: skip */
            *len = n;
            return 0;                  /* CRC-valid frame, any opcode */
        }

        if (rawlen >= sizeof(raw)) {
            rawlen = 0;                /* oversize: drop, resync */
            continue;
        }
        raw[rawlen++] = b;
    }
}
