/* diag_gsmtap_sink.c - the live GSMTAP UDP sink; see diag_gsmtap_sink.h. */

#include "diag_gsmtap_sink.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

const uint16_t DIAG_GSMTAP_ELIGIBLE_CODES[] = {
    0xB0C0, 0xB0E1, 0xB0E2, 0xB0E3, 0xB0EC, 0xB0ED,
};
const size_t DIAG_GSMTAP_ELIGIBLE_COUNT =
    sizeof(DIAG_GSMTAP_ELIGIBLE_CODES) / sizeof(DIAG_GSMTAP_ELIGIBLE_CODES[0]);

int diag_gsmtap_eligible(uint16_t code) {
    for (size_t i = 0; i < DIAG_GSMTAP_ELIGIBLE_COUNT; i++)
        if (DIAG_GSMTAP_ELIGIBLE_CODES[i] == code)
            return 1;
    return 0;
}

int diag_gsmtap_sink_open(diag_gsmtap_sink_t *s, const char *dest) {
    memset(s, 0, sizeof(*s));
    s->fd = -1;
    snprintf(s->dest, sizeof(s->dest), "%s", dest ? dest : "");

    const char *colon = dest ? strrchr(dest, ':') : NULL;
    if (colon == NULL || colon == dest) {
        errno = EINVAL;
        return -1;
    }
    char host[24];
    size_t hl = (size_t)(colon - dest);
    if (hl >= sizeof(host)) {
        errno = EINVAL;
        return -1;
    }
    memcpy(host, dest, hl);
    host[hl] = '\0';
    long port = strtol(colon + 1, NULL, 10);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (port < 1 || port > 65535 || inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        errno = EINVAL;
        return -1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    int fl = fcntl(fd, F_GETFL, 0);
    /* Unconnected, and sent with sendto(). A connect()ed socket would report a
     * closed port's ICMP unreachable as ECONNREFUSED on a later send, so
     * `errors` would count "nobody is listening" -- the normal state of a tap
     * with no Wireshark attached. */
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    s->fd = fd;
    s->to = sa;
    return 0;
}

void diag_gsmtap_sink_close(diag_gsmtap_sink_t *s) {
    if (s->fd >= 0)
        close(s->fd);
    s->fd = -1;
}

int diag_gsmtap_sink_send(diag_gsmtap_sink_t *s, const uint8_t *frame, size_t len) {
    if (s->fd < 0) {
        s->errors++;
        return 0;
    }
    ssize_t w;
    do {
        w = sendto(s->fd, frame, len, MSG_DONTWAIT | MSG_NOSIGNAL,
                   (const struct sockaddr *)&s->to, sizeof(s->to));
    } while (w < 0 && errno == EINTR);
    if (w < 0 || (size_t)w != len) {
        if (s->errors == 0)
            s->first_errno = (w < 0) ? errno : EMSGSIZE;
        s->errors++;
        return 0;
    }
    s->sent++;
    return 1;
}

int diag_gsmtap_sink_report(const diag_gsmtap_sink_t *s, char *out, size_t outsz) {
    int n = snprintf(out, outsz, "gsmtap %s sent=%llu declined=%llu errors=%llu",
                     s->dest, (unsigned long long)s->sent,
                     (unsigned long long)s->declined,
                     (unsigned long long)s->errors);
    if (s->no_framer && n >= 0 && (size_t)n < outsz)
        n += snprintf(out + n, outsz - (size_t)n, " (no native framer: %llu)",
                      (unsigned long long)s->no_framer);
    return n;
}
