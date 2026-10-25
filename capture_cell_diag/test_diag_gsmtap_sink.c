/* test_diag_gsmtap_sink.c - standalone tests for the native GSMTAP UDP sink.
 *
 * Links diag_gsmtap_sink.c (libc only). The far end is a real loopback UDP
 * socket, so what is checked is what a Wireshark on the port would receive.
 */

#include "diag_gsmtap_sink.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int failures = 0;

#define CHECK(cond, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
        failures++; \
    } \
} while (0)

/* A bound loopback receiver; writes its "127.0.0.1:port" into dest. */
static int receiver(char *dest, size_t destsz) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
        return -1;
    socklen_t sl = sizeof(sa);
    getsockname(fd, (struct sockaddr *)&sa, &sl);
    struct timeval tv = { .tv_sec = 1 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    snprintf(dest, destsz, "127.0.0.1:%u", (unsigned)ntohs(sa.sin_port));
    return fd;
}

static void test_datagrams_arrive_whole_and_in_order(void) {
    char dest[32];
    int r = receiver(dest, sizeof(dest));
    CHECK(r >= 0, "no receiver");
    diag_gsmtap_sink_t s;
    CHECK(diag_gsmtap_sink_open(&s, dest) == 0, "open %s: %s", dest, strerror(errno));

    uint8_t a[] = { 0x02, 0x04, 0x0d, 0x00, 0xde, 0xad };
    uint8_t b[200];
    for (size_t i = 0; i < sizeof(b); i++)
        b[i] = (uint8_t)(i * 7);
    CHECK(diag_gsmtap_sink_send(&s, a, sizeof(a)) == 1, "send a");
    CHECK(diag_gsmtap_sink_send(&s, b, sizeof(b)) == 1, "send b");

    uint8_t got[512];
    ssize_t n = recv(r, got, sizeof(got), 0);
    CHECK(n == (ssize_t)sizeof(a) && memcmp(got, a, sizeof(a)) == 0, "datagram a: %zd", n);
    n = recv(r, got, sizeof(got), 0);
    CHECK(n == (ssize_t)sizeof(b) && memcmp(got, b, sizeof(b)) == 0, "datagram b: %zd", n);
    CHECK(s.sent == 2 && s.errors == 0, "sent=%llu errors=%llu",
          (unsigned long long)s.sent, (unsigned long long)s.errors);
    diag_gsmtap_sink_close(&s);
    close(r);
}

/* No listener is the normal state of a tap with no Wireshark attached, so it
 * must count no error -- not even after the ICMP port-unreachable comes back. */
static void test_nobody_listening_is_not_an_error(void) {
    char dest[32];
    int r = receiver(dest, sizeof(dest));
    close(r);                                /* the port is now closed */
    diag_gsmtap_sink_t s;
    CHECK(diag_gsmtap_sink_open(&s, dest) == 0, "open");
    uint8_t f[16] = { 0x02 };
    for (int i = 0; i < 5; i++) {
        diag_gsmtap_sink_send(&s, f, sizeof(f));
        usleep(2000);
    }
    CHECK(s.sent == 5 && s.errors == 0, "closed port: sent=%llu errors=%llu",
          (unsigned long long)s.sent, (unsigned long long)s.errors);
    diag_gsmtap_sink_close(&s);
}

static void test_bad_destinations_refuse(void) {
    diag_gsmtap_sink_t s;
    CHECK(diag_gsmtap_sink_open(&s, "localhost:4729") == -1, "a name is not an IPv4 literal");
    CHECK(diag_gsmtap_sink_open(&s, "127.0.0.1") == -1, "no port");
    CHECK(diag_gsmtap_sink_open(&s, "127.0.0.1:0") == -1, "port 0");
    CHECK(diag_gsmtap_sink_open(&s, "127.0.0.1:70000") == -1, "port > 65535");
    /* A send on a sink that never opened is a counted error, not a crash. */
    uint8_t f[4] = { 0 };
    CHECK(diag_gsmtap_sink_send(&s, f, sizeof(f)) == 0 && s.errors == 1, "closed sink send");
}

static void test_report_line(void) {
    diag_gsmtap_sink_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.dest, sizeof(s.dest), "127.0.0.1:4729");
    s.sent = 7; s.declined = 3; s.errors = 0;
    char b[160];
    diag_gsmtap_sink_report(&s, b, sizeof(b));
    CHECK(strcmp(b, "gsmtap 127.0.0.1:4729 sent=7 declined=3 errors=0") == 0, "%s", b);
    s.no_framer = 2;
    diag_gsmtap_sink_report(&s, b, sizeof(b));
    CHECK(strcmp(b, "gsmtap 127.0.0.1:4729 sent=7 declined=3 errors=0 "
                    "(no native framer: 2)") == 0, "%s", b);
}

static void test_eligible_set(void) {
    static const uint16_t want[] = { 0xB0C0, 0xB0E1, 0xB0E2, 0xB0E3, 0xB0EC, 0xB0ED };
    CHECK(DIAG_GSMTAP_ELIGIBLE_COUNT == 6, "count %zu", DIAG_GSMTAP_ELIGIBLE_COUNT);
    for (size_t i = 0; i < 6; i++)
        CHECK(diag_gsmtap_eligible(want[i]), "0x%04X", want[i]);
    CHECK(!diag_gsmtap_eligible(0xB821), "NR RRC has no GSMTAP type");
    CHECK(!diag_gsmtap_eligible(0xB193), "a measurement code is no candidate");
}

int main(void) {
    test_datagrams_arrive_whole_and_in_order();
    test_nobody_listening_is_not_an_error();
    test_bad_destinations_refuse();
    test_report_line();
    test_eligible_set();
    if (failures) {
        fprintf(stderr, "test_diag_gsmtap_sink: %d failure(s)\n", failures);
        return 1;
    }
    printf("test_diag_gsmtap_sink: all tests passed\n");
    return 0;
}
