/* Option and allocation handling in the serial helpers.
 *
 * parse_baud() must take only a plain decimal rate, with spaces around it
 * skipped as sscanf did (so "11, 15, 20" channel lists still work): signs,
 * trailing junk and values that wrap (4294976896 is 9600 once cut to 32 bits, which
 * atoi and sscanf %u accepted) are refused.  channel= in catsniffer and
 * sniffle is parsed the same way, so 4294967311 can't wrap to channel 15, and
 * so is every channel the catsniffer and freaklabs chantranslate callbacks
 * get (channels=, hop lists, set-channel).  A refused baud value is not
 * echoed into the error message.
 *
 * For the helpers with a pty-testable open callback, also the line speed set
 * for the default and for supported values, and that bad values are refused
 * before the device is opened (get_baud() returns -1 for them, which used to
 * become the termios speed).
 *
 * Probe and open run with each allocation in turn failing: they must return
 * an error (-1, not "not my device"), close the device and leak nothing (LSan
 * in the asan flavor), and the probe must free its strings on success too.
 *
 *   F="--set framework --libs -llzma -lwebsockets -lutil"
 *   tools/unit.sh <tree> test/serial_baud/baud_test.c $F --cflags "-DBAUD_FREAKLABS" --flavor asan
 *   tools/unit.sh <tree> test/serial_baud/baud_test.c $F --cflags "-DBAUD_RADVIEW" --flavor asan
 *   tools/unit.sh <tree> test/serial_baud/baud_test.c $F --cflags "-DBAUD_SNIFFLE" --flavor asan
 *   tools/unit.sh <tree> test/serial_baud/baud_test.c $F --cflags "-DBAUD_NRF51822" --flavor asan
 *   tools/unit.sh <tree> test/serial_baud/baud_test.c $F --cflags "-DBAUD_LORAPIPE" --flavor asan
 *   tools/unit.sh <tree> test/serial_baud/baud_test.c $F --cflags "-DBAUD_CATSNIFFER" --flavor asan
 */

#define _GNU_SOURCE

#include <pty.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "../../config.h"
#include "../../capture_framework.h"
#include "../../simple_ringbuf_c.h"

/* Fail the kt_fail_at'th allocation the helper makes (0: never) */
static int kt_fail_at = 0;
static int kt_allocs = 0;

static int kt_fail_now(void) {
    kt_allocs++;
    return kt_fail_at > 0 && kt_allocs == kt_fail_at;
}

static void *kt_malloc(size_t n) {
    return kt_fail_now() ? NULL : malloc(n);
}

static void *kt_calloc(size_t n, size_t sz) {
    return kt_fail_now() ? NULL : calloc(n, sz);
}

static char *kt_strdup(const char *s) {
    return kt_fail_now() ? NULL : strdup(s);
}

static char *kt_strndup(const char *s, size_t n) {
    return kt_fail_now() ? NULL : strndup(s, n);
}

#define malloc(n) kt_malloc(n)
#define calloc(n, sz) kt_calloc(n, sz)
#define strdup(s) kt_strdup(s)
#define strndup(s, n) kt_strndup(s, n)

#define main helper_main
#if defined(BAUD_FREAKLABS)
#include "../../capture_freaklabs_zigbee_v2/capture_freaklabs_zigbee_v2.c"
typedef local_freaklabs_t local_t;
#define HELPER "freaklabs"
#define PROBE_IF "freaklabs"
#define BAUD_OPT "baudrate"
#define TEST_OPEN 1
#elif defined(BAUD_RADVIEW)
#include "../../capture_serial_radview/capture_serial_radview.c"
typedef local_radview_t local_t;
#define HELPER "radview"
#define PROBE_IF "radview"
#define BAUD_OPT "baudrate"
#define TEST_OPEN 1
#elif defined(BAUD_SNIFFLE)
#include "../../capture_sniffle_ble/capture_sniffle_ble.c"
typedef local_sniffle_t local_t;
#define HELPER "sniffle"
#define PROBE_IF "sniffle_ble"
#define BAUD_OPT "baud"
#define TEST_OPEN 1
#define OPEN_CHANNEL(l, i) ((l)->channel)
#elif defined(BAUD_NRF51822)
#include "../../capture_nrf_51822/capture_nrf_51822.c"
typedef local_nrf_t local_t;
#define HELPER "nrf51822"
#define PROBE_IF "nrf51822"
#define BAUD_OPT "baudrate"
#define TEST_OPEN 1
#elif defined(BAUD_LORAPIPE)
#include "../../capture_lorapipe/capture_lorapipe.c"
#define HELPER "lorapipe"
#define PROBE_IF "lorapipe"
#define TEST_OPEN 0
#elif defined(BAUD_CATSNIFFER)
#include "../../capture_catsniffer_zigbee/capture_catsniffer_zigbee.c"
typedef local_catsniffer_t local_t;
#define HELPER "catsniffer"
#define PROBE_IF "catsniffer_zigbee"
#define BAUD_OPT "baudrate"
#define TEST_OPEN 1
#define OPEN_CHANNEL(l, i) ((i) != NULL && (i)->chanset != NULL ? atoi((i)->chanset) : -1)
#else
#error "define BAUD_FREAKLABS, BAUD_RADVIEW, BAUD_SNIFFLE, BAUD_NRF51822, BAUD_LORAPIPE or BAUD_CATSNIFFER"
#endif
#undef main

#undef malloc
#undef calloc
#undef strdup
#undef strndup

static int failures = 0;

/* A refused baud value with text that must not reach the message */
#define HOSTILE_MARK "ZZQ"
#define HOSTILE_BAUD "9600" HOSTILE_MARK "\x1b[2J"

static void expect_parse(const char *str, int want) {
    int got = parse_baud(str);

    if (got != want) {
        fprintf(stderr, "FAIL parse_baud('%s') = %d, want %d\n", str, got, want);
        failures++;
    }
}

static void test_parse(void) {
    expect_parse("9600", 9600);
    expect_parse("115200", 115200);
    expect_parse("00115200", 115200);
    expect_parse("4000000", 4000000);

    expect_parse(NULL, -1);
    expect_parse("", -1);
    expect_parse("abc", -1);
    expect_parse("0", -1);
    expect_parse("-1", -1);
    expect_parse("-9600", -1);
    expect_parse("+9600", -1);
    /* Spaces around the value are skipped, as sscanf did */
    expect_parse(" 9600", 9600);
    expect_parse("9600 ", 9600);
    expect_parse("\t115200\r\n", 115200);
    expect_parse(" ", -1);
    expect_parse("96 00", -1);
    expect_parse(" +9600", -1);
    expect_parse(" -9600", -1);
    expect_parse("9600 x", -1);
    expect_parse("115200abc", -1);
    expect_parse("0x2580", -1);
    expect_parse("4000001", -1);
    expect_parse("4294976896", -1);
    expect_parse("4294967295", -1);
    expect_parse("99999999999999999999999", -1);

    /* get_baud() takes what parse_baud() refuses as unsupported */
    if (get_baud(parse_baud("4294976896")) != -1) {
        fprintf(stderr, "FAIL get_baud(parse_baud(4294976896)) != -1\n");
        failures++;
    }
}

#if defined(BAUD_CATSNIFFER) || defined(BAUD_FREAKLABS)
/* chantranslate_callback parses every channel the framework hands it (the
 * channels= list, hop lists and set-channel requests) */
static void expect_translate(int band, const char *str, int want) {
    kis_capture_handler_t caph;
    local_t local;
    local_channel_t *c;
    int got;

    memset(&caph, 0, sizeof(caph));
    memset(&local, 0, sizeof(local));
    local.band = band;
    caph.userdata = &local;

    c = (local_channel_t *) chantranslate_callback(&caph, str);
    got = c != NULL ? (int) c->channel : -1;
    free(c);

    if (got != want) {
        fprintf(stderr, "FAIL chantranslate(band %d, '%s') = %d, want %d\n", band, str, got, want);
        failures++;
    }
}

static void test_translate(void) {
    expect_translate(2, "11", 11);
    expect_translate(2, "15", 15);
    expect_translate(2, "015", 15);
    expect_translate(2, "26", 26);

    expect_translate(2, "4294967311", -1);
    expect_translate(2, "18446744073709551631", -1);
    expect_translate(2, "15abc", -1);
    /* The framework splits "11, 15, 20" at the commas, so list entries keep
     * their spaces */
    expect_translate(2, "15 ", 15);
    expect_translate(2, " 15", 15);
    expect_translate(2, " 20 ", 20);
    expect_translate(2, " ", -1);
    expect_translate(2, "1 5", -1);
    expect_translate(2, " +15", -1);
    expect_translate(2, " 15x", -1);
    expect_translate(2, " 4294967311", -1);
    expect_translate(2, "+15", -1);
    expect_translate(2, "-15", -1);
    expect_translate(2, "0x0f", -1);
    expect_translate(2, "", -1);
    expect_translate(2, "abc", -1);
    expect_translate(2, "27", -1);

#if defined(BAUD_CATSNIFFER)
    /* The band range is checked here too */
    expect_translate(2, "10", -1);
    expect_translate(1, "1", 1);
    expect_translate(1, "10", 10);
    expect_translate(1, "11", -1);
    expect_translate(0, "0", 0);
    expect_translate(0, "1", -1);
#else
    /* and at set time in freaklabs */
    expect_translate(1, "1", 1);
    expect_translate(0, "0", 0);
#endif
}
#endif

#if defined(BAUD_LORAPIPE)
/* baud= is checked before the device opens, so a refused value is seen
 * without a pty: refused, and not echoed back into the message */
static void test_lorapipe_baud(void) {
    static const char *vals[] = { HOSTILE_BAUD, "12345", "4294976896", "-1" };
    size_t i;

    for (i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        kis_capture_handler_t caph;
        local_lorapipe_t local;
        cf_params_interface_t *iface = NULL;
        cf_params_spectrum_t *spec = NULL;
        char *uuid = NULL;
        uint32_t dlt = 0;
        char def[256], msg[STATUS_MAX];
        int r;

        memset(&caph, 0, sizeof(caph));
        memset(&local, 0, sizeof(local));
        local.fd = -1;
        caph.userdata = &local;

        snprintf(def, sizeof(def), "lorapipe:device=/nonexistent-baud-test,region=US915,baud=%s", vals[i]);
        msg[0] = 0;
        r = open_callback(&caph, 0, def, msg, &dlt, &uuid, &iface, &spec);

        if (r > 0 || local.fd >= 0 || strstr(msg, "baud") == NULL || strstr(msg, HOSTILE_MARK) != NULL) {
            fprintf(stderr, "FAIL lorapipe baud='%s': r=%d fd=%d msg=%s\n", vals[i], r, local.fd, msg);
            failures++;
        } else {
            printf("rejected lorapipe baud: %s\n", msg);
        }

        if (iface != NULL)
            cf_params_interface_free(iface);
        if (spec != NULL)
            cf_params_spectrum_free(spec);
        free(uuid);
        free(local.interface);
        free(local.name);
    }
}
#endif

/* The lowest free fd, to see whether a call left one open */
static int next_fd(void) {
    int fd = open("/dev/null", O_RDONLY);

    if (fd >= 0)
        close(fd);

    return fd;
}

static int run_probe(const char *def, char *msg) {
    kis_capture_handler_t caph;
    cf_params_interface_t *iface = NULL;
    cf_params_spectrum_t *spec = NULL;
    char *uuid = NULL;
    int r;

    memset(&caph, 0, sizeof(caph));
    msg[0] = 0;

    r = probe_callback(&caph, 0, (char *) def, msg, &uuid, &iface, &spec);

    /* As the framework does after every probe */
    free(uuid);
    if (iface != NULL)
        cf_params_interface_free(iface);
    if (spec != NULL)
        cf_params_spectrum_free(spec);

    return r;
}

static void expect_probe(const char *def, int want) {
    char msg[STATUS_MAX];
    int r = run_probe(def, msg);

    if (r != want) {
        fprintf(stderr, "FAIL probe '%s': r=%d want %d msg=%s\n", def, r, want, msg);
        failures++;
    }
}

/* Every allocation the probe makes, failed in turn, is an error */
static void test_probe_oom(void) {
    char msg[STATUS_MAX];
    int n, r;

    for (n = 1; n < 64; n++) {
        kt_allocs = 0;
        kt_fail_at = n;
        r = run_probe(PROBE_IF ":device=/dev/null", msg);
        kt_fail_at = 0;

        if (kt_allocs < n)
            break;

        if (r != -1) {
            fprintf(stderr, "FAIL probe with allocation %d failing: r=%d msg=%s\n", n, r, msg);
            failures++;
        }
    }

    printf("probe: %d allocation failures checked\n", n - 1);
}

static void test_probe(void) {
    expect_probe(PROBE_IF ":device=/dev/null", 1);
    expect_probe(PROBE_IF ":name=nodevice", 0);
    expect_probe("someother:device=/dev/null", 0);
    test_probe_oom();
}

#if TEST_OPEN
#ifndef OPEN_CHANNEL
#define OPEN_CHANNEL(l, i) (-1)
#endif

/* Open a pty through the helper; returns the callback result, the speed set,
 * whether the helper opened the device and the channel it opened on */
static int try_open(const char *opts, speed_t *got, int *opened, int *channel, char *msg) {
    int mfd, sfd;
    char name[256], def[512];
    kis_capture_handler_t caph;
    local_t local;
    cf_params_interface_t *iface = NULL;
    cf_params_spectrum_t *spec = NULL;
    char *uuid = NULL;
    uint32_t dlt = 0;
    struct termios t;
    int r;

    if (openpty(&mfd, &sfd, name, NULL, NULL) < 0)
        return -99;

    /* Start the pty at a speed neither answer uses */
    tcgetattr(sfd, &t);
    cfsetispeed(&t, B9600);
    cfsetospeed(&t, B9600);
    tcsetattr(sfd, TCSANOW, &t);

    memset(&caph, 0, sizeof(caph));
    memset(&local, 0, sizeof(local));
    local.fd = -1;
    caph.userdata = &local;

    snprintf(def, sizeof(def), HELPER ":device=%s%s", name, opts);
    msg[0] = 0;
    r = open_callback(&caph, 0, def, msg, &dlt, &uuid, &iface, &spec);

    *opened = local.fd >= 0;
    *channel = r > 0 ? OPEN_CHANNEL(&local, iface) : -1;
    if (local.fd >= 0) {
        tcgetattr(local.fd, &t);
        *got = cfgetospeed(&t);
        close(local.fd);
    }

    if (iface != NULL)
        cf_params_interface_free(iface);
    if (spec != NULL)
        cf_params_spectrum_free(spec);
    free(uuid);
    free(local.interface);
    free(local.name);
    close(sfd);
    close(mfd);
    return r;
}

static void expect_speed(const char *opts, speed_t want) {
    speed_t got = 0;
    int opened = 0, channel;
    char msg[STATUS_MAX];
    int r = try_open(opts, &got, &opened, &channel, msg);

    if (r <= 0 || got != want) {
        fprintf(stderr, "FAIL '%s': r=%d speed=%lu want=%lu msg=%s\n", opts, r,
                (unsigned long) got, (unsigned long) want, msg);
        failures++;
    }
}

/* A bad option value is refused, with a message naming the option, before
 * the device is opened */
static void expect_refused(const char *opt, const char *val, const char *word) {
    speed_t got = 0;
    int opened = 0, channel;
    char opts[128];
    char msg[STATUS_MAX];
    int r;

    snprintf(opts, sizeof(opts), ",%s=%s", opt, val);
    r = try_open(opts, &got, &opened, &channel, msg);

    if (r > 0 || opened || strstr(msg, word) == NULL) {
        fprintf(stderr, "FAIL '%s': r=%d opened=%d speed=%lu msg=%s\n", opts, r, opened,
                (unsigned long) got, msg);
        failures++;
    } else {
        printf("rejected '%s': %s\n", opts, msg);
    }
}

static void expect_reject(const char *val) {
    expect_refused(BAUD_OPT, val, "baud");
}

/* A refused baud value is not echoed back into the message */
static void expect_reject_quiet(void) {
    speed_t got = 0;
    int opened = 0, channel;
    char msg[STATUS_MAX];
    int r = try_open("," BAUD_OPT "=" HOSTILE_BAUD, &got, &opened, &channel, msg);

    if (r > 0 || opened || strstr(msg, "baud") == NULL || strstr(msg, HOSTILE_MARK) != NULL) {
        fprintf(stderr, "FAIL hostile " BAUD_OPT "=: r=%d opened=%d msg=%s\n", r, opened, msg);
        failures++;
    }
}

#if defined(BAUD_CATSNIFFER) || defined(BAUD_SNIFFLE)
static void expect_channel(const char *val, int want) {
    speed_t got = 0;
    int opened = 0, channel = -1;
    char opts[128];
    char msg[STATUS_MAX];
    int r;

    snprintf(opts, sizeof(opts), ",channel=%s", val);
    r = try_open(opts, &got, &opened, &channel, msg);

    if (r <= 0 || channel != want) {
        fprintf(stderr, "FAIL '%s': r=%d channel=%d want %d msg=%s\n", opts, r, channel, want, msg);
        failures++;
    }
}

static void test_channel(void) {
#if defined(BAUD_CATSNIFFER)
    expect_channel("11", 11);
    expect_channel("26", 26);
    expect_channel("015", 15);
    expect_channel(" 15", 15);
    expect_refused("channel", "10", "channel");
    expect_refused("channel", "27", "channel");
    expect_refused("channel", "0", "channel");
    expect_refused("channel", "15x", "channel");
    expect_refused("channel", "+15", "channel");
    expect_refused("channel", "-15", "channel");
    expect_refused("channel", " -15", "channel");
    expect_refused("channel", "abc", "channel");
    expect_refused("channel", "4294967311", "channel");
#else
    expect_channel("37", 37);
    expect_channel("39", 39);
    expect_refused("channel", "36", "channel");
    expect_refused("channel", "40", "channel");
    expect_refused("channel", "37x", "channel");
    expect_channel(" 38", 38);
    expect_refused("channel", "+38", "channel");
    expect_refused("channel", " +38", "channel");
    expect_refused("channel", "abc", "channel");
    expect_refused("channel", "4294967333", "channel");
#endif
}
#endif

/* A device that opens but isn't a tty fails tcsetattr; the helper must close
 * it rather than leak the fd (and the device string, which LSan checks) */
static void expect_not_tty(void) {
    kis_capture_handler_t caph;
    local_t local;
    cf_params_interface_t *iface = NULL;
    cf_params_spectrum_t *spec = NULL;
    char *uuid = NULL;
    uint32_t dlt = 0;
    char msg[STATUS_MAX];
    int before, after, r;

    before = next_fd();

    memset(&caph, 0, sizeof(caph));
    memset(&local, 0, sizeof(local));
    local.fd = -1;
    caph.userdata = &local;

    msg[0] = 0;
    r = open_callback(&caph, 0, HELPER ":device=/dev/null", msg, &dlt, &uuid, &iface, &spec);

    after = next_fd();

    if (r > 0 || local.fd >= 0 || after != before) {
        fprintf(stderr, "FAIL not a tty: r=%d fd=%d next fd %d, was %d msg=%s\n", r, local.fd,
                after, before, msg);
        failures++;
    } else {
        printf("rejected /dev/null: %s\n", msg);
    }

    if (iface != NULL)
        cf_params_interface_free(iface);
    if (spec != NULL)
        cf_params_spectrum_free(spec);
    free(uuid);
    free(local.interface);
    free(local.name);
}

/* Every allocation the open makes, failed in turn, is an error that closes
 * the device */
static void test_open_oom(void) {
    speed_t got;
    int opened, channel, before, after, n, r;
    char msg[STATUS_MAX];

    for (n = 1; n < 64; n++) {
        before = next_fd();
        opened = 0;

        kt_allocs = 0;
        kt_fail_at = n;
        r = try_open("", &got, &opened, &channel, msg);
        kt_fail_at = 0;

        after = next_fd();

        if (kt_allocs < n)
            break;

        if (r >= 0 || opened || after != before) {
            fprintf(stderr, "FAIL open with allocation %d failing: r=%d opened=%d next fd %d, "
                    "was %d msg=%s\n", n, r, opened, after, before, msg);
            failures++;
        }
    }

    printf("open: %d allocation failures checked\n", n - 1);
}

static void test_open(void) {
    expect_not_tty();
    expect_speed("", D_BAUDRATE);
    expect_speed("," BAUD_OPT "=115200", B115200);
    expect_speed("," BAUD_OPT "=57600", B57600);
    expect_reject("12345");
    expect_reject("0");
    expect_reject("-1");
    expect_reject("abc");
    expect_reject("115200abc");
    expect_reject("4294976896");
    expect_reject("+115200");
    expect_reject_quiet();
#if defined(BAUD_CATSNIFFER) || defined(BAUD_SNIFFLE)
    test_channel();
#endif
    test_open_oom();
}
#endif

int main(void) {
    test_parse();
    test_probe();
#if defined(BAUD_CATSNIFFER) || defined(BAUD_FREAKLABS)
    test_translate();
#endif
#if defined(BAUD_LORAPIPE)
    test_lorapipe_baud();
#endif
#if TEST_OPEN
    test_open();
#endif

    if (failures) {
        fprintf(stderr, HELPER " baud_test: %d failure(s)\n", failures);
        return 1;
    }

    printf(HELPER " baud_test: ok\n");
    return 0;
}
