/* test_diag_portdiag.c - standalone unit tests for the DIAG-port failure
 * diagnostic. Links only diag_portdiag.c (libc). `make check`. */

#include "diag_portdiag.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
        failures++; \
    } \
} while (0)

static void test_no_usb_device(void) {
    char out[512];
    diag_portdiag_format("123456789012345", "/dev/ttyUSB2", NULL,
                         NULL, 0, out, sizeof(out));
    CHECK(strstr(out, "123456789012345") != NULL, "IMEI present: %s", out);
    CHECK(strstr(out, "/dev/ttyUSB2") != NULL, "AT port present: %s", out);
    CHECK(strstr(out, "did not resolve to a USB device") != NULL,
          "no-usb-device wording: %s", out);
    CHECK(strstr(out, "diagport=") != NULL, "actionable hint: %s", out);
}

static void test_ifaces_present(void) {
    char out[512];
    int ifs[] = { 2, 3 };
    diag_portdiag_format("999888777666555", "/dev/ttyUSB3", "usb3-1.4",
                         ifs, 2, out, sizeof(out));
    CHECK(strstr(out, "usb3-1.4") != NULL, "usb dev present: %s", out);
    CHECK(strstr(out, "{2,3}") != NULL, "iface set formatted: %s", out);
    CHECK(strstr(out, "if00") != NULL, "mentions if00 convention: %s", out);
    CHECK(strstr(out, "USB composition") != NULL, "composition hint: %s", out);
}

static void test_no_ttyusb_on_device(void) {
    char out[512];
    diag_portdiag_format("111222333444555", "/dev/ttyUSB0", "usb1-2",
                         NULL, 0, out, sizeof(out));
    CHECK(strstr(out, "usb1-2") != NULL, "usb dev present: %s", out);
    CHECK(strstr(out, "MHI/wwan") != NULL || strstr(out, "wwan") != NULL,
          "mentions MHI/wwan path: %s", out);
    CHECK(strstr(out, "{") == NULL, "no iface set when none present: %s", out);
}

static void test_single_iface(void) {
    char out[512];
    int ifs[] = { 5 };
    diag_portdiag_format("1", "/dev/ttyUSB9", "usb2-1", ifs, 1,
                         out, sizeof(out));
    CHECK(strstr(out, "{5}") != NULL, "single iface: %s", out);
}

static void test_truncation_safe(void) {
    char tiny[16];
    int ifs[] = { 2, 3, 4 };
    int n = diag_portdiag_format("123456789012345", "/dev/ttyUSB2", "usb3-1.4",
                                 ifs, 3, tiny, sizeof(tiny));
    CHECK(tiny[sizeof(tiny) - 1] == '\0', "NUL-terminated on truncation");
    CHECK(n > (int)sizeof(tiny), "returns would-be length %d for truncation", n);
    CHECK(strlen(tiny) < sizeof(tiny), "fits buffer: len=%zu", strlen(tiny));
}

static void test_iface_missing_names_requested(void) {
    /* Exact-interface mode: profile pinned interface 3, but the device only
     * exposes {0,2}. The message must name interface 3 and NOT claim the
     * generic "lowest interface (if00)" convention was what we tried. */
    char out[512];
    int ifs[] = { 0, 2 };
    diag_portdiag_format_iface_missing("123456789012345", "/dev/ttyUSB2",
                                       "usb3-1.4", 3, ifs, 2, out, sizeof(out));
    CHECK(strstr(out, "123456789012345") != NULL, "IMEI present: %s", out);
    CHECK(strstr(out, "usb3-1.4") != NULL, "usb dev present: %s", out);
    CHECK(strstr(out, "3") != NULL, "requested iface named: %s", out);
    CHECK(strstr(out, "{0,2}") != NULL, "enumerated set present: %s", out);
    CHECK(strstr(out, "diagport=") != NULL, "actionable hint: %s", out);
    /* Must not misattribute the failure to the if00/lowest convention. */
    CHECK(strstr(out, "if00") == NULL, "no misleading if00 blame: %s", out);
    CHECK(strstr(out, "lowest interface") == NULL,
          "no misleading 'lowest interface' blame: %s", out);
}

static void test_iface_missing_no_ttyusb(void) {
    /* Pinned interface but the device has zero ttyUSB siblings. */
    char out[512];
    diag_portdiag_format_iface_missing("1", "/dev/ttyUSB0", "usb1-2", 4,
                                       NULL, 0, out, sizeof(out));
    CHECK(strstr(out, "usb1-2") != NULL, "usb dev present: %s", out);
    CHECK(strstr(out, "{") == NULL, "no iface set when none present: %s", out);
    CHECK(strstr(out, "diagport=") != NULL, "actionable hint: %s", out);
}

static void test_iface_missing_truncation_safe(void) {
    char tiny[16];
    int ifs[] = { 2, 3, 4 };
    int n = diag_portdiag_format_iface_missing("123456789012345",
             "/dev/ttyUSB2", "usb3-1.4", 5, ifs, 3, tiny, sizeof(tiny));
    CHECK(tiny[sizeof(tiny) - 1] == '\0', "NUL-terminated on truncation");
    CHECK(n > (int)sizeof(tiny), "returns would-be length %d for truncation", n);
    CHECK(strlen(tiny) < sizeof(tiny), "fits buffer: len=%zu", strlen(tiny));
}

static void test_transport_unsupported(void) {
    char out[512];
    diag_portdiag_format_transport("123456789012345", "wwan_mhi",
                                   out, sizeof(out));
    CHECK(strstr(out, "123456789012345") != NULL, "IMEI present: %s", out);
    CHECK(strstr(out, "wwan_mhi") != NULL, "transport named: %s", out);
    CHECK(strstr(out, "diagport=") != NULL, "actionable hint: %s", out);
    /* NULL transport degrades to "?" rather than crashing. */
    diag_portdiag_format_transport("1", NULL, out, sizeof(out));
    CHECK(strstr(out, "?") != NULL, "NULL transport -> '?': %s", out);
}

/* Symmetry with the other two formatters: the transport message must also
 * NUL-terminate and report a would-be length when the buffer is too small. */
static void test_transport_truncation_safe(void) {
    char tiny[32];
    int n = diag_portdiag_format_transport("123456789012345", "qmi_embedded",
                                           tiny, sizeof(tiny));
    CHECK(tiny[sizeof(tiny) - 1] == '\0', "transport NUL-terminated on truncation");
    CHECK(n > (int)sizeof(tiny), "transport returns would-be length %d", n);
    CHECK(strlen(tiny) < sizeof(tiny), "transport fits buffer: len=%zu", strlen(tiny));
}

/* Extreme boundary: a 1-byte buffer must still be safely NUL-terminated and
 * empty. Guards the snprintf-cursor path in format()/iface_missing() where the
 * cursor advances past outsz once the buffer fills. */
static void test_min_buffer_nul_terminates(void) {
    const int ifs[] = {0, 1, 2};
    char one[1];
    int n;

    one[0] = 'X';
    n = diag_portdiag_format("123456789012345", "/dev/ttyUSB2", "usb3-1.4",
                             ifs, 3, one, sizeof(one));
    CHECK(one[0] == '\0', "format: 1-byte buffer NUL-terminated");
    CHECK(n > 0, "format: 1-byte buffer still reports would-be length %d", n);

    one[0] = 'X';
    n = diag_portdiag_format_iface_missing("1", "/dev/ttyUSB0", "usb1-2", 4,
                                           ifs, 3, one, sizeof(one));
    CHECK(one[0] == '\0', "iface_missing: 1-byte buffer NUL-terminated");

    one[0] = 'X';
    diag_portdiag_format_transport("1", "wwan_mhi", one, sizeof(one));
    CHECK(one[0] == '\0', "transport: 1-byte buffer NUL-terminated");
}

int main(void) {
    test_no_usb_device();
    test_ifaces_present();
    test_no_ttyusb_on_device();
    test_single_iface();
    test_truncation_safe();
    test_iface_missing_names_requested();
    test_iface_missing_no_ttyusb();
    test_iface_missing_truncation_safe();
    test_transport_unsupported();
    test_transport_truncation_safe();
    test_min_buffer_nul_terminates();

    if (failures == 0) {
        printf("PASS: all diag_portdiag tests\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d diag_portdiag test check(s)\n", failures);
    return 1;
}
