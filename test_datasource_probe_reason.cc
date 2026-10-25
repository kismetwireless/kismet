/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Framework-free selftest for the probe-decline ownership test.
 *
 * Builds and runs with a bare `c++ -std=c++17` on any host, including one that
 * cannot `./configure` this tree.
 *
 * No `_XOPEN_SOURCE` here, deliberately: defining it hides Darwin's BSD
 * extensions and the framework-free selftests stop building on macOS, which
 * is exactly the host that most needs a framework-free test.
 *
 * What this CANNOT prove: that the reason reaches the operator. That is the
 * server-side wiring in datasourcetracker.cc and needs a built kismet. The
 * decision is the part with logic in it; the wiring is a concatenation.
 */

#include <cstdio>
#include <cstdlib>
#include <string>

#include "datasource_probe_reason.h"

static int failures = 0;

static void check(bool cond, const char *what) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", what);
        failures++;
    }
}

static void check_owns(const char *definition, const char *type, bool expected,
        const char *why) {
    bool got = datasource_reason_is_own_definition(definition, type);
    if (got != expected) {
        fprintf(stderr, "FAIL: '%s' vs driver '%s': expected %s, got %s -- %s\n",
                definition, type, expected ? "OWNED" : "foreign",
                got ? "OWNED" : "foreign", why);
        failures++;
    }
}

int main(void) {
    /* ── the interface split ──────────────────────────────────────────────── */
    check(datasource_definition_interface("celldiag-350123456789012:replay=/x.dlf")
            == "celldiag-350123456789012", "interface stops at the first colon");
    check(datasource_definition_interface("wlan0") == "wlan0",
            "a definition with no options is all interface");
    check(datasource_definition_interface("") == "", "empty stays empty");

    /* ── the cases this is about ───────────────────────────────────────────── */
    check_owns("celldiag", "celldiag", true,
            "the bare-prefix typo: the whole point is that THIS "
            "reason reaches the operator");
    check_owns("celldiag:replay=/x.dlf", "celldiag", true,
            "options must not change ownership");
    check_owns("celldiag-350123456789012", "celldiag", true,
            "the correct form, declined for some other reason");

    /* ── a foreign definition gains no chatter ─────────────────────────────── */
    check_owns("wlan0", "celldiag", false, "the wlan0 case");
    check_owns("wlan0", "linuxwifi", false,
            "even the driver that ends up OWNING wlan0 does not match by "
            "name -- interface names and driver names are different "
            "namespaces, so a matching driver's decline is still suppressed. "
            "This is the deliberate cost of the ownership rule: it protects "
            "the common case (one bad -c) at the price of the rare one (a "
            "driver whose type is unrelated to its interface names)");
    check_owns("celldiag-350123456789012", "linuxwifi", false,
            "capture_linux_wifi writes 'Expected an interface with a standard "
            "network API, skipping' for this -- the exact string that would "
            "have become chatter if every non-empty reason were surfaced");
    check_owns("celldiag-350123456789012", "cellat", false,
            "the two sibling drivers in this tree share a 'cell' prefix and "
            "must NOT claim each other's definitions");
    check_owns("cellat-350123456789012", "cellat", true, "...and each claims its own");

    /* ── the boundary test, which is why this is not a substring match ────── */
    check_owns("celldiagnostics0", "celldiag", false,
            "a plain prefix compare would claim a differently-named driver's "
            "interface; the boundary char must be non-alphanumeric");
    check_owns("celldiag_2", "celldiag", true, "'_' is a legal boundary");
    check_owns("celldiag2", "celldiag", false, "a digit is not a boundary");

    /* ── case ─────────────────────────────────────────────────────────────── */
    check_owns("CellDiag-350123456789012", "celldiag", true,
            "definitions are operator-typed; matching case-exactly would be "
            "a branch that never fires for a capitalised definition");

    /* ── degenerate inputs must not claim ownership ───────────────────────── */
    check_owns("", "celldiag", false, "an empty definition owns nothing");
    check_owns("celldiag", "", false,
            "an empty source type must NOT match everything -- an empty "
            "string is a prefix of every string, so without this guard a "
            "builder with an unset type would claim every definition on the "
            "system and surface its reason for all of them");
    check_owns(":replay=/x.dlf", "", false,
            "the input that actually pins the empty-type guard. The line "
            "above does not: it is rejected by the boundary test ('c' is "
            "alphanumeric), so removing the guard leaves it passing. Here the "
            "interface is empty too, so lengths are equal, the loop runs zero "
            "times, and the equal-length branch returns true -- an unset-type "
            "builder claiming a definition");
    check_owns("cell", "celldiag", false,
            "a definition SHORTER than the driver type is not owned by it");

    if (failures) {
        fprintf(stderr, "\n%d check(s) failed\n", failures);
        return 1;
    }

    printf("test_datasource_probe_reason: all checks passed\n");
    return 0;
}
