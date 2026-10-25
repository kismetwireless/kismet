/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Selftest for device_location_signal_threshold's admission decision.

    This gate decides whether a device gets a location.  It fails by silence,
    and the failure is selective, so a regression presents as a per-device
    quirk with a global cause.

    The test that matters is test_signal_less_packet_is_located.  It is stated
    in the vocabulary of the config file's promise ("packet types which do not
    report a signal level will use all packets") rather than in the vocabulary
    of the implementation, so it cannot be satisfied by re-describing whatever
    the code happens to do.

    Build/run:  make test_device_location_policy && ./test_device_location_policy
*/

#include <cstdio>

#include "device_location_policy.h"

static int g_fails = 0;

static void expect_bool(const char *what, bool got, bool want) {
    if (got != want) {
        printf("FAIL %s: got %s want %s\n", what, got ? "true" : "false",
                want ? "true" : "false");
        g_fails++;
    } else {
        printf("ok   %s\n", what);
    }
}

using device_location_policy::admits_location;

/* The default. A zero threshold disables the feature entirely and every packet
 * carrying a fix is located -- including one whose signal is far below any
 * plausible threshold, which is the arm that proves 0 is not being treated as
 * "0 dBm". */
static void test_threshold_zero_admits_everything() {
    expect_bool("threshold 0, strong signal", admits_location(0, true, -30), true);
    expect_bool("threshold 0, very weak signal", admits_location(0, true, -120), true);
    expect_bool("threshold 0, no signal at all", admits_location(0, false, 0), true);
}

/* The feature doing its job: with a threshold set, a packet whose measured
 * signal is below it does not contribute to the location average. */
static void test_weak_signal_is_excluded() {
    expect_bool("-65 threshold rejects -90", admits_location(-65, true, -90), false);
    expect_bool("-65 threshold rejects -66", admits_location(-65, true, -66), false);
}

static void test_strong_signal_is_admitted() {
    expect_bool("-65 threshold admits -40", admits_location(-65, true, -40), true);
    expect_bool("-65 threshold admits -65 exactly (>=, not >)",
            admits_location(-65, true, -65), true);
}

/* The signal-less exemption, stated as the config file states it.
 *
 * conf/kismet_filter.conf, unchanged since the feature landed:
 *
 *     "Signal is in dBm and applied to all packet types; packet types which do
 *      not report a signal level will use all packets."
 *
 * Requiring `pack_l1info != nullptr` would exclude a packet reporting no
 * signal level.  On phy_cell that covers several 0xB193 versions (v18/v22/v35/
 * v36 have no grounded RSRP scale, so those rows are emitted identity-only by
 * design): every one of them would lose its geo-tag the moment an operator set
 * a threshold, with nothing announcing it.
 *
 * NOTE the signal_dbm argument: it is deliberately a value that WOULD fail the
 * threshold. If a future refactor drops the have_signal check and reads
 * signal_dbm unconditionally, this test fails rather than passing by accident
 * on a zero that happens to clear a negative threshold. */
static void test_signal_less_packet_is_located() {
    expect_bool("no l1info is EXEMPT, not rejected",
            admits_location(-65, false, -120), true);
    expect_bool("no l1info, exempt even at a positive threshold",
            admits_location(10, false, 0), true);
}

/* A positive threshold is not a configuration this feature was designed for,
 * but it is expressible, and it is the only way to distinguish "exempt" from
 * "compared against a zero-initialised signal_dbm" -- because a zeroed
 * signal_dbm clears every NEGATIVE threshold on its own. Without this arm, a
 * refactor that passed 0 through the comparison would still look green above. */
static void test_zero_signal_is_not_a_free_pass() {
    expect_bool("a packet REPORTING 0 dBm is compared, not exempted",
            admits_location(10, true, 0), false);
}

int main(int, char **) {
    printf("== device_location_policy selftest ==\n");

    test_threshold_zero_admits_everything();
    test_weak_signal_is_excluded();
    test_strong_signal_is_admitted();
    test_signal_less_packet_is_located();
    test_zero_signal_is_not_a_free_pass();

    if (g_fails) {
        printf("RESULT: %d check(s) FAILED\n", g_fails);
        return 1;
    }

    printf("RESULT: all checks passed\n");
    return 0;
}
