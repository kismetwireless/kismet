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

    Selftest for the phy_cell decision layer.

    phy_cell.cc is the single funnel every cell observation passes through on
    its way into Kismet's device tree -- both cellat and celldiag, every RAT,
    every DIAG log code. Its failures tend to be silent: a one-line RSRP guard
    can delete the entire DIAG leg for half of 0xB193 traffic while every
    datasource counter looks healthy.

    Scope, stated so a green run is not overread. This covers every decision
    made before the tracker boundary: key derivation, identity level, the RSRP
    keep-vs-populate split, band/channel derivation, device naming, seen_via
    accumulation policy, and PCI<->full-identity promotion key derivation.

    It does not cover update_common_device / signal tracking (needs the packet
    chain), nor that add_related_device actually inserts both directions in the
    tracker -- pci_promotion() decides the two keys; it cannot observe the
    insert. Those still need a device-tree fixture.

    seen_via accumulation and promotion look tracker-bound, but only their
    mutation is; the decision is pure, and writing it down is what exposes the
    cross-RAT collision that test_promotion_keys_agree_across_rats pins.

    Build/run:  make test_phy_cell_decisions && ./test_phy_cell_decisions
*/

#include "config.h"

#include <cstdint>
#include <cstdio>
#include <set>
#include <string>
#include <vector>

#include "nlohmann/json.hpp"
#include "phy_cell_decisions.h"
#ifdef HAVE_HELPER_BAND_TABLE
#include "lte_band.h"
#endif


static int g_fails = 0;

static void expect_str(const char *what, const std::string& got,
        const std::string& want) {
    if (got != want) {
        fprintf(stderr, "  FAIL %s: got \"%s\" want \"%s\"\n",
                what, got.c_str(), want.c_str());
        g_fails++;
    }
}

static void expect_bool(const char *what, bool got, bool want) {
    if (got != want) {
        fprintf(stderr, "  FAIL %s: got %s want %s\n",
                what, got ? "true" : "false", want ? "true" : "false");
        g_fails++;
    }
}

static void expect_int(const char *what, long long got, long long want) {
    if (got != want) {
        fprintf(stderr, "  FAIL %s: got %lld want %lld\n", what, got, want);
        g_fails++;
    }
}

/* ── Identity-only observations: the case that motivated this file ─────────
 *
 * An observation can carry identity and no rsrp key: the decoder emits RSRP
 * only for the measurement-record versions whose scale is grounded, and leaves
 * the key out -- never 0 -- everywhere else. The fixture below is an EG25-G
 * capture in which no observation carries it. Under a guard
 * like
 *
 *     if (!rsrp_j.is_number() || rsrp_j.get<int>() == 0) return false;
 *
 * that is not "some rows dropped": every observation is dropped and no device
 * appears, while the datasource still reports itself running without errors.
 *
 * The fixture has only two distinct cell shapes (PCI 236 and PCI 471, both
 * EARFCN 2300), so it is used for exactly what it proves -- that an
 * identity-only observation still yields a key -- and the spec-derived cases
 * below cover the branches it cannot reach. Real data where it exists, honest
 * synthetics where it does not. */
static void test_identity_only_observations_still_key(void) {
    struct { int64_t pci; uint32_t earfcn; int count; } real[] = {
        {236, 2300, 299},   /* 0xB193 serving, no rsrp */
        {471, 2300,  50},   /* 0xB192 neighbour, no rsrp */
    };

    int total = 0;
    for (const auto& r : real) {
        auto k = cell_decisions::derive_key("LTE", -1, -1, -1, -1, r.pci,
                true, r.earfcn);
        expect_bool("identity-only observation is keyable", k.valid, true);
        expect_bool("observation is partial identity", k.full_identity, false);
        /* EARFCN 2300 is B4 == 2145000 kHz. The key carries the resolved
         * frequency rather than the raw EARFCN -- see
         * test_overlapping_bands_do_not_split_a_cell. */
        expect_str("partial key format", k.key,
                "LTE_pci" + std::to_string(r.pci) + "_f2145000");

        /* And the keep-vs-populate split: no usable RSRP, yet the
         * observation is still valid. The two answers must differ. */
        expect_bool("rsrp absent", cell_decisions::have_usable_rsrp(false, 0),
                false);
        total += r.count;
    }
    expect_int("fixture size", total, 349);

    if (g_fails == 0)
        printf("  ok   349 identity-only DIAG observations all key\n");
}

/* Key derivation across every branch. The key becomes the device MAC, so the
 * literal format strings are the contract -- a change forks the device tree
 * silently. */
static void test_key_derivation(void) {
    int before = g_fails;

    /* Full identity: mcc + mnc + cid. */
    auto full = cell_decisions::derive_key("LTE", 310, 260, 6699, 11259361,
            381, true, 5035);
    expect_bool("full identity flagged", full.full_identity, true);
    expect_str("full key format", full.key, "310260_6699_11259361");

    /* Not "262001_5_7": every MNC zero-padded to three digits would be wrong.
     * WiGLE writes MCC 262 / MNC 01 as `26201_...` (the MNC as broadcast), so
     * the padded form names a different operator to WiGLE's importer and to cell_op= in its search API. A numeric
     * MNC arrives with its digit count already destroyed, so it is
     * reconstructed by plmn_from_numbers()'s 2-vs-3 rule; MCC 262 is not a
     * 3-digit-MNC block, hence two digits.
     *
     * Padding is still load-bearing within a digit count: "26201" must not
     * become "2621", or it collides with MCC 262 / MNC 21. */
    auto pad = cell_decisions::derive_key("LTE", 262, 1, 5, 7, -1, false, 0);
    expect_str("numeric mnc rendered at its reconstructed width", pad.key,
            "26201_5_7");

    /* MNC 0 is a real value. The bounds are deliberately asymmetric
     * (mcc > 0, mnc >= 0); making them uniform deletes every observation from
     * an MNC-00 network. */
    auto mnc0 = cell_decisions::derive_key("LTE", 262, 0, 5, 7, -1, false, 0);
    expect_bool("mnc 0 is a valid full identity", mnc0.full_identity, true);
    expect_str("mnc 0 key", mnc0.key, "26200_5_7");

    /* An absent TAC encodes as 0 rather than being omitted. Pinned as existing
     * behaviour: it means the same cell seen with and without a TAC produces two
     * devices, which is a real wart -- but changing it must be deliberate. */
    auto notac = cell_decisions::derive_key("LTE", 310, 260, -1, 11259361,
            -1, false, 0);
    expect_str("absent tac encodes as 0", notac.key, "310260_0_11259361");

    /* Full identity WINS over partial when both are available -- otherwise a
     * tower would fork between its full and partial keys depending on which
     * fields a given source happened to carry. */
    auto both = cell_decisions::derive_key("LTE", 310, 260, 6699, 11259361,
            381, true, 5035);
    expect_str("full identity takes priority over pci/earfcn", both.key,
            "310260_6699_11259361");

    /* Partial identity, and PCI 0 is valid (pci >= 0, not > 0). */
    auto pci0 = cell_decisions::derive_key("NR", -1, -1, -1, -1, 0, true, 658080);
    expect_bool("pci 0 is a valid partial identity", pci0.valid, true);
    /* NR-ARFCN 658080 -> 3000000 + (658080-600000)*15 == 3871200 kHz. */
    expect_str("nr partial key carries the rat", pci0.key, "NR_pci0_f3871200");

    /* Rejects: neither identity level satisfiable. */
    expect_bool("no identity at all is rejected",
            cell_decisions::derive_key("LTE", -1, -1, -1, -1, -1, false, 0).valid,
            false);
    expect_bool("pci without earfcn is rejected",
            cell_decisions::derive_key("LTE", -1, -1, -1, -1, 236, false, 0).valid,
            false);
    expect_bool("cid without mcc/mnc falls through to partial-or-reject",
            cell_decisions::derive_key("LTE", -1, -1, 5, 11259361, -1, false, 0).valid,
            false);
    /* cid == 0 is not a cell identity, and neither is mcc == 0. */
    expect_bool("cid 0 is not a full identity",
            cell_decisions::derive_key("LTE", 310, 260, 5, 0, -1, false, 0).full_identity,
            false);
    expect_bool("mcc 0 is not a full identity",
            cell_decisions::derive_key("LTE", 0, 260, 5, 7, -1, false, 0).full_identity,
            false);

    if (g_fails == before)
        printf("  ok   key derivation (full/partial/reject, padding, mnc 0, pci 0)\n");
}

/* The capture helper sends strings; both readers must accept them.
 *
 * The capture helper's observation JSON carries mcc/mnc as digit strings by
 * design, so the MNC's digit count survives the wire. A reader that tests is_number(), or
 * uses j.value("mcc", (uint64_t) 0), silently scores a string-valued key as
 * absent: every DIAG-sourced SIB1 identity falls to "no MCC", the PHY demotes
 * it to a PCI-only partial device, and the exporter bins it as
 * skipped_fields.
 *
 * The failure is silent. The visible symptom downstream is an empty WiGLE CSV
 * (the live logger writes only identity_level == "full"), which reads as
 * "nothing was in range" rather than as an error.
 *
 * The rule lives in one function, which is why this test can reach it at
 * all -- it is in the decision layer, not in the tracker-linked PHY. */
static void test_json_plmn_accepts_strings_and_numbers(void) {
    int before = g_fails;

    /* The DIAG leg's actual shape. */
    auto diag = cell_decisions::plmn_from_json(
            nlohmann::json::parse(R"({"mcc": "311", "mnc": "480"})"));
    expect_bool("string mcc/mnc are accepted", diag.present, true);
    expect_str("string plmn round-trips", diag.joined(), "311480");

    /* The core property, as one assertion: a string-valued identity must build
     * a full key, not fall through to the partial form with mcc = -1. */
    auto k = cell_decisions::derive_key("NR", diag, 1714944, 7025029432LL,
            596, true, 521310);
    expect_bool("a string-valued SIB1 identity is FULL, not partial",
            k.full_identity, true);
    expect_str("string identity keys on the plmn", k.key,
            "311480_1714944_7025029432");

    /* The AT leg's shape -- numbers -- still works. */
    auto at = cell_decisions::plmn_from_json(
            nlohmann::json::parse(R"({"mcc": 310, "mnc": 260})"));
    expect_bool("numeric mcc/mnc still accepted", at.present, true);
    expect_str("numeric plmn reconstructs", at.joined(), "310260");

    /* Mixed forms take the lossless half rather than dropping both. */
    expect_str("string mcc + numeric mnc",
            cell_decisions::plmn_from_json(
                nlohmann::json::parse(R"({"mcc": "234", "mnc": 15})")).joined(),
            "23415");
    expect_str("numeric mcc + string mnc keeps the broadcast digits",
            cell_decisions::plmn_from_json(
                nlohmann::json::parse(R"({"mcc": 234, "mnc": "15"})")).joined(),
            "23415");

    /* A leading zero is the case a number cannot carry: "04" arrives from
     * SIB1 as two digits and must stay two, where the numeric path would have
     * to guess. */
    expect_str("leading-zero mnc survives as a string",
            cell_decisions::plmn_from_json(
                nlohmann::json::parse(R"({"mcc": "310", "mnc": "04"})")).joined(),
            "31004");

    /* Absent / null / junk stays absent -- the demotion is correct here. */
    expect_bool("no mcc/mnc keys at all",
            cell_decisions::plmn_from_json(
                nlohmann::json::parse(R"({"pci": 596})")).present, false);
    expect_bool("null mcc",
            cell_decisions::plmn_from_json(
                nlohmann::json::parse(R"({"mcc": null, "mnc": "480"})")).present,
            false);
    expect_bool("non-numeric string mcc",
            cell_decisions::plmn_from_json(
                nlohmann::json::parse(R"({"mcc": "n/a", "mnc": "480"})")).present,
            false);

    if (g_fails == before)
        printf("  ok   json plmn accepts strings AND numbers\n");
}

/* The PLMN carries as-broadcast digits, and the key is WiGLE's.
 *
 * Why this is not cosmetic: WiGLE's cell key is MCC+MNC_xAC_CELLID with the
 * MNC exactly as the network broadcast it -- 2 or 3 digits
 * (GsmOperator.getOperatorKeyString(), CellIdentity.getMncString()). Vodafone
 * UK broadcasts MNC "15" and is `23415_...` on WiGLE; a key that zero-pads
 * every MNC to three emits `234015_...`. That is a different network as far
 * as WiGLE, its /api/v2/cell/search?cell_op=<MCCMNC> endpoint
 * and its /api/v3/detail/cell/{type}/{operator}/... path are concerned -- for
 * every 2-digit-MNC PLMN, which is most of the world outside North America.
 *
 * The digits are data, not formatting: MCC 262 MNC "01" (Telekom DE) and
 * MCC 262 MNC "001" are, in principle, distinct assignments. Only the
 * broadcast string knows which one is on the air, so the contract carries a
 * string end to end (the JSON test above is the same fact, seen from the
 * JSON side). */
static void test_plmn_digits_are_as_broadcast(void) {
    int before = g_fails;

    /* Digits that ARRIVED as digits are preserved verbatim -- this is the
     * DIAG/SIB1 path and the only lossless one. */
    auto de = cell_decisions::plmn_from_digits("262", "01");
    expect_bool("2-digit broadcast mnc is present", de.present, true);
    expect_str("2-digit broadcast mnc kept at 2", de.joined(), "26201");

    auto us = cell_decisions::plmn_from_digits("311", "480");
    expect_str("3-digit broadcast mnc kept at 3", us.joined(), "311480");

    /* These two are different PLMNs and must not collapse into each other.
     * A zero-padding normalisation makes them the same string, which is the
     * entire defect. */
    expect_bool("mnc '01' and mnc '001' are distinct plmns",
            cell_decisions::plmn_from_digits("262", "01").joined() ==
            cell_decisions::plmn_from_digits("262", "001").joined(),
            false);

    /* MNC "00" is a real network (the cellat_cpsi parse_plmn comment names
     * 460-00), and it must survive as two zeroes, not as an absent value. */
    auto mnc00 = cell_decisions::plmn_from_digits("460", "00");
    expect_bool("mnc 00 is present", mnc00.present, true);
    expect_str("mnc 00 keeps both digits", mnc00.joined(), "46000");

    /* A short MCC is zero-padded -- MCC is fixed at 3 digits by 3GPP, so a
     * "31" can only be a dropped leading zero, never a 2-digit country. */
    expect_str("short mcc is left-padded to 3",
            cell_decisions::plmn_from_digits("62", "30").joined(), "06230");

    /* Junk is rejected rather than silently keyed. */
    expect_bool("non-digit mcc rejected",
            cell_decisions::plmn_from_digits("3a1", "480").present, false);
    expect_bool("empty mnc rejected",
            cell_decisions::plmn_from_digits("310", "").present, false);
    expect_bool("over-long mnc rejected",
            cell_decisions::plmn_from_digits("310", "4800").present, false);

    if (g_fails == before)
        printf("  ok   plmn digits are as-broadcast\n");
}

/* The lossy fallback, for legs that destroyed the digits before we saw them.
 *
 * capture_cell_at's parse_plmn() parses "460-00" and immediately parse_int()s
 * both halves (cellat_cpsi.inc:156), so the AT leg hands us the NUMBER 0 and
 * the digit count is already gone. Reconstructing it needs WiGLE's own rule:
 * determineMnc() decides 2 vs 3 from a recognised-MNC table keyed on the MCC.
 * We implement the MCC-block form of that table.
 *
 * This is a fallback, not the contract. Anything that can carry the string
 * must carry the string; a reconstructed digit count is a guess that is wrong
 * for every 3-digit-MNC network outside the listed blocks. */
static void test_numeric_mnc_fallback_follows_wigle_rule(void) {
    int before = g_fails;

    /* North America (MCC 310-316, 302, 334) broadcasts 3-digit MNCs. */
    expect_str("us mnc reconstructs to 3 digits",
            cell_decisions::plmn_from_numbers(310, 260).joined(), "310260");
    expect_str("us low mnc still 3 digits",
            cell_decisions::plmn_from_numbers(311, 40).joined(), "311040");
    expect_str("canada mnc 3 digits",
            cell_decisions::plmn_from_numbers(302, 720).joined(), "302720");

    /* Everywhere else defaults to 2 -- Germany 262/01, not 262/001. */
    expect_str("germany mnc reconstructs to 2 digits",
            cell_decisions::plmn_from_numbers(262, 1).joined(), "26201");
    expect_str("uk vodafone matches wigle's 23415",
            cell_decisions::plmn_from_numbers(234, 15).joined(), "23415");

    /* An MNC that needs 3 digits to be written at all gets 3, whatever the
     * block says -- truncating 262/120 to "20" would be a wrong network. */
    expect_str("mnc >= 100 is never truncated to 2",
            cell_decisions::plmn_from_numbers(262, 120).joined(), "262120");

    /* Absent / invalid stays absent. */
    expect_bool("mcc 0 is not a plmn",
            cell_decisions::plmn_from_numbers(0, 260).present, false);
    expect_bool("negative mnc is not a plmn",
            cell_decisions::plmn_from_numbers(310, -1).present, false);
    expect_bool("mnc 0 IS a plmn",
            cell_decisions::plmn_from_numbers(460, 0).present, true);

    if (g_fails == before)
        printf("  ok   numeric mnc fallback follows wigle's 2-vs-3 rule\n");
}

/* The key built from a plmn_t, and the legacy numeric overload agreeing with it. */
static void test_key_uses_as_broadcast_plmn(void) {
    int before = g_fails;

    auto k = cell_decisions::derive_key("LTE",
            cell_decisions::plmn_from_digits("234", "15"), 5, 7, -1, false, 0);
    expect_bool("string-plmn full identity flagged", k.full_identity, true);
    expect_str("key is wigle's MCCMNC_xAC_CID, unpadded", k.key, "23415_5_7");

    /* The two entry points must produce the SAME key for the same network, or
     * a cell forks by which leg observed it. */
    expect_str("numeric overload agrees with the string form",
            cell_decisions::derive_key("LTE", 310, 260, 6699, 11259361,
                    381, true, 5035).key,
            cell_decisions::derive_key("LTE",
                    cell_decisions::plmn_from_digits("310", "260"),
                    6699, 11259361, 381, true, 5035).key);

    /* An unparseable plmn falls through to the partial branch rather than
     * keying on garbage -- the partial demotion, but only for real garbage. */
    auto bad = cell_decisions::derive_key("LTE",
            cell_decisions::plmn_from_digits("", ""), 5, 7, 100, true, 1850);
    expect_bool("absent plmn falls through to partial", bad.full_identity, false);
    expect_bool("absent plmn partial is still valid", bad.valid, true);

    if (g_fails == before)
        printf("  ok   key uses as-broadcast plmn\n");
}

/* LTE ECI split -- the derived fields engineers always want.
 *
 * LTE ECI is 28 bits: the low 8 are the sector/cell-identity and the high 20
 * the eNB-ID (3GPP TS 36.413 ECGI). Splitting it is one shift, and every
 * engineer reading a cell list does it by hand otherwise.
 *
 * NR is deliberately not split. The NCI is 36 bits and the gNB-ID length is
 * operator-configured (22-32 bits, broadcast in SIB1's cellIdentity context,
 * not derivable from the NCI alone). Guessing a split here would print a
 * confident wrong number, which is worse than printing none. */
static void test_lte_eci_split(void) {
    int before = g_fails;

    expect_int("enb id is the high 20 bits",
            cell_decisions::lte_enb_id(11259361), 11259361 >> 8);
    expect_int("sector is the low 8 bits",
            cell_decisions::lte_sector(11259361), 11259361 & 0xff);
    /* A sector 0 is real; the split must not report it as absent. */
    expect_int("sector 0 survives the split",
            cell_decisions::lte_sector(11259361 & ~0xffLL), 0);

    if (g_fails == before)
        printf("  ok   lte eci -> enb_id/sector split\n");
}

/* The partial key must not partition a cell by band numbering.
 *
 * LTE band 4 is a subset of band 66. The same 2145 MHz carrier is addressable
 * as EARFCN 2300 (B4) or EARFCN 66786 (B66), and vendors differ on which they
 * report: Quectel's AT+QENG says B4/2300, Telit's AT#MONI says B66/66786.
 * Keying on the raw EARFCN would make two modems side by side track one
 * tower as two devices, splitting observation_count, min/max RSRP and the
 * seen_via provenance across both halves. For example, an EG25-G and an
 * LM960A18 on T-Mobile 310260 report:
 *
 *   LM960A18   LTE PCI 242 B66    raw key would be LTE_pci242_66786
 *   EG25-G     LTE PCI 242 B4     raw key would be LTE_pci242_2300
 *
 * The frequency math resolves both to 2145000 kHz, so the key carries the
 * resolved frequency.
 */
static void test_overlapping_bands_do_not_split_a_cell(void) {
    int before = g_fails;

    /* The observation above. */
    auto b4 = cell_decisions::derive_key("LTE", -1, -1, -1, -1, 242, true, 2300);
    auto b66 = cell_decisions::derive_key("LTE", -1, -1, -1, -1, 242, true, 66786);
    expect_str("B4 EARFCN 2300 keys on frequency", b4.key, "LTE_pci242_f2145000");
    expect_str("B66 EARFCN 66786 keys on the SAME frequency", b66.key,
            "LTE_pci242_f2145000");
    expect_str("the two vendors' spellings produce ONE key", b4.key, b66.key);

    /* A second cell, so the merge is not an artifact of one PCI. */
    expect_str("PCI 3 merges too",
            cell_decisions::derive_key("LTE", -1, -1, -1, -1, 3, true, 2300).key,
            cell_decisions::derive_key("LTE", -1, -1, -1, -1, 3, true, 66786).key);

    /* The merge must be frequency-driven, not "any two EARFCNs merge". A
     * different carrier on the same PCI stays a different device -- otherwise
     * the fix trades a split for a conflation, which is strictly worse. */
    auto other = cell_decisions::derive_key("LTE", -1, -1, -1, -1, 242, true, 2400);
    expect_bool("a different carrier on the same PCI stays distinct",
            other.key != b4.key, true);

    /* B2/B25 and B12/B17 are the other common overlapping pairs in North
     * America. B2 EARFCN 900 and B25 EARFCN 8340
     * are both 1960.0 MHz; B12 EARFCN 5120 and B17 EARFCN 5790 are both
     * 740.0 MHz.
     *
     * EARFCN 8000 is in B24 (7700..8039, 1555 MHz), not B25; a one-row table
     * shift (B24's range with B25's F_DL_low) would make it look like B2's
     * carrier. The second assert keeps 8000 out of B2's carrier. */
    expect_str("B2/B25 same carrier merges",
            cell_decisions::derive_key("LTE", -1, -1, -1, -1, 7, true, 900).key,
            cell_decisions::derive_key("LTE", -1, -1, -1, -1, 7, true, 8340).key);
    expect_bool("B24 EARFCN 8000 is NOT B2's carrier",
            cell_decisions::derive_key("LTE", -1, -1, -1, -1, 7, true, 900).key !=
                cell_decisions::derive_key("LTE", -1, -1, -1, -1, 7, true, 8000).key,
            true);
    expect_str("B12/B17 same carrier merges",
            cell_decisions::derive_key("LTE", -1, -1, -1, -1, 268, true, 5120).key,
            cell_decisions::derive_key("LTE", -1, -1, -1, -1, 268, true, 5790).key);

    /* NR keys the same way, and cannot collide with an LTE key at the same
     * frequency because the RAT prefix is still first. */
    /* A real NR observation: NR-ARFCN 174770 is in the 5 kHz range, so
     * 174770 * 5 == 873850 kHz. */
    auto nr = cell_decisions::derive_key("NR", -1, -1, -1, -1, 43, true, 174770);
    expect_str("nr partial key carries rat + frequency", nr.key,
            "NR_pci43_f873850");

    /* An ARFCN the frequency table cannot convert must not key as
     * frequency 0 -- that would merge every unconvertible ARFCN on a PCI into
     * one device, the band-split defect pointed the other way. Fall back to the raw ARFCN, in a shape that cannot be
     * confused with a frequency key. */
    auto gap = cell_decisions::derive_key("LTE", -1, -1, -1, -1, 242, true, 4999);
    expect_str("an unconvertible earfcn falls back to the raw value", gap.key,
            "LTE_pci242_e4999");
    auto gap2 = cell_decisions::derive_key("LTE", -1, -1, -1, -1, 242, true, 5000);
    expect_bool("two DIFFERENT unconvertible earfcns stay distinct",
            gap.key != gap2.key, true);

    if (g_fails == before)
        printf("  ok   overlapping bands merge on resolved frequency\n");
}

/* Prerequisite for frequency keys -- the LTE frequency table itself.
 *
 * Keying on frequency is only safe if the frequency is right. Bands 17, 18
 * and 19 are easy to get off by one row (each carrying the next row's
 * F_DL_low):
 *
 *   band | off-by-one | 3GPP TS 36.101 Table 5.7.3-1
 *     17 |      860.0 | 734.0
 *     18 |      875.0 | 860.0
 *     19 |      890.0 | 875.0
 *
 * With frequency keys that is a false merge, not a display error: under the
 * shifted table, B17 EARFCN 5820 computes to 869.0 MHz, which is exactly B5
 * EARFCN 2400's real frequency -- so two unrelated cells sharing a PCI would
 * collapse into one device.
 */
static void test_lte_frequency_table_band_edges(void) {
    int before = g_fails;

    /* The three rows, at their lowest EARFCN (== F_DL_low). */
    expect_int("band 17 F_DL_low is 734 MHz",
            cell_decisions::arfcn_to_khz("LTE", 5730), 734000);
    expect_int("band 18 F_DL_low is 860 MHz",
            cell_decisions::arfcn_to_khz("LTE", 5850), 860000);
    expect_int("band 19 F_DL_low is 875 MHz",
            cell_decisions::arfcn_to_khz("LTE", 6000), 875000);

    /* The collision a shifted table would create with frequency-based keys:
     * B17 5820 and B5 2400 must not be the same frequency. */
    expect_int("band 17 EARFCN 5820 is 743 MHz, not 869",
            cell_decisions::arfcn_to_khz("LTE", 5820), 743000);
    expect_int("band 5 EARFCN 2400 is 869 MHz",
            cell_decisions::arfcn_to_khz("LTE", 2400), 869000);
    expect_bool("B17 and B5 no longer collide",
            cell_decisions::arfcn_to_khz("LTE", 5820) !=
                cell_decisions::arfcn_to_khz("LTE", 2400), true);

    /* Adjacent rows, to pin that the shift has not moved one row further
     * along. */
    expect_int("band 14 unchanged", cell_decisions::arfcn_to_khz("LTE", 5280), 758000);
    expect_int("band 20 unchanged", cell_decisions::arfcn_to_khz("LTE", 6150), 791000);

    /* The overlap pairs, as frequencies rather than as keys. */
    expect_int("B4 EARFCN 2300 == 2145 MHz",
            cell_decisions::arfcn_to_khz("LTE", 2300), 2145000);
    expect_int("B66 EARFCN 66786 == 2145 MHz",
            cell_decisions::arfcn_to_khz("LTE", 66786), 2145000);

    /* An EARFCN in a table gap converts to 0, which is what drives the raw
     * fallback in derive_key. */
    expect_int("an earfcn in a table gap converts to 0",
            cell_decisions::arfcn_to_khz("LTE", 4999), 0);

    if (g_fails == before)
        printf("  ok   LTE frequency table (bands 17/18/19)\n");
}

/* The RSRP policy, isolated. This function must answer ONE question -- populate
 * signal or not -- and never be read as a keep/drop test. */
static void test_rsrp_policy(void) {
    int before = g_fails;

    expect_bool("a real dBm is usable", cell_decisions::have_usable_rsrp(true, -95),
            true);
    expect_bool("absent rsrp is not usable",
            cell_decisions::have_usable_rsrp(false, 0), false);
    /* 0 dBm is not a plausible cellular RSRP; the AT paths use it as a
     * not-reported sentinel, so it is treated as absent. */
    expect_bool("rsrp 0 is treated as absent",
            cell_decisions::have_usable_rsrp(true, 0), false);
    /* A non-number field that happens to hold 0 must not read as present. */
    expect_bool("non-number rsrp with a stale value is absent",
            cell_decisions::have_usable_rsrp(false, -95), false);
    /* Positive values are implausible but are NOT silently dropped -- that is a
     * decode bug to surface upstream, not something this layer should hide. */
    expect_bool("an implausible positive rsrp is still 'present'",
            cell_decisions::have_usable_rsrp(true, 12), true);

    if (g_fails == before)
        printf("  ok   rsrp policy (populate-vs-drop kept separate)\n");
}

/* Bands 23..32 are prone to the same off-by-one (each row carrying the next
 * band's F_DL_low and label). Each band at its lowest EARFCN must read its own
 * F_DL_low. */
static void test_lte_frequency_table_b23_to_b32(void) {
    int before = g_fails;
    expect_int("band 23 F_DL_low 2180", cell_decisions::arfcn_to_khz("LTE", 7500), 2180000);
    expect_int("band 24 F_DL_low 1525", cell_decisions::arfcn_to_khz("LTE", 7700), 1525000);
    expect_int("band 25 F_DL_low 1930", cell_decisions::arfcn_to_khz("LTE", 8040), 1930000);
    expect_int("band 26 F_DL_low 859",  cell_decisions::arfcn_to_khz("LTE", 8690), 859000);
    expect_int("band 27 F_DL_low 852",  cell_decisions::arfcn_to_khz("LTE", 9040), 852000);
    expect_int("band 28 F_DL_low 758",  cell_decisions::arfcn_to_khz("LTE", 9210), 758000);
    expect_int("band 29 F_DL_low 717",  cell_decisions::arfcn_to_khz("LTE", 9660), 717000);
    expect_int("band 30 F_DL_low 2350", cell_decisions::arfcn_to_khz("LTE", 9770), 2350000);
    expect_int("band 31 F_DL_low 462.5", cell_decisions::arfcn_to_khz("LTE", 9870), 462500);
    expect_int("band 32 F_DL_low 1452", cell_decisions::arfcn_to_khz("LTE", 9920), 1452000);
    /* The merge a shift would make possible: B28 EARFCN 9330 (770 MHz) must
     * not compute into B13's spectrum; shifted, it reads 729 MHz ==
     * B12 EARFCN 5010. */
    expect_bool("B28 9330 no longer lands on B12 5010",
            cell_decisions::arfcn_to_khz("LTE", 9330) !=
                cell_decisions::arfcn_to_khz("LTE", 5010), true);
    /* Neighbours of the block, so a fix cannot shift it further. */
    expect_int("band 22 unchanged", cell_decisions::arfcn_to_khz("LTE", 6600), 3510000);
    expect_int("band 33 unchanged", cell_decisions::arfcn_to_khz("LTE", 36000), 1900000);
    if (g_fails == before)
        printf("  ok   lte frequency table, bands 23..32\n");
}

/* The server's earfcn_to_band and the helper's lte_band::earfcn_to_band label
 * the same cell and must agree. Sweep the whole domain so no row can drift.
 * Built only when the tree has the helper's table (see Makefile.in). */
#ifdef HAVE_HELPER_BAND_TABLE
static void test_earfcn_to_band_matches_the_helper_table(void) {
    int before = g_fails;
    int diffs = 0;
    for (uint32_t e = 0; e <= 80000; e++) {
        const int s = cell_decisions::earfcn_to_band(e);
        const int h = lte_band::earfcn_to_band(e);
        if (s != h && diffs++ < 5)
            printf("  FAIL earfcn %u: server band %d, helper band %d\n", e, s, h);
    }
    if (diffs) {
        printf("  FAIL %d EARFCN(s) where server and helper disagree\n", diffs);
        g_fails++;
    }
    expect_int("earfcn 9660 -> band 29", cell_decisions::earfcn_to_band(9660), 29);
    expect_int("earfcn 9820 -> band 30", cell_decisions::earfcn_to_band(9820), 30);
    if (g_fails == before)
        printf("  ok   earfcn_to_band == helper lte_band over 0..80000\n");
}
#else
static void test_earfcn_to_band_matches_the_helper_table(void) {
    printf("  skip earfcn_to_band vs helper lte_band: no diagspec band table in this tree\n");
}
#endif

/* TS 36.101 v20.0.0 Table 5.7.3-1, checked row for row. Band 26 runs to 9039;
 * 70546..70655 is B87, B88, B103 (there is no LTE band 86); and B54/B106/B111
 * need rows, or their cells key on the raw EARFCN. Each band's edges must read
 * its own label and its own F_DL_low. */
static void test_lte_frequency_table_b54_to_b111(void) {
    int before = g_fails;
    expect_int("earfcn 8940 -> band 26", cell_decisions::earfcn_to_band(8940), 26);
    expect_int("earfcn 9039 -> band 26", cell_decisions::earfcn_to_band(9039), 26);
    expect_int("earfcn 9039 -> 893.9 MHz",
            (long long)cell_decisions::arfcn_to_khz("LTE", 9039), 893900);
    const struct { uint32_t lo, hi; int band; long long fdl_khz; } rows[] = {
        {60255, 60304,  54, 1670000},
        {70546, 70595,  87,  420000},
        {70596, 70645,  88,  422000},
        {70646, 70655, 103,  757000},
        {70656, 70705, 106,  935000},
        {73386, 73485, 111, 1820000},
    };
    for (const auto& r : rows) {
        char name[64];
        snprintf(name, sizeof(name), "band %d lower edge", r.band);
        expect_int(name, cell_decisions::earfcn_to_band(r.lo), r.band);
        snprintf(name, sizeof(name), "band %d upper edge", r.band);
        expect_int(name, cell_decisions::earfcn_to_band(r.hi), r.band);
        snprintf(name, sizeof(name), "band %d F_DL_low", r.band);
        expect_int(name, (long long)cell_decisions::arfcn_to_khz("LTE", r.lo), r.fdl_khz);
    }
    for (uint32_t e = 0; e <= 80000; e++)
        if (cell_decisions::earfcn_to_band(e) == 86) {
            printf("  FAIL earfcn %u labelled band 86, which LTE does not have\n", e);
            g_fails++;
            break;
        }
    expect_int("past the last row", cell_decisions::earfcn_to_band(73486), 0);
    if (g_fails == before)
        printf("  ok   lte bands 54..111 per TS 36.101 v20.0.0\n");
}

static void test_band_and_channel(void) {
    int before = g_fails;

    expect_int("earfcn 2300 -> band 4", cell_decisions::earfcn_to_band(2300), 4);
    expect_int("earfcn 5035 -> band 12", cell_decisions::earfcn_to_band(5035), 12);
    expect_int("earfcn 5230 -> band 13", cell_decisions::earfcn_to_band(5230), 13);
    expect_int("earfcn 66536 -> band 66", cell_decisions::earfcn_to_band(66536), 66);
    /* Band boundaries: off-by-one here silently mislabels every cell at the edge
     * of a band, which reads as a real deployment rather than a bug. */
    expect_int("band 1 lower edge", cell_decisions::earfcn_to_band(0), 1);
    expect_int("band 1 upper edge", cell_decisions::earfcn_to_band(599), 1);
    expect_int("band 2 lower edge", cell_decisions::earfcn_to_band(600), 2);
    /* Gaps in the table are real (36.101 leaves EARFCN ranges unassigned) and
     * must report 0, not the neighbouring band. */
    expect_int("an unassigned earfcn has no band",
            cell_decisions::earfcn_to_band(5000), 0);

    expect_str("lte channel from a derived band",
            cell_decisions::channel_string("LTE", 0, true, 2300), "LTE B4");
    expect_str("an explicit band wins over derivation",
            cell_decisions::channel_string("LTE", 71, true, 2300), "LTE B71");
    /* NR must not go through the LTE band table. An NR-ARFCN lands in
     * whichever LTE range contains the integer and would report a fabricated
     * band -- worse than reporting none. */
    expect_str("nr without an explicit band yields no channel",
            cell_decisions::channel_string("NR", 0, true, 2300), "");
    expect_str("nr with an explicit band is fine",
            cell_decisions::channel_string("NR", 78, true, 658080), "NR B78");
    expect_str("no earfcn yields no channel",
            cell_decisions::channel_string("LTE", 0, false, 0), "");

    /* Frequency conversion, per RAT. */
    expect_int("lte earfcn 2300 -> kHz",
            (long long)cell_decisions::arfcn_to_khz("LTE", 2300), 2145000);
    expect_int("nr arfcn low range -> kHz",
            (long long)cell_decisions::arfcn_to_khz("NR", 100000), 500000);
    expect_int("an out-of-range nr arfcn converts to 0",
            (long long)cell_decisions::arfcn_to_khz("NR", 4000000), 0);
    expect_int("an unknown rat converts to 0",
            (long long)cell_decisions::arfcn_to_khz("GSM", 2300), 0);

    if (g_fails == before)
        printf("  ok   band/channel/frequency (edges, gaps, NR not via LTE table)\n");
}

static void test_device_naming(void) {
    int before = g_fails;

    auto full = cell_decisions::derive_key("LTE", 310, 260, 6699, 11259361,
            381, true, 5035);
    expect_str("full-identity name is rat + key",
            cell_decisions::device_name(full, "LTE", 381, 5035, 12),
            "LTE 310260_6699_11259361");

    auto partial = cell_decisions::derive_key("LTE", -1, -1, -1, -1, 236,
            true, 2300);
    expect_str("partial name with a band",
            cell_decisions::device_name(partial, "LTE", 236, 2300, 4),
            "LTE PCI 236 B4");
    /* No band -> fall back to the EARFCN rather than printing "B0", which would
     * read as a real band number. */
    expect_str("partial name without a band falls back to earfcn",
            cell_decisions::device_name(partial, "LTE", 236, 2300, 0),
            "LTE PCI 236 EARFCN 2300");

    if (g_fails == before)
        printf("  ok   device naming (full, partial+band, partial+earfcn)\n");
}

/* ---------------------------------------------------------------------------
 * seen_via accumulation
 * ------------------------------------------------------------------------ */

static std::string join(const std::vector<std::string>& v) {
    std::string out;
    for (size_t i = 0; i < v.size(); i++) {
        if (i) out += ",";
        out += v[i];
    }
    return out;
}

static void test_prov_field_ordering(void) {
    int before = g_fails;

    /* The output order follows the canonical list, not the caller's. Two
     * sources reporting the same fields must produce byte-identical lists, or a
     * consumer diffing them sees a change that is really JSON key order. */
    std::vector<std::string> shuffled = {"rsrp", "mcc", "duplex", "rat"};
    expect_str("contributed fields are canonically ordered",
            join(cell_decisions::contributed_fields(shuffled)),
            "rat,mcc,rsrp,duplex");

    /* A source cannot advertise a field the schema does not define. */
    std::vector<std::string> unknown = {"mcc", "not_a_field", "rsrp"};
    expect_str("unknown keys are dropped",
            join(cell_decisions::contributed_fields(unknown)), "mcc,rsrp");

    expect_str("no present keys -> empty",
            join(cell_decisions::contributed_fields({})), "");

    if (g_fails == before)
        printf("  ok   prov field ordering + filtering\n");
}

static void test_seen_via_is_a_union_not_a_replace(void) {
    int before = g_fails;

    /* The core provenance property, in one assertion. A tower seen by both
     * capture pipes: `at` supplies identity, `diag` supplies signal. If this
     * were an assignment rather than a union, each observation would erase the
     * other pipe's contribution and the last writer would appear to be the sole
     * source of everything -- with a plausible-looking field list either way. */
    std::vector<std::string> from_at =
            cell_decisions::contributed_fields({"rat", "mcc", "mnc", "tac", "cell_id"});
    std::vector<std::string> from_diag =
            cell_decisions::contributed_fields({"rat", "pci", "earfcn", "rsrp", "rsrq"});

    std::vector<std::string> acc = from_at;
    cell_decisions::merge_prov_fields(acc, from_diag);

    expect_str("at + diag accumulate, existing order preserved",
            join(acc), "rat,mcc,mnc,tac,cell_id,pci,earfcn,rsrp,rsrq");

    /* Re-merging the same source must be idempotent -- an observation arriving
     * twice must not grow the list, or `prov_fields` becomes an observation
     * counter wearing a field list's name. */
    size_t len = acc.size();
    cell_decisions::merge_prov_fields(acc, from_diag);
    expect_bool("re-merging the same source is idempotent", acc.size() == len, true);

    /* Merging into an empty accumulator is the first-observation case. */
    std::vector<std::string> fresh;
    cell_decisions::merge_prov_fields(fresh, from_at);
    expect_str("first observation seeds the list", join(fresh),
            "rat,mcc,mnc,tac,cell_id");

    if (g_fails == before)
        printf("  ok   seen_via field union (at + diag, idempotent, seed)\n");
}

static void test_absent_origin_does_not_blank_a_known_one(void) {
    int before = g_fails;

    expect_bool("a real origin overwrites",
            cell_decisions::prov_origin_wins("0xB193"), true);
    /* The DIAG pipe may not stamp an origin. A later origin-less observation
     * must not erase the one the AT pipe recorded. */
    expect_bool("an absent origin does NOT overwrite",
            cell_decisions::prov_origin_wins(""), false);

    if (g_fails == before)
        printf("  ok   prov origin overwrite policy\n");
}

/* ---------------------------------------------------------------------------
 * PCI <-> full-identity promotion
 * ------------------------------------------------------------------------ */

static void test_promotion_gating(void) {
    int before = g_fails;

    /* No PCI, or no EARFCN -> the whole block is skipped. */
    expect_bool("no pci -> inactive",
            cell_decisions::pci_promotion("LTE", -1, true, 1850, true).active, false);
    expect_bool("no earfcn -> inactive",
            cell_decisions::pci_promotion("LTE", 100, false, 0, true).active, false);

    /* PCI 0 is a real cell, the same asymmetry derive_key() pins. Gating on
     * `pci > 0` here would silently exclude every PCI-0 cell from promotion. */
    expect_bool("pci 0 is promotable",
            cell_decisions::pci_promotion("LTE", 0, true, 1850, false).active, true);

    auto full = cell_decisions::pci_promotion("LTE", 100, true, 1850, true);
    expect_bool("full identity registers itself", full.register_self, true);
    expect_bool("full identity does not consult the map", full.consult_map, false);

    auto partial = cell_decisions::pci_promotion("LTE", 100, true, 1850, false);
    expect_bool("partial consults the map", partial.consult_map, true);
    expect_bool("partial does not register itself", partial.register_self, false);
    expect_str("partial has no peer cell key", partial.peer_cell_key, "");

    if (g_fails == before)
        printf("  ok   promotion gating (pci/earfcn presence, both directions)\n");
}

static void test_promotion_keys_agree_across_rats(void) {
    int before = g_fails;

    /* Cross-RAT collision.
     *
     * Direction 1 builds a peer device key with the rat; direction 2 looks up a
     * map key. Without a rat in the map key, LTE EARFCNs (0..262143) and
     * NR-ARFCNs (0..3279165) overlap completely across the LTE range, and the
     * PCI ranges overlap over 0..503 -- so an NR cell at PCI 100 / NR-ARFCN 1850
     * would consult the same map slot as an LTE tower at PCI 100 / EARFCN 1850
     * and link itself to it as the same `cell_identity`. Two unrelated cells,
     * related in the UI, nothing logged.
     *
     * The invariant that prevents it: the map key must distinguish exactly what
     * the peer device key distinguishes. Assert them together, because the bug
     * is the two disagreeing -- pinning either alone would pass. */
    auto lte = cell_decisions::pci_promotion("LTE", 100, true, 1850, true);
    auto nr  = cell_decisions::pci_promotion("NR",  100, true, 1850, false);

    expect_bool("LTE and NR at the same pci/arfcn do NOT share a map slot",
            lte.map_key != nr.map_key, true);

    /* Both keys carry the resolved frequency, so that a promotion
     * registered by a modem reporting B4/2300 is found by one reporting
     * B66/66786. EARFCN 1850 is B3: 1805.0 + 0.1*(1850-1200) == 1870.0 MHz.
     * NR-ARFCN 1850 is in the 5 kHz range: 1850 * 5 == 9250 kHz -- which is
     * also why the RAT qualifier is still load-bearing, since the two RATs
     * would otherwise be distinguished only by an accident of arithmetic. */
    expect_str("LTE map key carries the rat", lte.map_key, "LTE_100_f1870000");
    expect_str("NR map key carries the rat", nr.map_key, "NR_100_f9250");

    /* The peer device key is the format cellkey_to_mac consumes and must keep
     * matching derive_key()'s partial form exactly -- it is the device MAC.
     * If a key-format change reaches derive_key() alone, promotion links to a
     * MAC no device has; this pair catches that. */
    expect_str("peer cell key matches derive_key's partial format",
            lte.peer_cell_key, "LTE_pci100_f1870000");
    expect_str("derive_key partial form, for comparison",
            cell_decisions::derive_key("LTE", 0, 0, 0, 0, 100, true, 1850).key,
            "LTE_pci100_f1870000");

    /* And the promotion path merges the overlapping pair too -- the same
     * carrier under both band numberings must reach ONE map slot, or a
     * promotion registered by one modem is invisible to the other. */
    expect_str("promotion map slot is band-numbering agnostic",
            cell_decisions::pci_promotion("LTE", 242, true, 2300, true).map_key,
            cell_decisions::pci_promotion("LTE", 242, true, 66786, true).map_key);

    /* Same RAT, same pci/earfcn -> same slot. The fix must not over-partition,
     * or promotion stops working entirely and, again, says nothing. */
    auto lte_partial = cell_decisions::pci_promotion("LTE", 100, true, 1850, false);
    expect_str("same rat still shares a slot", lte_partial.map_key, lte.map_key);

    if (g_fails == before)
        printf("  ok   promotion keys are rat-qualified on BOTH sides\n");
}

/* The offline exporter's PCI->identity map must key on the same
 * "{rat}_{pci}_{carrier_token}" the live PHY registers a promotion under.
 *
 * kismetdb_to_wiglecsv.cc builds its pass-1 map (and pass-2 lookup) through
 * promotion_map_key(). A local `"{pci}_{earfcn}"` -- raw ARFCN, no rat --
 * would silently lose the cross-vendor band merges the PHY makes offline, and
 * an LTE PCI/EARFCN could false-merge an NR PCI/NR-ARFCN over the overlapping
 * ranges. Both writers key through one function, so they cannot drift --
 * assert that agreement here, the same way plmn_from_json is shared by the
 * two writers. */
static void test_promotion_map_key_shared_with_phy(void) {
    int before = g_fails;

    /* 1. The extracted function is what pci_promotion stores -- one spelling. If
     * these ever differ, the offline map and the live map have drifted. Pinned for full-identity (register_self) AND partial
     * (consult_map) since both directions must reach the same slot. */
    expect_str("promotion_map_key == pci_promotion.map_key (full)",
            cell_decisions::promotion_map_key("LTE", 100, 1850),
            cell_decisions::pci_promotion("LTE", 100, true, 1850, true).map_key);
    expect_str("promotion_map_key == pci_promotion.map_key (partial)",
            cell_decisions::promotion_map_key("LTE", 100, 1850),
            cell_decisions::pci_promotion("LTE", 100, true, 1850, false).map_key);

    /* 2. The literal, so a format-string change forks every offline resolution
     * silently (the key never reaches a device, so nm/compiler see nothing). */
    expect_str("map key carries the rat and the resolved frequency",
            cell_decisions::promotion_map_key("LTE", 100, 1850), "LTE_100_f1870000");

    /* 3. A real capture: RXM-G1 NR serving cell, PCI 596 / NR-ARFCN 521310
     * (n41). 521310 * 5 kHz == 2606550 kHz. A full
     * identity obs (pass 1) and its own PCI-only self-neighbour + the 8 measured
     * neighbours (pass 2) must land in the same slot to resolve. */
    expect_str("NR pci596/arfcn521310 keys as the PHY does",
            cell_decisions::promotion_map_key("NR", 596, 521310), "NR_596_f2606550");

    /* 4. Cross-vendor band spellings of one downlink carrier reach one slot
     * offline, exactly as they do live. B4/EARFCN 2300 and B66/EARFCN 66786
     * are the same 2145 MHz carrier; a raw "{pci}_{earfcn}" key puts them in
     * two slots, so a neighbour seen by a B66-spelling modem never resolved
     * against a B4-spelling serving cell. */
    expect_str("cross-vendor band spellings share one offline slot",
            cell_decisions::promotion_map_key("LTE", 242, 2300),
            cell_decisions::promotion_map_key("LTE", 242, 66786));

    /* 5. And it does not over-merge across RATs: an LTE PCI/EARFCN and an NR
     * PCI/NR-ARFCN that collide on the raw ranges get distinct slots. Under a
     * raw key they would read equal, which is why the assertion is
     * inequality. */
    expect_bool("LTE and NR at the same pci/arfcn do NOT share an offline slot",
            cell_decisions::promotion_map_key("LTE", 100, 1850) !=
                cell_decisions::promotion_map_key("NR", 100, 1850), true);

    if (g_fails == before)
        printf("  ok   offline promotion map key == PHY key, folds bands\n");
}

/* The last place a distinct cell can stop being distinct: cell_key -> device MAC.
 *
 * Every decision above can be right and this one wrong, and the result is two
 * real cells presented as one device, with nothing logged. See
 * cell_key_to_mac_bytes' header. */
static uint64_t mac_u64(const std::string& key) {
    uint8_t b[6];
    cell_decisions::cell_key_to_mac_bytes(key, b);
    uint64_t v = 0;
    for (int i = 0; i < 6; i++)
        v = (v << 8) | b[i];
    return v;
}

static void test_cell_key_to_mac(void) {
    int before = g_fails;

    /* 1. Deterministic, and dependent on the whole key. */
    expect_int("same key -> same MAC", mac_u64("LTE_pci100_1850") == mac_u64("LTE_pci100_1850"), 1);
    expect_int("a different PCI -> a different MAC",
            mac_u64("LTE_pci100_1850") != mac_u64("LTE_pci101_1850"), 1);
    expect_int("a different EARFCN -> a different MAC",
            mac_u64("LTE_pci100_1850") != mac_u64("LTE_pci100_1851"), 1);
    expect_int("a different RAT -> a different MAC",
            mac_u64("LTE_pci100_1850") != mac_u64("NR_pci100_1850"), 1);
    expect_int("the empty key still yields a MAC (no crash, no zero address)",
            mac_u64("") != 0, 1);

    /* 2. The two address bits. A synthetic MAC that does not claim to be
     * locally administered is a forged OUI assignment; a group-bit address is
     * not a device at all. Checked over every key below, not just one. */
    {
        int bad_local = 0, bad_group = 0, n = 0;
        for (int pci = 0; pci < 504; pci++) {
            uint8_t b[6];
            cell_decisions::cell_key_to_mac_bytes(
                    "LTE_pci" + std::to_string(pci) + "_1850", b);
            n++;
            if (!(b[0] & 0x02)) bad_local++;
            if (b[0] & 0x01) bad_group++;
        }
        expect_int("locally-administered bit SET on every MAC", bad_local, 0);
        expect_int("group bit CLEAR on every MAC", bad_group, 0);
        expect_int("...over the full legal LTE PCI range", n, 504);
    }

    /* 3. Injectivity over realistic key spaces. An adler32-based derivation
     * (adler32(key) || adler32(key + "_cell") & 0xFFFF) merges 43% of one
     * carrier's LTE cells into another cell's device -- and 86% across one
     * PCI's EARFCN range -- because Kismet's adler32 keeps ls1 as a plain byte
     * sum, so a constant salt adds a constant. These sweeps catch that class
     * of derivation. */
    {
        std::set<uint64_t> macs;
        for (int pci = 0; pci < 504; pci++)
            macs.insert(mac_u64("LTE_pci" + std::to_string(pci) + "_1850"));
        expect_int("504 legal LTE PCIs on one EARFCN -> 504 distinct devices",
                (int)macs.size(), 504);
    }
    {
        std::set<uint64_t> macs;
        for (int pci = 0; pci < 1008; pci++)
            macs.insert(mac_u64("NR_pci" + std::to_string(pci) + "_627264"));
        expect_int("1008 legal NR PCIs on one NR-ARFCN -> 1008 distinct devices",
                (int)macs.size(), 1008);
    }
    {
        std::set<uint64_t> macs;
        for (int e = 1; e <= 8000; e++)
            macs.insert(mac_u64("LTE_pci100_" + std::to_string(e)));
        expect_int("one PCI across EARFCN 1..8000 -> 8000 distinct devices",
                (int)macs.size(), 8000);
    }
    {
        /* Full identity is not safer: 310260_1_1000080 and 310260_2_1000007
         * differ in both TAC and CID and collide under adler32. */
        std::set<uint64_t> macs;
        int n = 0;
        for (int tac = 1; tac <= 50; tac++)
            for (int cid = 1000000; cid < 1000100; cid++, n++)
                macs.insert(mac_u64("310260_" + std::to_string(tac) + "_"
                            + std::to_string(cid)));
        expect_int("5000 full-identity keys -> 5000 distinct devices",
                (int)macs.size(), n);
        expect_int("a pair that collides under adler32 is two devices",
                mac_u64("310260_1_1000080") != mac_u64("310260_2_1000007"), 1);
    }
    expect_int("the named LTE neighbour pair is two devices",
            mac_u64("LTE_pci120_1850") != mac_u64("LTE_pci201_1850"), 1);

    /* 4. The structural property: the low 16 bits must not be a fixed offset
     * from the preceding 16. Under adler32 the difference has exactly one value (511, the byte sum of "_cell") across
     * every key tried -- so a 48-bit address carried 32 bits. */
    {
        std::set<int> deltas;
        for (int pci = 0; pci < 504; pci++) {
            uint8_t b[6];
            cell_decisions::cell_key_to_mac_bytes(
                    "LTE_pci" + std::to_string(pci) + "_1850", b);
            deltas.insert((((b[4] << 8) | b[5]) - ((b[2] << 8) | b[3])) & 0xFFFF);
        }
        expect_int("bytes[4..5] are NOT a fixed offset from bytes[2..3]",
                (int)deltas.size() > 400, 1);
    }

    if (g_fails == before)
        printf("  ok   cell_key -> MAC is injective over the realistic key space\n");
}

/* ---------------------------------------------------------------------------
 * The two related-device inserts.
 *
 * pci_promotion() decides the keys and cannot observe the insert, but the
 * insert has a decision inside it: the edge set must be symmetric and both
 * edges must carry the same relationship name. Kismet's related-device map is
 * keyed by relationship name, so a mismatched name does not drop a link: it
 * files the reverse edge under a different relationship, yielding a link that
 * resolves A->B and not B->A. A device-tree fixture asserting "a link exists"
 * passes on that. This does not.
 * -------------------------------------------------------------------------- */
static void test_related_links_are_symmetric(void) {
    printf("related-device edges\n");

    auto none = cell_decisions::related_links(false);
    expect_bool("no peer resolved -> no edges at all", none.empty(), true);

    auto links = cell_decisions::related_links(true);
    expect_bool("a resolved peer produces EXACTLY two edges", links.size() == 2, true);
    if (links.size() != 2)
        return;

    expect_bool("the two edges point in OPPOSITE directions -- one from self, one from peer", links[0].from_self != links[1].from_self, true);
    expect_bool("both edges carry the SAME relationship name -- a typo in one would "
          "file the reverse edge under a different relationship", std::string(links[0].relationship) == std::string(links[1].relationship), true);
    expect_bool("the relationship is 'cell_identity' -- the name kismetdb and the UI read", std::string(links[0].relationship) == "cell_identity", true);
    expect_bool("the relationship name is never empty", std::string(links[0].relationship).length() > 0, true);
}

/* The map claim. See phy_cell_decisions.h: the map is usually injective on
 * real captures, so this is insurance against a rare case. It is here because
 * the failure would be silent -- an unconditional overwrite links every later
 * PCI-only sighting to the most recent tower. */
static void test_pci_map_claim(void) {
    printf("pci_to_full_identity claim\n");

    expect_bool("a free slot is claimed", cell_decisions::pci_map_claim(false, false) == cell_decisions::map_claim_t::claim, true);
    expect_bool("the same device re-registering is idempotent, NOT ambiguous -- a tower "
          "re-observed on every sweep must not report ambiguity against itself", cell_decisions::pci_map_claim(true, true) == cell_decisions::map_claim_t::reaffirm, true);
    expect_bool("a DIFFERENT device holding the slot is AMBIGUOUS -- PCI reuse", cell_decisions::pci_map_claim(true, false) == cell_decisions::map_claim_t::ambiguous, true);

    /* The property that matters: ambiguity is never silently resolved into a
     * claim. `diag_wwan_pick` returns -2 rather than choose between two DIAG
     * nodes for exactly this reason -- picking one presents as a working link
     * bound to the wrong device. */
    expect_bool("an occupied-by-another slot is NEVER silently re-claimed", cell_decisions::pci_map_claim(true, false) != cell_decisions::map_claim_t::claim, true);
}

int main(void) {
    printf("phy_cell decision layer selftest\n");

    test_identity_only_observations_still_key();
    test_key_derivation();
    test_json_plmn_accepts_strings_and_numbers();
    test_plmn_digits_are_as_broadcast();
    test_numeric_mnc_fallback_follows_wigle_rule();
    test_key_uses_as_broadcast_plmn();
    test_lte_eci_split();
    test_lte_frequency_table_band_edges();
    test_overlapping_bands_do_not_split_a_cell();
    test_rsrp_policy();
    test_band_and_channel();
    test_lte_frequency_table_b23_to_b32();
    test_earfcn_to_band_matches_the_helper_table();
    test_lte_frequency_table_b54_to_b111();
    test_device_naming();
    test_prov_field_ordering();
    test_seen_via_is_a_union_not_a_replace();
    test_absent_origin_does_not_blank_a_known_one();
    test_promotion_gating();
    test_promotion_keys_agree_across_rats();
    test_promotion_map_key_shared_with_phy();
    test_cell_key_to_mac();
    test_related_links_are_symmetric();
    test_pci_map_claim();

    printf("%s\n", g_fails == 0 ? "PASS: all phy_cell decision tests"
                                : "FAIL: phy_cell decision tests");
    return g_fails == 0 ? 0 : 1;
}
