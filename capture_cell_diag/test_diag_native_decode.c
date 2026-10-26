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

    Selftest for diag_native_decode -- the C-callable surface over the diagspec
    cell_observation legs.

    THE POINT OF THIS TEST IS THE LANGUAGE IT IS WRITTEN IN. The legs are C++,
    and the decode must be reachable from the HELPER, which is C:
    capture_cell_diag.c decodes in-process and ships only decoded JSON upstream.
    This file is a pure-C translation unit (no C++ headers, no
    C++ types) that calls diag_native_decode() and checks real payloads decode
    correctly. If it compiles as C, links, and passes, the C entry points work.

    It also pins the two routing behaviours a caller depends on:
      * a log code with no leg returns -1 ("no native leg") -- distinct from
      * a code with a leg that legitimately found nothing, which returns 0.
    Collapsing those two would hide an uncovered code behind "found nothing".

    Expected values are generated from the committed real-capture fixtures via the
    helper-side A/B harness, not hand-transcribed.

    Build: see the selftest rule in Makefile.in (links the C++ legs + -lstdc++).
*/

#ifdef CELL_SELFTEST

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "diag_native_decode.h"

typedef struct {
    const char *rat;
    uint16_t log_code;
    int32_t pci;
    int32_t earfcn;
    bool is_serving;
    bool has_rsrp;
    double rsrp;
    bool has_rsrq;
    double rsrq;
    bool has_identity;
    const char *mcc;
    const char *mnc;
    uint32_t tac;
    /* 64-bit to match diag_native_obs_t: NR NCI is 36 bits. A uint32_t
     * here would make the EXPECTATION truncate too, so a real widening bug in
     * the leg would compare equal against an equally-broken expected value. */
    uint64_t cell_id;
} expect_t;

#define MAX_OBS 64

static size_t unhex(const char *h, uint8_t *out, size_t out_sz) {
    size_t n = 0;
    for (size_t i = 0; h[i] && h[i + 1] && n < out_sz; i += 2) {
        int hi = h[i] >= 'a' ? h[i] - 'a' + 10 : h[i] - '0';
        int lo = h[i + 1] >= 'a' ? h[i + 1] - 'a' + 10 : h[i + 1] - '0';
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

/* LTE idle neighbors, SDX62 -- 3 cells, exercises the multi-cell walk
 * Source fixture: lte_ml1_neighbor_b192_rm520ngl_sdx62_232B.bin (232 B) */
static const char *kHex_b192_rm520ngl_sdx62 =
        "010200461a023c00fc08000023000000ec08000060d4010060d4010000000000d709000090d4010090d4010000000000"
        "0609000080d5010080d50100000000001b38a800fc0800000300000065000000022550007bb44700022550001c71e40a"
        "ae70c411f7010000ddb90f00000000003500340060d4010060d4010000000000660000007dd447009994490099944900"
        "9658c20ccc30c30cf7010000deb90f00000000003500340090d4010090d4010000000000670000005664450056644500"
        "566445008514d2088d34d208e1010000d9090f00000000003500340080d5010080d5010000000000";
static const expect_t kExp_b192_rm520ngl_sdx62[] = {
        {"LTE", 0xB192, 101, 2300, false, false, 0.0, false, 0.0, false, "", "", 0, 0},
        {"LTE", 0xB192, 102, 2300, false, false, 0.0, false, 0.0, false, "", "", 0, 0},
        {"LTE", 0xB192, 103, 2300, false, false, 0.0, false, 0.0, false, "", "", 0, 0},
};
/* LTE idle neighbors, MDM9207 -- a different chipset generation
 * Source fixture: lte_ml1_neighbor_b192_eg25g_mdm9207_96B_v4.bin (96 B) */
static const char *kHex_b192_eg25g_mdm9207 =
        "010202001a021c00fc08000021000000031000000000000000000000000000001b044000fc0800000100000068000000"
        "42244400c0033c0042244400bdf4220bb2f4d20b960100001eb10c000000000025003000b2560300b256030000000000";
static const expect_t kExp_b192_eg25g_mdm9207[] = {
        {"LTE", 0xB192, 104, 2300, false, false, 0.0, false, 0.0, false, "", "", 0, 0},
};
/* LTE connected neighbors, sp_ver=40 body-derived-count branch, 2 cells
 * Source fixture: lte_ml1_conn_neighbor_b195_lv55_sdx55_168B_v40.bin (168 B) */
static const char *kHex_b195_lv55_sdx55_168B =
        "010292ff1e283000e803010022010000d154000001100000853502008535020000000000361100007935020079350200"
        "000000001f287400e803010002c853016900000007744000eaa33e0007744000a184c2099c84120a620100004a110b00"
        "00000000350037008535020085350200000000006a000000411444005224450052244500db6c43100411441062010000"
        "4a110b000000000035003700793502007935020000000000";
static const expect_t kExp_b195_lv55_sdx55_168B[] = {
        {"LTE", 0xB195, 105, 66536, false, false, 0.0, false, 0.0, false, "", "", 0, 0},
        {"LTE", 0xB195, 106, 66536, false, false, 0.0, false, 0.0, false, "", "", 0, 0},
};
/* LTE SIB1 identity -- the only code carrying MCC/MNC/TAC/CellID; v20 branch
 * Source fixture: lte_rrc_sib1_ident_b0c0_eg25g_mdm9207_v20.bin (56 B) */
static const char *kHex_b0c0_ident_eg25g_v20 =
        "140e30007000ab130000a5fe0202000000250068400600312340abcde182352c8020610b089848c306e38263f4228070"
        "0964760000000000";
static const expect_t kExp_b0c0_ident_eg25g_v20[] = {
        {"LTE", 0xB0C0, 112, 5035, false, false, 0.0, false, 0.0, true, "001", "001", 4660, 11259361},
};
/* LTE SIB1 identity -- the v>=25 variable-header branch
 * Source fixture: lte_rrc_sib1_ident_b0c0_rm520ngl_sdx62_v27.bin (53 B) */
static const char *kHex_b0c0_ident_rm520ngl =
        "1b101010600071006e140000054e03020000002000484006003234501234569181822103108ac21bac1524a80c030292"
        "ccba000000";
static const expect_t kExp_b0c0_ident_rm520ngl[] = {
        {"LTE", 0xB0C0, 113, 5230, false, false, 0.0, false, 0.0, true, "001", "001", 9029, 1193046},
};
/* NR meas, v7 SDX55 -- carries a serving flag AND an absent-rsrp sentinel cell
 * Source fixture: nr5g_meas_db_update_b97f_rm500q_sdx55_168B.bin (168 B) */
static const char *kHex_b97f_rm500q_sdx55_v7 =
        "0700020001140000ac000000f4ffffff8ea607000200c900000000000000000000000000ffffffffffff0000ffffffff"
        "c900fe020100000000cdffff00f9ffff0000000000000000000000004b63074584d6f80cb8ccffff14cdffff14cdffff"
        "e6f8ffff0000000000000000ca007e000100000000baffff00ecffff0200000000000000000000009747dd782f13f90c"
        "00baffff00baffff00baffff80eaffff0000000000000000";
static const expect_t kExp_b97f_rm500q_sdx55_v7[] = {
        {"NR", 0xB97F, 201, 501390, true, true, -102, true, -14, false, "", "", 0, 0},
        {"NR", 0xB97F, 202, 501390, false, false, 0, true, -40, false, "", "", 0, 0},
};
/* NR meas, v9 SDX62 -- 4 cells with fractional /128 rsrp/rsrq
 * Source fixture: nr5g_meas_db_update_b97f_rm520ngl_sdx62_v9_292B.bin (292 B) */
static const char *kHex_b97f_rm520ngl_v9 =
        "090002000000f125011400006811000051000000a0e009000004cb000001000055c8ffff67c3ffffffffffffffff0000"
        "ffffffffcb00be00010000003ec6ffff8ef6ffff010000000000000000000000801f71aefa6bd01009c3ffff1cc6ffff"
        "3ec6ffff8ef6fffff2c7ffff97f8ffffcc00a6000100000010c3ffff27f5ffff010000000000000000000000a3cc2504"
        "5b6c851061c1ffff00b2ffff10c3ffff27f5ffff0000000000000000cd004e01010000000ac5ffff16f6ffff00000000"
        "0000000000000000ccae36a7a252d01000b2ffff1bc5ffff0ac5ffff16f6ffff0000000000000000ce00be0001000000"
        "86c3ffff93f4ffff0000000000000000000000004c7c78dad552d010e6c0ffff86c3ffff86c3ffff93f4ffff00000000"
        "00000000";
static const expect_t kExp_b97f_rm520ngl_v9[] = {
        {"NR", 0xB97F, 203, 647328, true, true, -115.515625, true, -18.890625, false, "", "", 0, 0},
        {"NR", 0xB97F, 204, 647328, false, true, -121.875, true, -21.6953125, false, "", "", 0, 0},
        {"NR", 0xB97F, 205, 647328, false, true, -117.921875, true, -19.828125, false, "", "", 0, 0},
        {"NR", 0xB97F, 206, 647328, false, true, -120.953125, true, -22.8515625, false, "", "", 0, 0},
};

/* v59 SDX62 -- BITPACKED 12-bit rsrp/rsrq at cell+44/+56, PCI at cell+8, and the
 * only version with a grounded serving flag (bit15 of the PCI word)
 * Source fixture: lte_ml1_serving_b193_rm520ngl_sdx62_164B_v59.bin (164 B) */
static const char *kHex_b193_rm520ngl_sdx62_v59 =
        "01018df8193ba000f613000001000000030000000001ffff6b800000fa2600000a0900008504d817fbde1200b7344700"
        "730400006009960000702300b7744b0079e4a1033a00000079e49107cd4a160000000000cd020000fbfff9ff00000000"
        "350036000000000000000000ef3e0000a01300000000000000000000a4c5050000000000280000000c00000000000000"
        "00000000b0c44700000000000000000079000000";
static const expect_t kExp_b193_rm520ngl_sdx62_v59[] = {
        {"LTE", 0xB193, 107, 5110, true, true, -104.56, true, -22.44, false, "", "", 0, 0},
};
/* v48 SDX55, THREE cells -- the ONLY 12-byte carrier header, so the array both
 * starts and is STRIDED 4 B later. Signal absent on every cell: the x16 scale
 * holds on SINGLE-cell records but reads +1947 dBm on a multi-cell one, so the
 * leg withholds it and ships the verified identity. The 1-vs-3 cell contrast
 * is what separates the two candidate stride derivations -- they are
 * identical at num_cells == 1
 * Source fixture: lte_ml1_serving_b193_m2000_sdx55_440B_v48_3cell.bin (440 B) */
static const char *kHex_b193_m2000_sdx55_v48_3cell =
        "01015f201930b401e204010003000f00000102036c1000009e120000489a010024cdf0149eb21300e6745000fb844e00"
        "e3d44f000675280007d54f00d34c430ee43cd30de490030eda221700da4a1700e4020000f8fff7fff8fff7ff23002400"
        "290029000000ff7f8d3d0200c2f30100eccc0100c1d6010076010000b2010000d9be0100c3ba010035000000e4000000"
        "a2010000710200007affffff090200006d0000009e160000489a010024cdf0149e0a1100e6944300fbb44400e3d44f00"
        "21241c0042a443002bac900009c400002bac0002d7821700da921700f0020000f8fff7fff8fff7ff2300240029002900"
        "0000ff7f5c2100005c21000070e000006bc6000007000000050000002c3c000032000000350000002b000000a2010000"
        "6202000075ffffff090200006e0000009e1a0000489a010024cdf0149e6e1100e6244b00fb344600e3d44f0077242300"
        "b2b4490046185108853c210485145207d66a1700d4aa1700ed020000f8fff7fff8fff7ff23002400290029000000ff7f"
        "ab350000bc990000856401008210010027000000780000007750010065f800003500000085000000a50100004b020000"
        "75ffffff0c020000";
static const expect_t kExp_b193_m2000_sdx55_v48_3cell[] = {
        {"LTE", 0xB193, 108, 66786, true, false, 0.0, false, 0.0, false, "", "", 0, 0},
        {"LTE", 0xB193, 109, 66786, false, false, 0.0, false, 0.0, false, "", "", 0, 0},
        {"LTE", 0xB193, 110, 66786, false, false, 0.0, false, 0.0, false, "", "", 0, 0},
};
/* v18 MDM9207 (EG25-G) -- NO cell array at all; the serving cell is packed inline
 * in the carrier header. Its signal is v6's x16 block at +8: expected values
 * pinned from a reference decode of the same bytes.
 * Source fixture: lte_ml1_serving_b193_eg25g_mdm9207_100B_v18.bin (100 B) */
static const char *kHex_b193_eg25g_mdm9207_v18 =
        "0101ff0019126000fc0800006f100000410600004aad0600a5560b1241ba11006ed43c00cde346006ea48b2e9e78a20b"
        "bacce93d73020000000008002500300000000000ea2b0000973100007c020100190000001100000063a600003a000000"
        "ba000000";
static const expect_t kExp_b193_eg25g_mdm9207_v18[] = {
        {"LTE", 0xB193, 111, 2300, true, true, -109.12, true, -18.38, false, "", "", 0, 0},
};

static bool check(const char *name, uint16_t code, const char *hex,
        const expect_t *exp, size_t n_exp) {
    uint8_t payload[4096];
    size_t len = unhex(hex, payload, sizeof(payload));

    diag_native_obs_t got[MAX_OBS];
    int n = diag_native_decode(code, payload, len, got, MAX_OBS);

    if (n < 0) {
        printf("FAIL[%s]: no native leg for 0x%04X\n", name, code);
        return false;
    }
    if ((size_t)n != n_exp) {
        printf("FAIL[%s]: %d observation(s), expected %zu\n", name, n, n_exp);
        return false;
    }
    for (size_t i = 0; i < n_exp; i++) {
        const diag_native_obs_t *g = &got[i];
        const expect_t *e = &exp[i];
        bool same =
            strcmp(g->rat, e->rat) == 0 && g->log_code == e->log_code &&
            g->pci == e->pci && g->earfcn == e->earfcn &&
            g->is_serving == e->is_serving &&
            g->has_rsrp == e->has_rsrp && g->has_rsrq == e->has_rsrq &&
            (!e->has_rsrp || g->rsrp == e->rsrp) &&
            (!e->has_rsrq || g->rsrq == e->rsrq) &&
            g->has_identity == e->has_identity &&
            (!e->has_identity ||
             (strcmp(g->mcc, e->mcc) == 0 && strcmp(g->mnc, e->mnc) == 0 &&
              g->tac == e->tac && g->cell_id == e->cell_id));
        if (!same) {
            printf("FAIL[%s] obs %zu:\n", name, i);
            printf("  got  rat=%s code=0x%04X pci=%d earfcn=%d serving=%d "
                   "rsrp=%s%.10g rsrq=%s%.10g ident=%d %s/%s tac=%u cid=%llu\n",
                   g->rat, g->log_code, g->pci, g->earfcn, (int)g->is_serving,
                   g->has_rsrp ? "" : "(absent)", g->rsrp,
                   g->has_rsrq ? "" : "(absent)", g->rsrq,
                   (int)g->has_identity, g->mcc, g->mnc, g->tac,
                   (unsigned long long)g->cell_id);
            printf("  want rat=%s code=0x%04X pci=%d earfcn=%d serving=%d "
                   "rsrp=%s%.10g rsrq=%s%.10g ident=%d %s/%s tac=%u cid=%llu\n",
                   e->rat, e->log_code, e->pci, e->earfcn, (int)e->is_serving,
                   e->has_rsrp ? "" : "(absent)", e->rsrp,
                   e->has_rsrq ? "" : "(absent)", e->rsrq,
                   (int)e->has_identity, e->mcc, e->mnc, e->tac,
                   (unsigned long long)e->cell_id);
            return false;
        }
    }
    printf("PASS[%s]: %d observation(s) decoded natively from C\n", name, n);
    return true;
}

/* A code with no leg must be DISTINGUISHABLE from a code with a leg that found
 * nothing -- the census routes on that difference (undecoded vs decoded). If
 * both returned 0, every record of an uncovered code would read as decoded.
 *
 * The no-leg exemplar is 0xB197. Of the cell codes carried in
 * DIAG_TARGET_CODES, 0xB192/0xB195/0xB0C0/0xB97F/0xB193/0xB17F/0xB821 have a
 * native leg. 0xB197 is a genuine no-leg case rather than a placeholder: it is
 * LTE serving-cell config, which only feeds the sib1 map's cell-config cache
 * (diag_native_cell_config_learn) and emits no observation of its own, so
 * diag_native_decode must keep declining it outright. (0xB821 was the
 * exemplar until its MeasurementReport rows became a native leg.)
 *
 * Keeping a REAL no-leg code here matters. Without one, the -1-vs-0
 * distinction would go untested. */
static bool check_routing_contract(void) {
    uint8_t junk[64];
    memset(junk, 0, sizeof(junk));
    diag_native_obs_t got[MAX_OBS];

    if (diag_native_has_leg(0xB197)) {
        printf("FAIL[routing]: 0xB197 unexpectedly reports a native cell leg\n");
        return false;
    }
    if (diag_native_decode(0xB197, junk, sizeof(junk), got, MAX_OBS) != -1) {
        printf("FAIL[routing]: no-leg 0xB197 did not return -1\n");
        return false;
    }
    /* 0xB821 has a leg: junk must decode to 0 (ran, found nothing). */
    if (!diag_native_has_leg(0xB821) ||
            diag_native_decode(0xB821, junk, sizeof(junk), got, MAX_OBS) != 0) {
        printf("FAIL[routing]: 0xB821 is not a leg returning 0 on junk\n");
        return false;
    }
    /* ...and codes with a leg must answer the other way, or this test would keep
     * passing against a build that silently lost the 0xB193 leg. */
    if (!diag_native_has_leg(0xB193)) {
        printf("FAIL[routing]: 0xB193 does not report a native leg\n");
        return false;
    }
    if (!diag_native_has_leg(0xB192)) {
        printf("FAIL[routing]: 0xB192 does not report a native leg\n");
        return false;
    }
    /* A code with a leg fed an unparseable payload must return 0 (decoded,
     * found nothing), NOT -1 -- otherwise it would be counted as uncovered. */
    if (diag_native_decode(0xB192, junk, sizeof(junk), got, MAX_OBS) != 0) {
        printf("FAIL[routing]: 0xB192 (has a leg) on junk did not return 0\n");
        return false;
    }
    printf("PASS[routing]: -1 (no leg) and 0 (leg found nothing) stay distinct\n");
    return true;
}

/* Truncation must be reported, not overflow the caller's buffer. */
static bool check_capacity_clamp(void) {
    uint8_t payload[4096];
    size_t len = unhex(kHex_b192_rm520ngl_sdx62, payload, sizeof(payload));
    diag_native_obs_t got[1];
    int n = diag_native_decode(0xB192, payload, len, got, 1);
    if (n != 1) {
        printf("FAIL[clamp]: wrote %d into a 1-slot buffer, expected 1\n", n);
        return false;
    }
    printf("PASS[clamp]: a 3-cell record clamps to the caller's 1-slot buffer\n");
    return true;
}


/* ---- GNSS position fix (0x1476) -- the SECOND entry point ------------------
 *
 * Not a fifth cell code: diag_native_decode_gps_fix() has its own output type
 * (see diag_native_decode.h for why folding it into diag_native_obs_t would make
 * "no measurement" readable as a value).
 *
 * These payloads are BUILT, not hex blobs, because the thing under test is an
 * OFFSET REGIME and the records are 291..2477 bytes of mostly zeros. 0x1476
 * lands lat/lon/alt at three different offset triples keyed on the
 * (version, payload_size) PAIR:
 *
 *   `_POS_FMT` v1/v2/v10        (default)                  lat@40 lon@48 alt@56
 *   mdm9600 gpsOne              version==2 && size==797     lat@36 lon@44 alt@52
 *   v13 (SDX55) / v24 (SDX62+)  version>=13 && size>=407    lat@49 lon@57 alt@65
 *
 * and the REFERENCE MODEM USES THE LAST ONE: all 16 0x1476 records in the
 * RM520N-GL capture are version=24. A leg reading the first regime's offsets on
 * a v24 record gets lat=0.0 and a ~1e185 lon, which the validity gate rejects --
 * so it emits ZERO fixes on the reference modem where 16 are there, and "no
 * fixes" is indistinguishable from "no sky view". That is a silent regression,
 * which is why the regimes are pinned here.
 *
 * v24 and mdm9600 both matter for a second reason: `plain_v2_291` and
 * `mdm9600_797` share version byte 2, so a gate keyed on the version alone
 * routes one of them into the other's offsets.
 *
 * Expected values generated from the diagspec 0x1476 fixture builder
 * (enrichment/py/diag_0x1476_fixture.py::build_all_regimes), not hand-
 * transcribed. Coordinates are fabricated, not real locations.
 */

/* Store an IEEE-754 double / float little-endian at `off`. memcpy, not a cast:
 * a *(double*)(buf+off) store is an alignment + strict-aliasing violation, and
 * these offsets (49, 57, 65) are deliberately unaligned. */
static void put_f64(uint8_t *buf, size_t off, double v) { memcpy(buf + off, &v, 8); }
static void put_f32(uint8_t *buf, size_t off, float v) { memcpy(buf + off, &v, 4); }
static void put_u8(uint8_t *buf, size_t off, uint8_t v) { buf[off] = v; }

/* One GNSS expectation: the (decision, coordinates) tuple. `valid` is IN the
 * tuple because the reject decision is half the contract and the more dangerous
 * half -- a wrong-regime leg fails by emitting nothing, not by emitting a wrong
 * number, so a coordinates-only compare cannot see it. */
typedef struct {
    const char *name;
    uint8_t version;
    size_t size;
    size_t lat_off, lon_off, alt_off;
    double lat_rad, lon_rad;
    float alt_m;
    bool want_valid;
    double want_lat_deg, want_lon_deg, want_alt_m;
    /* The gps_week to plant (0 == a valid time solution) and the decline
     * reason the tap must attribute. Zero-filled fields mean "valid time, and
     * DIAG_NATIVE_GPS_DECLINE_NONE" -- correct for every want_valid case. */
    uint16_t gps_week;
    diag_native_gps_decline_t want_reason;
} gnss_case_t;

/* Offset of the u16le gps_week for a given (version, size), mirroring the
 * generated diag_0x1476_t::fix_gps_week() regime resolution exactly (mdm9600
 * 19, v13+ 32, else 23). The test plants gps_week itself so a NO_TIME case is a
 * real seed-position payload, not a mocked reason. */
static size_t gps_week_offset(uint8_t version, size_t size) {
    if (version == 2 && size == 797) return 19;          /* mdm9600 gpsOne */
    if (version >= 13 && size >= 407) return 32;         /* v13/v24 (SDX55+) */
    return 23;                                           /* plain _POS_FMT */
}

/* pi as the exact IEEE-754 double (M_PI), so the placeholder cases below land on
 * exactly the expected coordinates. */
#define GNSS_PI 3.141592653589793

static const gnss_case_t kGnssCases[] = {
    /* plain `_POS_FMT` -- the regime the .ksy's seq models. */
    {"plain_v7",     7,  291, 40, 48, 56,  0.5, -1.0,  100.0f, true,
      28.64788975654116, -57.29577951308232, 100.0},
    {"plain_v2_291", 2,  291, 40, 48, 56,  0.75, -1.25, 1424.5f, true,
      42.97183463481174, -71.6197243913529, 1424.5},
    /* v24 = the reference modem (RM520N-GL / SDX62) -- 9 bytes LATER. */
    {"v24_sdx62",   24, 1575, 49, 57, 65,  0.75, -1.25, 1424.5f, true,
      42.97183463481174, -71.6197243913529, 1424.5},
    /* v13 = SDX55: same header offsets, different version AND size, so a leg
     * that hardcoded one of the two passes on the other. */
    {"v13_sdx55",   13, 2477, 49, 57, 65, -0.5, 2.0,   50.25f, true,
      -28.64788975654116, 114.59155902616465, 50.25},
    /* mdm9600: the only regime that reads EARLIER than the seq (no fake_align). */
    {"mdm9600_797",  2,  797, 36, 44, 52,  0.5, -1.0,  1418.0f, true,
      28.64788975654116, -57.29577951308232, 1418.0,
      /* A real week: the mdm9600 layout refuses week 0 (its structural
       * guard), and this leg declines such a record UNPARSEABLE. */
      1397, DIAG_NATIVE_GPS_DECLINE_NONE},
    /* ...and that guard, pinned: the same record at week 0 is refused, not a
     * fix. */
    {"reject_mdm9600_week0", 2, 797, 36, 44, 52, 0.5, -1.0, 1418.0f, false,
      0, 0, 0, 0, DIAG_NATIVE_GPS_DECLINE_UNPARSEABLE},
    /* Vendor "no fix" placeholders -- must be REJECTED, or Kismet geo-tags every
     * cell in the run at a fabricated coordinate: Qualcomm's Nevada default
     * (38, -117) and the Telit no-antenna sentinel (5.5, 6.6). Each reject also
     * pins WHICH gate refused, so a leg that rejects for the wrong reason (and
     * thus mis-counts the tap's opposite-findings split) is caught. */
    {"reject_nevada_v24", 24, 1575, 49, 57, 65,
      38.0 * GNSS_PI / 180.0, -117.0 * GNSS_PI / 180.0, 1000.0f, false, 0, 0, 0,
      0, DIAG_NATIVE_GPS_DECLINE_PLACEHOLDER},
    {"reject_telit_plain", 7, 291, 40, 48, 56,
      5.5 * GNSS_PI / 180.0, 6.6 * GNSS_PI / 180.0, 0.0f, false, 0, 0, 0,
      0, DIAG_NATIVE_GPS_DECLINE_PLACEHOLDER},
    /* (0,0): the generic "value unavailable" sentinel. It fails the coordinate
     * magnitude gate (|0| is not > 1) BEFORE the placeholder gate, so its reason
     * is NO_POSITION, matching gps_gate_verdict's ordering -- not PLACEHOLDER,
     * even though is_placeholder_position would also catch it. This is also what
     * a 0x14D8 record would look like if it carried position -- it does not,
     * which is why there is no 0x14D8 leg (diag_native_decode.h). */
    {"reject_zero_v24", 24, 1575, 49, 57, 65, 0.0, 0.0, 0.0f, false, 0, 0, 0,
      0, DIAG_NATIVE_GPS_DECLINE_NO_POSITION},
    /* Seed position: plausible degrees but gps_week==0xFFFF, so ONLY the
     * time-solution gate can reject it. The coordinate gates pass -- that is the
     * whole point -- so this is the case a single decline counter would fold in
     * with benign no-sky-view, 215 km apart. Same coords as v24_sdx62. */
    {"reject_seedpos_v24_notime", 24, 1575, 49, 57, 65, 0.75, -1.25, 1424.5f,
      false, 0, 0, 0, 0xFFFF, DIAG_NATIVE_GPS_DECLINE_NO_TIME},
};

/* Exact compare, no epsilon. Both sides evaluate (rad * 180.0) / pi in that
 * order, so the last ulp agrees; a tolerance would be wide enough to hide the
 * off-by-9-bytes read these cases exist to catch. */
static bool check_gnss(const gnss_case_t *c) {
    uint8_t *buf = (uint8_t *) calloc(1, c->size);
    if (buf == NULL) { printf("  FAIL %s: calloc\n", c->name); return false; }
    put_u8(buf, 0, c->version);
    put_f64(buf, c->lat_off, c->lat_rad);
    put_f64(buf, c->lon_off, c->lon_rad);
    put_f32(buf, c->alt_off, c->alt_m);
    /* Plant gps_week at its regime offset (0 by default == valid time). */
    { size_t wo = gps_week_offset(c->version, c->size);
      buf[wo] = (uint8_t)(c->gps_week & 0xFF);
      buf[wo + 1] = (uint8_t)((c->gps_week >> 8) & 0xFF); }

    diag_native_gps_fix_t fix;
    /* NULL tracker: the per-record verdict, no staleness reference. */
    int rc = diag_native_decode_gps_fix(NULL, 0x1476, buf, c->size, &fix);
    free(buf);

    bool ok = true;
    if (rc < 0) {
        printf("  FAIL %s: 0x1476 reported no native GNSS leg (rc=%d)\n", c->name, rc);
        return false;
    }
    if (fix.valid != c->want_valid || rc != (c->want_valid ? 1 : 0)) {
        printf("  FAIL %s: valid=%d rc=%d, want valid=%d\n",
               c->name, (int) fix.valid, rc, (int) c->want_valid);
        return false;
    }
    /* The decline reason must be the exact gate that refused (and
     * DIAG_NATIVE_GPS_DECLINE_NONE on an accepted fix). This is what keeps the
     * tap's opposite findings -- benign no_position vs a 215 km seed position --
     * from collapsing back into one number. */
    if (fix.decline_reason != c->want_reason) {
        printf("  FAIL %s: decline_reason=%d, want %d\n",
               c->name, (int) fix.decline_reason, (int) c->want_reason);
        ok = false;
    }
    if (c->want_valid) {
        if (fix.lat_deg != c->want_lat_deg || fix.lon_deg != c->want_lon_deg ||
                fix.alt_m != c->want_alt_m) {
            printf("  FAIL %s: got %.17g,%.17g alt=%.17g want %.17g,%.17g alt=%.17g\n",
                   c->name, fix.lat_deg, fix.lon_deg, fix.alt_m,
                   c->want_lat_deg, c->want_lon_deg, c->want_alt_m);
            ok = false;
        }
    }
    if (ok)
        printf("  ok   %s (v%u, %zuB, lat@%zu)\n", c->name, c->version, c->size, c->lat_off);
    return ok;
}

/* The GNSS routing contract, and the reason it is separate from the cell one:
 * the two entry points must DISAGREE about which codes they own. 0x1476 has no
 * cell leg and 0xB192 has no GNSS leg; if either surface claimed the other's
 * codes, the caller would route a record into a decoder that reads it as a
 * different structure entirely. 0x14D8 must be claimed by NEITHER -- see
 * diag_native_decode.h for why there is deliberately no leg for it. */
static bool check_gnss_routing_contract(void) {
    bool ok = true;
    diag_native_gps_fix_t fix;
    uint8_t dummy[64];
    memset(dummy, 0, sizeof(dummy));

    if (!diag_native_has_gps_leg(0x1476)) {
        printf("  FAIL routing: 0x1476 should have a GNSS leg\n"); ok = false;
    }
    if (diag_native_has_gps_leg(0x14D8)) {
        printf("  FAIL routing: 0x14D8 must NOT have a GNSS leg -- its lat/lon/alt\n"
               "       are hardcoded 0.0 in the reference parser, so a leg for it\n"
               "       would be a decode path that is provably always empty\n");
        ok = false;
    }
    if (diag_native_has_gps_leg(0xB192) || diag_native_has_leg(0x1476)) {
        printf("  FAIL routing: the cell and GNSS surfaces overlap\n"); ok = false;
    }
    /* A no-leg code returns -1 ("no leg"), never 0 ("leg ran, no fix"). */
    if (diag_native_decode_gps_fix(NULL, 0x14D8, dummy, sizeof(dummy), &fix) != -1) {
        printf("  FAIL routing: 0x14D8 gps decode should return -1\n"); ok = false;
    }
    /* ...and -1 still leaves out_fix fully written, so a caller that ignores the
     * return value reads "no fix", not stack garbage. */
    if (fix.valid) {
        printf("  FAIL routing: out_fix not cleared on the no-leg path\n"); ok = false;
    }
    /* A payload far too short for any regime declines, it does not crash: a
     * malformed record is a no-fix, in the UNPARSEABLE bucket. */
    if (diag_native_decode_gps_fix(NULL, 0x1476, dummy, 4, &fix) != 0 || fix.valid ||
            fix.decline_reason != DIAG_NATIVE_GPS_DECLINE_UNPARSEABLE) {
        printf("  FAIL routing: a 4-byte 0x1476 should decline UNPARSEABLE, not fix "
               "(valid=%d reason=%d)\n", (int) fix.valid, (int) fix.decline_reason);
        ok = false;
    }
    if (ok)
        printf("  ok   gnss routing contract (-1 no-leg vs 0 declined; 0x14D8 unclaimed)\n");
    return ok;
}

/* The GNSS freshness tracker contract.
 *
 * The staleness gate is the one GNSS gate the per-record cases above cannot
 * reach: it judges a fix against the newest GNSS clock the STREAM carried
 * before it. What is pinned HERE is the C ABI around the leg's FreshnessTracker
 * -- that the handle actually reaches the leg, that NULL is inert, that reset
 * forgets, and the decline names.
 *
 * The stream is the measured RM500Q-AE shape: a v13 record re-served 13.68 h
 * after it was live, at the same coordinates, between live ones. */
static void put_u16(uint8_t *b, size_t off, uint16_t v) {
    b[off] = (uint8_t)(v & 0xFF); b[off + 1] = (uint8_t)(v >> 8);
}
static void put_u32(uint8_t *b, size_t off, uint32_t v) {
    for (int i = 0; i < 4; i++) b[off + i] = (uint8_t)(v >> (8 * i));
}

/* A v13 (SDX55, 2477 B) record at a plausible fictional position, week 2430. */
static uint8_t *v13_record(uint32_t tow_ms) {
    uint8_t *b = (uint8_t *) calloc(1, 2477);
    if (b == NULL) return NULL;
    put_u8(b, 0, 13);
    put_u16(b, 32, 2430);          /* fix_gps_week, v13 base 32 */
    put_u32(b, 34, tow_ms);        /* fix_gps_tow_ms, base + 2  */
    put_f64(b, 49, 0.75);
    put_f64(b, 57, -1.25);
    put_f32(b, 65, 1424.5f);
    return b;
}

static int judge(diag_native_gnss_tracker_t *t, uint32_t tow_ms,
                 diag_native_gps_fix_t *fix) {
    uint8_t *b = v13_record(tow_ms);
    if (b == NULL) return -2;
    int rc = diag_native_decode_gps_fix(t, 0x1476, b, 2477, fix);
    free(b);
    return rc;
}

static bool check_gnss_tracker_contract(void) {
    bool ok = true;
    const uint32_t live = 90600000u, stale = 90600000u - 49246000u;  /* 13.68 h */
    diag_native_gps_fix_t fix;

    if (diag_native_gnss_default_max_fix_age_ms() != 60000) {
        printf("  FAIL tracker: default bound %lld ms, want 60000\n",
               (long long) diag_native_gnss_default_max_fix_age_ms());
        ok = false;
    }
    diag_native_gnss_tracker_t *t =
        diag_native_gnss_tracker_new(diag_native_gnss_default_max_fix_age_ms());
    if (t == NULL) {
        printf("  FAIL tracker: _new returned NULL\n");
        return false;
    }
    /* live seeds the reference (the warm-up hole: counted, accepted)... */
    if (judge(t, live, &fix) != 1 || !fix.valid ||
            diag_native_gnss_tracker_unjudged(t) != 1) {
        printf("  FAIL tracker: the seeding live fix must be accepted and counted "
               "unjudged (valid=%d unjudged=%llu)\n", (int) fix.valid,
               (unsigned long long) diag_native_gnss_tracker_unjudged(t));
        ok = false;
    }
    /* ...so the re-served copy is refused, under its OWN reason... */
    if (judge(t, stale, &fix) != 0 || fix.valid ||
            fix.decline_reason != DIAG_NATIVE_GPS_DECLINE_STALE) {
        printf("  FAIL tracker: a 13.68 h old re-served fix must decline STALE "
               "(valid=%d reason=%d)\n", (int) fix.valid, (int) fix.decline_reason);
        ok = false;
    }
    /* ...while the next live one is kept, and the hole stays one record wide. */
    if (judge(t, live + 1000u, &fix) != 1 || !fix.valid ||
            diag_native_gnss_tracker_unjudged(t) != 1) {
        printf("  FAIL tracker: a live fix after the stale one must be accepted\n");
        ok = false;
    }
    /* NULL is inert: the same stale record, per record, is a fix. That is the
     * gap -- and why a capture source must pass its tracker. */
    if (judge(NULL, stale, &fix) != 1 || !fix.valid) {
        printf("  FAIL tracker: a NULL tracker must leave staleness inert\n");
        ok = false;
    }
    /* reset forgets: the stale record seeds a fresh reference and slips. */
    diag_native_gnss_tracker_reset(t);
    if (diag_native_gnss_tracker_unjudged(t) != 0 ||
            judge(t, stale, &fix) != 1 || !fix.valid ||
            diag_native_gnss_tracker_unjudged(t) != 1) {
        printf("  FAIL tracker: reset must forget the reference and the count\n");
        ok = false;
    }
    diag_native_gnss_tracker_free(t);
    diag_native_gnss_tracker_free(NULL);   /* a no-op, like the sib1 map */
    if (diag_native_gnss_tracker_unjudged(NULL) != 0) {
        printf("  FAIL tracker: unjudged(NULL) must be 0\n");
        ok = false;
    }

    /* The decline names, verbatim. */
    static const struct { diag_native_gps_decline_t r; const char *want; } kNames[] = {
        {DIAG_NATIVE_GPS_DECLINE_UNPARSEABLE, "unparseable"},
        {DIAG_NATIVE_GPS_DECLINE_NO_POSITION, "no_position"},
        {DIAG_NATIVE_GPS_DECLINE_PLACEHOLDER, "placeholder_position"},
        {DIAG_NATIVE_GPS_DECLINE_NO_TIME, "no_time_solution"},
        {DIAG_NATIVE_GPS_DECLINE_STALE, "stale_fix"},
        {DIAG_NATIVE_GPS_DECLINE_ALTITUDE, "implausible_altitude"},
        {DIAG_NATIVE_GPS_DECLINE_JUMP, "implausible_jump"},
    };
    for (size_t i = 0; i < sizeof(kNames) / sizeof(kNames[0]); i++) {
        const char *got = diag_native_gps_decline_name(kNames[i].r);
        if (got == NULL || strcmp(got, kNames[i].want) != 0) {
            printf("  FAIL tracker: decline %d named %s, want %s\n", (int) kNames[i].r,
                   got ? got : "(null)", kNames[i].want);
            ok = false;
        }
    }
    if (diag_native_gps_decline_name(DIAG_NATIVE_GPS_DECLINE_NONE) != NULL) {
        printf("  FAIL tracker: DECLINE_NONE must have no name\n");
        ok = false;
    }
    if (ok)
        printf("  ok   gnss freshness tracker (stale refused, NULL inert, reset, names)\n");
    return ok;
}

/* The cross-record SIB1 map contract.
 *
 * WHY THIS IS HERE AND NOT IN A REPLAY TEST. Changing diag_native_sib1_learn
 * from first-write-wins to LAST-write-wins leaves a replay green: in the replay
 * fixtures no (pci, earfcn) key is ever seen carrying two DIFFERENT SIB1
 * identities, so the two policies are observationally identical there. An
 * end-to-end replay simply cannot distinguish them.
 *
 * The return value can. First-write-wins means a repeated key is a NO-OP,
 * which diag_native_sib1_learn reports as 0 ("ran, inserted nothing"). Last-write-wins overwrites and reports 1. So feeding the
 * SAME record twice separates the policies with no second identity needed --
 * which is what makes this checkable at all without a synthetic capture. */
static bool check_sib1_map_contract(void) {
    bool ok = true;
    uint8_t dummy[64];
    memset(dummy, 0, sizeof(dummy));

    /* The identity-source set is NOT the cell-leg set. 0xB0C0 and 0xB821 are in
     * both: 0xB821 seeds the map (SIB1 identity, MIB scs) for every record, and
     * emits a cell observation only for a UL-DCCH MeasurementReport. Routing identity learning on
     * diag_native_has_leg() alone would still be wrong for any identity-only
     * code, which is why the two predicates stay separate. */
    if (!diag_native_is_identity_source(0xB0C0) ||
            !diag_native_is_identity_source(0xB821)) {
        printf("  FAIL sib1: 0xB0C0 and 0xB821 must both be identity sources\n");
        ok = false;
    }
    if (!diag_native_has_leg(0xB821)) {
        printf("  FAIL sib1: 0xB821 must have a cell-observation leg -- it emits an\n"
               "       NR serving row per MeasurementReport\n");
        ok = false;
    }
    if (diag_native_is_identity_source(0xB193) ||
            diag_native_is_identity_source(0x1476)) {
        printf("  FAIL sib1: a measurement/GNSS code claimed to be an identity source\n");
        ok = false;
    }

    diag_native_sib1_map_t *map = diag_native_sib1_map_new();
    if (map == NULL) {
        printf("  FAIL sib1: map allocation failed\n");
        return false;
    }

    if (diag_native_sib1_map_size(map) != 0) {
        printf("  FAIL sib1: a fresh map is not empty\n"); ok = false;
    }
    /* A non-identity code returns -1 ("not an identity source"), never 0 ("ran,
     * learned nothing") -- the same three-way contract the decode surfaces keep.
     * Collapsing them would make "this code cannot seed identity" indistinguishable
     * from "this record happened not to carry SIB1". */
    if (diag_native_sib1_learn(map, 0xB193, dummy, sizeof(dummy)) != -1) {
        printf("  FAIL sib1: learn() on a non-identity code should return -1\n");
        ok = false;
    }
    /* A real identity code with a garbage payload declines: 0, not -1. */
    if (diag_native_sib1_learn(map, 0xB0C0, dummy, sizeof(dummy)) != 0) {
        printf("  FAIL sib1: learn() on a garbage 0xB0C0 should return 0\n");
        ok = false;
    }
    if (diag_native_sib1_map_size(map) != 0) {
        printf("  FAIL sib1: a declined record still grew the map\n"); ok = false;
    }

    /* The real 0xB0C0 SIB1 record the check() cases above already pin. */
    uint8_t b0c0[1024];
    size_t b0c0_len = unhex(kHex_b0c0_ident_rm520ngl, b0c0, sizeof(b0c0));
    int first = diag_native_sib1_learn(map, 0xB0C0, b0c0, b0c0_len);
    int second = diag_native_sib1_learn(map, 0xB0C0, b0c0, b0c0_len);
    if (first != 1) {
        printf("  FAIL sib1: a SIB1-bearing 0xB0C0 did not insert a key (got %d)\n",
               first);
        ok = false;
    }
    if (second != 0) {
        printf("  FAIL sib1: FIRST-write-wins violated -- re-learning the same key\n"
               "       returned %d, expected 0. First-write-wins makes a repeat\n"
               "       a no-op; last-write-wins reports 1 and is what this\n"
               "       catches\n", second);
        ok = false;
    }
    if (diag_native_sib1_map_size(map) != 1) {
        printf("  FAIL sib1: map size %zu after learning one key twice\n",
               diag_native_sib1_map_size(map));
        ok = false;
    }

    /* Enrichment: a bare measurement on that key gains identity; one on an
     * unknown key does not; and an observation that ALREADY carries identity is
     * left alone (a 0xB0C0 identity row is never enriched). */
    diag_native_obs_t hit;
    memset(&hit, 0, sizeof(hit));
    diag_native_obs_t seed[8];
    int n = diag_native_decode(0xB0C0, b0c0, b0c0_len, seed, 8);
    if (n < 1) {
        printf("  FAIL sib1: could not re-decode the seed record\n");
        ok = false;
    } else {
        hit.pci = seed[0].pci;
        hit.earfcn = seed[0].earfcn;
        if (!diag_native_sib1_enrich(map, &hit)) {
            printf("  FAIL sib1: a measurement on a known (pci=%d, earfcn=%d) was\n"
                   "       not enriched\n", hit.pci, hit.earfcn);
            ok = false;
        } else if (!hit.has_identity || hit.cell_id != seed[0].cell_id ||
                   strcmp(hit.mcc, seed[0].mcc) != 0 ||
                   strcmp(hit.mnc, seed[0].mnc) != 0 || hit.tac != seed[0].tac) {
            printf("  FAIL sib1: enriched fields differ from the seed record\n");
            ok = false;
        }
        /* Re-enriching an already-identity-bearing observation must be a no-op --
         * only MEASUREMENT rows are enriched. */
        if (diag_native_sib1_enrich(map, &hit)) {
            printf("  FAIL sib1: enriched an observation that already had identity\n");
            ok = false;
        }
        diag_native_obs_t miss;
        memset(&miss, 0, sizeof(miss));
        miss.pci = seed[0].pci + 1;
        miss.earfcn = seed[0].earfcn;
        if (diag_native_sib1_enrich(map, &miss) || miss.has_identity) {
            printf("  FAIL sib1: enriched an UNKNOWN key -- identity would be\n"
                   "       fabricated for a cell no SIB1 ever described\n");
            ok = false;
        }
    }

    /* A NULL map must no-op, not crash: allocation failure is explicitly
     * non-fatal in capture_cell_diag.c (capture beats diagnostics). */
    diag_native_obs_t nullcase;
    memset(&nullcase, 0, sizeof(nullcase));
    if (diag_native_sib1_learn(NULL, 0xB0C0, b0c0, b0c0_len) != 0 ||
            diag_native_sib1_enrich(NULL, &nullcase) ||
            diag_native_sib1_map_size(NULL) != 0) {
        printf("  FAIL sib1: a NULL map is not a safe no-op\n");
        ok = false;
    }

    diag_native_sib1_map_free(map);
    diag_native_sib1_map_free(NULL);   /* must tolerate NULL, like free() */

    if (ok)
        printf("  ok   sib1 map contract (source set, -1 vs 0, first-write-wins,\n"
               "       enrich hit/miss/already-identity, NULL-safe)\n");
    return ok;
}

/* ---- LTE MeasurementReport neighbours --------------------------------------
 *
 * The one native output that depends on EARLIER records: a report's neighbours
 * are joined against the measConfig a previous RRCConnectionReconfiguration
 * set up, held in the sib1 map and updated by diag_native_sib1_learn(0xB0C0).
 * The diagspec join itself is pinned by diagspec's own tests; this pins the shim
 * around it -- that learn() feeds the state, that the rows come out flagged and
 * shaped for the renderer, and the -1 / 0 / NULL-map contract.
 *
 * Payloads: real tshark-pinned bodies (a Band 66 reconfiguration whose measId 1
 * carrier is signalled in carrierFreq-v9e0, and a measId 1 report of PCI 114)
 * framed in a v20 0xB0C0 header. A release is its first byte only (DL-DCCH c1 5):
 * the state machine reads nothing else of it. */
static const char *kHex_b0c0_v20_reconfig_b66_v9e0 =
    "140e000064006e14000000000700000000a10020105588c0057fffac901e1c13cb847a68cf6e"
    "21f1853ec0c7e61cfed42018940b4a07c82f989f41bea47d8afb844affffb800414ca07c82f9"
    "89f41bea47d8afb8680030021280e11e001072281f20be627d06fa91f62bee1a000c00c4a13a"
    "b582042482856940f905f313e837d48fb15f70d00060060052050b2e1082e004b7b01011625a"
    "1b8c08b0a105ca000020088021846410ca31a006800d1c055f809c40";
static const char *kHex_b0c0_v20_report_meas_id_1 =
    "140e000064006e1400000000090000000013000830251401c9a93042002148a93124a5a6c4f0";
/* Synthetic (diagspec's MeasurementReport fixture encoder): measId 1, a cgi-Info
 * neighbour PCI 17 (001/01, TAC 0x1234, CI 0x0ABCDE1) and a PCI-only PCI 18. */
static const char *kHex_b0c0_v20_report_cgi =
    "140e000064006e14000000000900000000130008103c50184500100855e6f0891a24e09348a0";
static const char *kHex_b0c0_v20_release =
    "140e000064006e1400000000070000000003002800" "00";

static bool check_lte_meas_neighbours(void) {
    bool ok = true;
    uint8_t rc[512], mr[128], rel[64], cgi[128];
    size_t rc_len = unhex(kHex_b0c0_v20_reconfig_b66_v9e0, rc, sizeof(rc));
    size_t mr_len = unhex(kHex_b0c0_v20_report_meas_id_1, mr, sizeof(mr));
    size_t rel_len = unhex(kHex_b0c0_v20_release, rel, sizeof(rel));
    size_t cgi_len = unhex(kHex_b0c0_v20_report_cgi, cgi, sizeof(cgi));
    diag_native_obs_t got[8];

    diag_native_sib1_map_t *map = diag_native_sib1_map_new();
    if (map == NULL) { printf("  FAIL meas: map allocation\n"); return false; }

    /* Not 0xB0C0: -1, the "not this entry point's code" answer. */
    if (diag_native_lte_meas_neighbours(map, 0xB193, mr, mr_len, got, 8) != -1) {
        printf("  FAIL meas: a non-0xB0C0 code should return -1\n"); ok = false;
    }
    /* Report before any reconfiguration: measId 1 is unmapped, the PCI-only
     * neighbour is omitted -- 0, never a guessed carrier. */
    if (diag_native_lte_meas_neighbours(map, 0xB0C0, mr, mr_len, got, 8) != 0) {
        printf("  FAIL meas: an unmapped report emitted a row\n"); ok = false;
    }
    /* learn() is what feeds the state: the reconfiguration carries no SIB1, so
     * it inserts no identity key (0) and must still configure measId 1. */
    if (diag_native_sib1_learn(map, 0xB0C0, rc, rc_len) != 0) {
        printf("  FAIL meas: a reconfiguration inserted a SIB1 key\n"); ok = false;
    }
    int n = diag_native_lte_meas_neighbours(map, 0xB0C0, mr, mr_len, got, 8);
    if (n != 1) {
        printf("  FAIL meas: mapped report gave %d row(s), want 1\n", n); ok = false;
    } else {
        const diag_native_obs_t *o = &got[0];
        if (!o->meas_neighbour || o->earfcn_absent || o->has_identity ||
                o->is_serving || o->log_code != 0xB0C0 || strcmp(o->rat, "LTE") != 0 ||
                o->pci != 114 || o->earfcn != 66911 ||
                !o->has_rsrp || o->rsrp != -99.0 || !o->has_rsrq || o->rsrq != -14.0) {
            printf("  FAIL meas: row fields (pci %d earfcn %d nb %d absent %d id %d)\n",
                   o->pci, o->earfcn, o->meas_neighbour, o->earfcn_absent,
                   o->has_identity);
            ok = false;
        }
        /* A PCI-only row carries no identity, so SIB1 enrichment may reach it
         * (miss here: the map holds no SIB1 for (114, 66911)). */
        if (diag_native_sib1_enrich(map, &got[0])) {
            printf("  FAIL meas: enrich hit on an empty SIB1 map\n"); ok = false;
        }
    }
    /* Capacity: max_obs 0 writes nothing. */
    if (diag_native_lte_meas_neighbours(map, 0xB0C0, mr, mr_len, got, 0) != 0) {
        printf("  FAIL meas: max_obs 0 should return 0\n"); ok = false;
    }
    /* A NULL map knows no carriers. */
    if (diag_native_lte_meas_neighbours(NULL, 0xB0C0, mr, mr_len, got, 8) != 0) {
        printf("  FAIL meas: a NULL map mapped a carrier\n"); ok = false;
    }
    /* ...but a cgi-Info neighbour keys on its own identity: with no carrier it
     * is still emitted, with NO earfcn and the report's own CGI (so enrich,
     * which skips rows that carry identity, can never overwrite it). The
     * PCI-only neighbour beside it is omitted. */
    n = diag_native_lte_meas_neighbours(NULL, 0xB0C0, cgi, cgi_len, got, 8);
    if (n != 1) {
        printf("  FAIL meas: unmapped CGI report gave %d row(s), want 1\n", n);
        ok = false;
    } else if (!got[0].meas_neighbour || !got[0].earfcn_absent ||
               !got[0].has_identity || got[0].pci != 17 ||
               strcmp(got[0].mcc, "001") != 0 || strcmp(got[0].mnc, "01") != 0 ||
               got[0].tac != 0x1234 || got[0].cell_id != 0x0ABCDE1 ||
               !got[0].has_rsrp || got[0].rsrp != -101.0 || got[0].has_rsrq) {
        printf("  FAIL meas: CGI row (pci %d absent %d id %d mcc %s tac %u)\n",
               got[0].pci, got[0].earfcn_absent, got[0].has_identity, got[0].mcc,
               (unsigned)got[0].tac);
        ok = false;
    }
    /* rrcConnectionRelease clears the measConfig. */
    diag_native_sib1_learn(map, 0xB0C0, rel, rel_len);
    if (diag_native_lte_meas_neighbours(map, 0xB0C0, mr, mr_len, got, 8) != 0) {
        printf("  FAIL meas: a release did not clear the measId map\n"); ok = false;
    }
    diag_native_sib1_map_free(map);

    if (ok)
        printf("  ok   lte meas neighbours (learn feeds the join, -1 vs 0, "
               "release clears, NULL-safe)\n");
    return ok;
}

/* 0xB17F decode: one v0x05 record is one cell with rsrp/rsrq/rssi;
 * a search-mode record (earfcn 0) emits nothing. Payload built by the harness
 * that captured the b17f_enriched_rssi serialization string, with RSRQ in bits
 * 0..9 of u32@20 as the v13 layout has it (raw 0x138 -> -10.5;
 * earlier it sat in bits 20..29, the pre-v13 reading). */
static bool check_b17f_decode(void) {
    static const char *hex =
        "05000000fc08000074060000f2040000000000003801000000f00900000000000000000000000000";
    uint8_t payload[64];
    size_t len = unhex(hex, payload, sizeof(payload));
    diag_native_obs_t got[4];
    int n = diag_native_decode(0xB17F, payload, len, got, 4);
    if (n != 1 || strcmp(got[0].rat, "LTE") != 0 || got[0].log_code != 0xB17F ||
        got[0].pci != 116 || got[0].earfcn != 2300 || got[0].is_serving ||
        !got[0].has_rsrp || got[0].rsrp != -100.875 ||
        !got[0].has_rsrq || got[0].rsrq != -10.5 ||
        !got[0].has_rssi || got[0].rssi != -70.25 || got[0].has_identity) {
        printf("FAIL[b17f_decode]: n=%d pci=%d earfcn=%d rsrp=%g rsrq=%g rssi=%g\n",
               n, n > 0 ? got[0].pci : -1, n > 0 ? got[0].earfcn : -1,
               n > 0 ? got[0].rsrp : 0.0, n > 0 ? got[0].rsrq : 0.0,
               n > 0 ? got[0].rssi : 0.0);
        return false;
    }
    memset(payload + 4, 0, 4);           /* earfcn 0: search mode */
    n = diag_native_decode(0xB17F, payload, len, got, 4);
    if (n != 0) {
        printf("FAIL[b17f_decode]: search-mode record emitted %d obs\n", n);
        return false;
    }
    printf("  ok b17f decode (1 cell with rssi; search mode -> 0)\n");
    return true;
}

/* ---- Serializer parity -------------------------------------------------------
 *
 * diag_native_obs_to_json must reproduce, byte-for-byte, the pinned
 * cell_observation line for each observation -- including the per-code key
 * ordering. The expected strings below are fixed, with fixed
 * IMEI/captured_at/log_tick, so any drift in the renderer fails here.
 *
 * Obs structs are built by hand rather than decoded, so this isolates the RENDER
 * step from the decode legs (which check() already pins) -- a serializer bug and
 * a decode bug cannot mask each other. */

#define SER_IMEI  "000000000000000"
#define SER_CA    1719873600.5
#define SER_LT    60345938315396ULL

static bool check_serialize_one(const char *name, const diag_native_obs_t *o,
                                const char *expect) {
    char buf[1024];
    int n = diag_native_obs_to_json(o, SER_IMEI, SER_CA, SER_LT, buf, sizeof(buf));
    if (n < 0) {
        printf("  FAIL serialize %s: returned -1 (no serialization)\n", name);
        return false;
    }
    if ((size_t)n != strlen(expect) || strcmp(buf, expect) != 0) {
        printf("  FAIL serialize %s:\n    got:  %s\n    want: %s\n", name, buf, expect);
        return false;
    }
    printf("  ok serialize %s (%d bytes)\n", name, n);
    return true;
}

static bool check_serialize(void) {
    bool ok = true;

    /* 0xB193 serving, rsrp+rsrq present (x16 fractional dBm), no identity.
     * prov sits between earfcn and rsrp -- the branch unique to this code. */
    diag_native_obs_t b193s;
    memset(&b193s, 0, sizeof(b193s));
    b193s.rat = "LTE"; b193s.log_code = 0xB193; b193s.pci = 1; b193s.earfcn = 5230;
    b193s.is_serving = true;
    b193s.has_rsrp = true; b193s.rsrp = -105.5625;
    b193s.has_rsrq = true; b193s.rsrq = -11.25;
    ok &= check_serialize_one("b193_serving",  &b193s,
        "{\"rat\":\"LTE\",\"pci\":1,\"earfcn\":5230,\"prov\":{\"src\":\"diag\","
        "\"origin\":\"0xB193\",\"imei\":\"000000000000000\",\"captured_at\":1719873600.5,"
        "\"log_tick\":60345938315396},\"rsrp\":-105.5625,\"rsrq\":-11.25,"
        "\"observation_type\":\"serving\",\"is_serving\":true,\"band\":13,\"duplex\":\"FDD\"}");

    /* 0xB193 neighbour, rsrp/rsrq ABSENT (version without a grounded scale),
     * enriched with SIB1 identity appended last. */
    diag_native_obs_t b193n;
    memset(&b193n, 0, sizeof(b193n));
    b193n.rat = "LTE"; b193n.log_code = 0xB193; b193n.pci = 106; b193n.earfcn = 66536;
    b193n.is_serving = false;
    b193n.has_identity = true;
    strcpy(b193n.mcc, "310"); strcpy(b193n.mnc, "410");
    b193n.tac = 1234; b193n.cell_id = 173696769;
    ok &= check_serialize_one("b193_enriched_norsrp", &b193n,
        "{\"rat\":\"LTE\",\"pci\":106,\"earfcn\":66536,\"prov\":{\"src\":\"diag\","
        "\"origin\":\"0xB193\",\"imei\":\"000000000000000\",\"captured_at\":1719873600.5,"
        "\"log_tick\":60345938315396},\"observation_type\":\"observation\","
        "\"is_serving\":false,\"mcc\":\"310\",\"mnc\":\"410\",\"tac\":1234,"
        "\"cell_id\":173696769,\"band\":66,\"duplex\":\"FDD\"}");

    /* 0x512F GSM SI3: no pci/earfcn, identity inline, tac == lac, prov last,
     * no band/duplex. Synthetic values. A 2-digit
     * MNC keeps its leading zero; a 3-digit one is three characters. */
    diag_native_obs_t gsm2;
    memset(&gsm2, 0, sizeof(gsm2));
    gsm2.rat = "GSM"; gsm2.log_code = 0x512F; gsm2.is_serving = false;
    gsm2.has_identity = true;
    strcpy(gsm2.mcc, "310"); strcpy(gsm2.mnc, "01");
    gsm2.tac = 4660; gsm2.cell_id = 22136;
    ok &= check_serialize_one("512f_si3_mnc2", &gsm2,
        "{\"rat\":\"GSM\",\"mcc\":\"310\",\"mnc\":\"01\",\"lac\":4660,\"tac\":4660,"
        "\"cell_id\":22136,\"observation_type\":\"observation\",\"is_serving\":false,"
        "\"prov\":{\"src\":\"diag\",\"origin\":\"0x512F\",\"imei\":\"000000000000000\","
        "\"captured_at\":1719873600.5,\"log_tick\":60345938315396}}");
    diag_native_obs_t gsm3 = gsm2;
    strcpy(gsm3.mcc, "234"); strcpy(gsm3.mnc, "015");
    gsm3.tac = 1; gsm3.cell_id = 65535;
    ok &= check_serialize_one("512f_si3_mnc3", &gsm3,
        "{\"rat\":\"GSM\",\"mcc\":\"234\",\"mnc\":\"015\",\"lac\":1,\"tac\":1,"
        "\"cell_id\":65535,\"observation_type\":\"observation\",\"is_serving\":false,"
        "\"prov\":{\"src\":\"diag\",\"origin\":\"0x512F\",\"imei\":\"000000000000000\","
        "\"captured_at\":1719873600.5,\"log_tick\":60345938315396}}");

    /* 0xB192 with identity: prov after is_serving, then enrich (mnc keeps its
     * leading zero -- a string, not an int). */
    diag_native_obs_t b192;
    memset(&b192, 0, sizeof(b192));
    b192.rat = "LTE"; b192.log_code = 0xB192; b192.pci = 42; b192.earfcn = 2050;
    b192.is_serving = false;
    b192.has_identity = true;
    strcpy(b192.mcc, "310"); strcpy(b192.mnc, "01");
    b192.tac = 5; b192.cell_id = 7;
    ok &= check_serialize_one("b192_enriched", &b192,
        "{\"rat\":\"LTE\",\"pci\":42,\"earfcn\":2050,\"observation_type\":\"observation\","
        "\"is_serving\":false,\"prov\":{\"src\":\"diag\",\"origin\":\"0xB192\","
        "\"imei\":\"000000000000000\",\"captured_at\":1719873600.5,"
        "\"log_tick\":60345938315396},\"mcc\":\"310\",\"mnc\":\"01\",\"tac\":5,"
        "\"cell_id\":7,\"band\":4,\"duplex\":\"FDD\"}");

    /* 0xB0C0: identity is INLINE (mid-dict) and prov is LAST -- the branch whose
     * key order differs most from the measurement codes. */
    diag_native_obs_t b0c0;
    memset(&b0c0, 0, sizeof(b0c0));
    b0c0.rat = "LTE"; b0c0.log_code = 0xB0C0; b0c0.pci = 7; b0c0.earfcn = 2050;
    b0c0.is_serving = false;
    b0c0.has_identity = true;
    strcpy(b0c0.mcc, "311"); strcpy(b0c0.mnc, "480");
    b0c0.tac = 23130; b0c0.cell_id = 173694465;
    ok &= check_serialize_one("b0c0_inline_identity", &b0c0,
        "{\"rat\":\"LTE\",\"pci\":7,\"earfcn\":2050,\"mcc\":\"311\",\"mnc\":\"480\","
        "\"tac\":23130,\"cell_id\":173694465,\"observation_type\":\"observation\","
        "\"is_serving\":false,\"prov\":{\"src\":\"diag\",\"origin\":\"0xB0C0\","
        "\"imei\":\"000000000000000\",\"captured_at\":1719873600.5,"
        "\"log_tick\":60345938315396},\"band\":4,\"duplex\":\"FDD\"}");

    /* 0xB0C0 MeasurementReport neighbour: its own key order -- prov
     * right after is_serving, THEN earfcn/rsrp/rsrq, then identity. Every LTE
     * string here ends in band/duplex: they are rendered last on every LTE
     * row. */
    diag_native_obs_t b0c0n;
    memset(&b0c0n, 0, sizeof(b0c0n));
    b0c0n.rat = "LTE"; b0c0n.log_code = 0xB0C0; b0c0n.meas_neighbour = true;
    b0c0n.pci = 114; b0c0n.earfcn = 66911;
    b0c0n.has_rsrp = true; b0c0n.rsrp = -99.0;
    b0c0n.has_rsrq = true; b0c0n.rsrq = -14.0;
    ok &= check_serialize_one("b0c0_meas_neighbour", &b0c0n,
        "{\"rat\":\"LTE\",\"pci\":114,\"observation_type\":\"observation\","
        "\"is_serving\":false,\"prov\":{\"src\":\"diag\",\"origin\":\"0xB0C0\","
        "\"imei\":\"000000000000000\",\"captured_at\":1719873600.5,"
        "\"log_tick\":60345938315396},\"earfcn\":66911,\"rsrp\":-99.0,\"rsrq\":-14.0,\"band\":66,\"duplex\":\"FDD\"}");

    /* ...and a cgi-Info neighbour whose measId did not map: NO earfcn key at
     * all, identity from the report itself. */
    diag_native_obs_t b0c0c;
    memset(&b0c0c, 0, sizeof(b0c0c));
    b0c0c.rat = "LTE"; b0c0c.log_code = 0xB0C0; b0c0c.meas_neighbour = true;
    b0c0c.pci = 17; b0c0c.earfcn_absent = true;
    b0c0c.has_rsrp = true; b0c0c.rsrp = -101.0;
    b0c0c.has_identity = true;
    strcpy(b0c0c.mcc, "001"); strcpy(b0c0c.mnc, "01");
    b0c0c.tac = 4660; b0c0c.cell_id = 11259361;
    ok &= check_serialize_one("b0c0_meas_neighbour_cgi_no_earfcn", &b0c0c,
        "{\"rat\":\"LTE\",\"pci\":17,\"observation_type\":\"observation\","
        "\"is_serving\":false,\"prov\":{\"src\":\"diag\",\"origin\":\"0xB0C0\","
        "\"imei\":\"000000000000000\",\"captured_at\":1719873600.5,"
        "\"log_tick\":60345938315396},\"rsrp\":-101.0,\"mcc\":\"001\",\"mnc\":\"01\","
        "\"tac\":4660,\"cell_id\":11259361}");

    /* 0xB195 with an INTEGER-valued rsrp -- pins that json.dumps renders a float
     * -114.0 as "-114.0" (the strip-but-keep-one-digit rule), not "-114". */
    diag_native_obs_t b195;
    memset(&b195, 0, sizeof(b195));
    b195.rat = "LTE"; b195.log_code = 0xB195; b195.pci = 100; b195.earfcn = 900;
    b195.is_serving = false;
    b195.has_rsrp = true; b195.rsrp = -114.0;
    ok &= check_serialize_one("b195_rsrp_integer", &b195,
        "{\"rat\":\"LTE\",\"pci\":100,\"earfcn\":900,\"observation_type\":\"observation\","
        "\"is_serving\":false,\"prov\":{\"src\":\"diag\",\"origin\":\"0xB195\","
        "\"imei\":\"000000000000000\",\"captured_at\":1719873600.5,"
        "\"log_tick\":60345938315396},\"rsrp\":-114.0,\"band\":2,\"duplex\":\"FDD\"}");

    /* 0xB17F: prov after is_serving, then rsrp/rsrq/rssi, then enriched
     * identity, then band/duplex.
     * Captured from result_to_observations(0xB17F, parse_0xb17f(payload)) with
     * a one-entry sib1_map; payload in check_b17f_decode below. */
    diag_native_obs_t b17f;
    memset(&b17f, 0, sizeof(b17f));
    b17f.rat = "LTE"; b17f.log_code = 0xB17F; b17f.pci = 116; b17f.earfcn = 2300;
    b17f.has_rsrp = true; b17f.rsrp = -100.875;
    b17f.has_rsrq = true; b17f.rsrq = -10.5;
    b17f.has_rssi = true; b17f.rssi = -70.25;
    b17f.has_identity = true;
    strcpy(b17f.mcc, "001"); strcpy(b17f.mnc, "001");
    b17f.tac = 4660; b17f.cell_id = 11259361;
    ok &= check_serialize_one("b17f_enriched_rssi", &b17f,
        "{\"rat\":\"LTE\",\"pci\":116,\"earfcn\":2300,\"observation_type\":\"observation\","
        "\"is_serving\":false,\"prov\":{\"src\":\"diag\",\"origin\":\"0xB17F\","
        "\"imei\":\"000000000000000\",\"captured_at\":1719873600.5,"
        "\"log_tick\":60345938315396},\"rsrp\":-100.875,\"rsrq\":-10.5,"
        "\"rssi\":-70.25,\"mcc\":\"001\",\"mnc\":\"001\",\"tac\":4660,"
        "\"cell_id\":11259361,\"band\":4,\"duplex\":\"FDD\"}");

    /* band/duplex edges: an SDL band must read "SDL", never "FDD";
     * an EARFCN in no band (the 4950..5009 hole) gets NEITHER key. */
    diag_native_obs_t sdl;
    memset(&sdl, 0, sizeof(sdl));
    sdl.rat = "LTE"; sdl.log_code = 0xB192; sdl.pci = 3; sdl.earfcn = 9700;
    ok &= check_serialize_one("b192_band29_sdl", &sdl,
        "{\"rat\":\"LTE\",\"pci\":3,\"earfcn\":9700,\"observation_type\":\"observation\","
        "\"is_serving\":false,\"prov\":{\"src\":\"diag\",\"origin\":\"0xB192\","
        "\"imei\":\"000000000000000\",\"captured_at\":1719873600.5,"
        "\"log_tick\":60345938315396},\"band\":29,\"duplex\":\"SDL\"}");
    diag_native_obs_t hole;
    memset(&hole, 0, sizeof(hole));
    hole.rat = "LTE"; hole.log_code = 0xB192; hole.pci = 3; hole.earfcn = 5000;
    ok &= check_serialize_one("b192_band0_omitted", &hole,
        "{\"rat\":\"LTE\",\"pci\":3,\"earfcn\":5000,\"observation_type\":\"observation\","
        "\"is_serving\":false,\"prov\":{\"src\":\"diag\",\"origin\":\"0xB192\","
        "\"imei\":\"000000000000000\",\"captured_at\":1719873600.5,"
        "\"log_tick\":60345938315396}}");

    /* 0xB97F NR serving, rsrp+rsrq present, rat "NR". */
    diag_native_obs_t b97f;
    memset(&b97f, 0, sizeof(b97f));
    b97f.rat = "NR"; b97f.log_code = 0xB97F; b97f.pci = 500; b97f.earfcn = 650000;
    b97f.is_serving = true;
    b97f.has_rsrp = true; b97f.rsrp = -95.9375;
    b97f.has_rsrq = true; b97f.rsrq = -8.0;
    ok &= check_serialize_one("b97f_nr_serving", &b97f,
        "{\"rat\":\"NR\",\"pci\":500,\"earfcn\":650000,\"observation_type\":\"serving\","
        "\"is_serving\":true,\"prov\":{\"src\":\"diag\",\"origin\":\"0xB97F\","
        "\"imei\":\"000000000000000\",\"captured_at\":1719873600.5,"
        "\"log_tick\":60345938315396},\"rsrp\":-95.9375,\"rsrq\":-8.0}");

    /* A code with no cell-observation serialization must decline, not emit an
     * empty/partial line. 0xB197 feeds the cell-config cache, never a row. */
    diag_native_obs_t none;
    memset(&none, 0, sizeof(none));
    none.rat = "LTE"; none.log_code = 0xB197; none.pci = 1; none.earfcn = 1;
    char nb[64];
    if (diag_native_obs_to_json(&none, SER_IMEI, SER_CA, SER_LT, nb, sizeof(nb)) != -1) {
        printf("  FAIL serialize: 0xB197 should return -1 (no observation leg)\n");
        ok = false;
    }

    /* Truncation is reported snprintf-style: too-small buffer -> return >= out_len,
     * and the caller must not emit. */
    char tiny[16];
    int tn = diag_native_obs_to_json(&b193s, SER_IMEI, SER_CA, SER_LT, tiny, sizeof(tiny));
    if (tn < (int)sizeof(tiny)) {
        printf("  FAIL serialize: truncation not reported (got %d, buf %zu)\n",
               tn, sizeof(tiny));
        ok = false;
    }

    printf("%s serialize: pinned bytes across 7 code branches "
           "(+ decline + truncation)\n", ok ? "  ok" : "  FAIL");
    return ok;
}

/* The 0xB197 cell-config cache and the 0xB97F beam keys, through the
 * learn -> attach -> render path the helper runs. The 0xB197 payload is a live
 * RM500Q-AE record (EARFCN 66786 truncated to 1250, PCI 115, 100 RB, 2 ports);
 * diagspec's own tests pin the cache itself. */
static const char *kHex_b197_rm500q = "02643000e20400007342000000000000df050000a4596d0000000000000030a800000200";

static bool check_cell_config_and_beams(void) {
    bool ok = true;
    uint8_t p[64];
    size_t n = unhex(kHex_b197_rm500q, p, sizeof(p));
    diag_native_sib1_map_t *map = diag_native_sib1_map_new();

    if (diag_native_cell_config_learn(map, 0xB193, p, n) != -1) {
        printf("  FAIL cell_config: a non-0xB197 code must return -1\n");
        ok = false;
    }
    if (diag_native_cell_config_learn(map, 0xB197, p, n) != 1) {
        printf("  FAIL cell_config: the RM500Q 0xB197 did not cache\n");
        ok = false;
    }
    if (diag_native_sib1_map_size(map) != 0) {
        printf("  FAIL cell_config: 0xB197 must not add a SIB1 identity\n");
        ok = false;
    }

    /* An NR row is never attached, and must not enter the alias guard. */
    diag_native_obs_t nr;
    memset(&nr, 0, sizeof(nr));
    nr.rat = "NR"; nr.log_code = 0xB97F; nr.pci = 115; nr.earfcn = 1250;
    if (diag_native_lte_cell_config(map, &nr) || nr.has_bandwidth_rb) {
        printf("  FAIL cell_config: attached to an NR row\n");
        ok = false;
    }

    /* The live case: the LTE row carries the FULL earfcn, 0xB197 the low 16. */
    diag_native_obs_t o;
    memset(&o, 0, sizeof(o));
    o.rat = "LTE"; o.log_code = 0xB193; o.pci = 115; o.earfcn = 66786;
    o.is_serving = true;
    if (!diag_native_lte_cell_config(map, &o)) {
        printf("  FAIL cell_config: 66786 did not find the 1250-keyed config\n");
        ok = false;
    }
    ok &= check_serialize_one("b193_cell_config_b66", &o,
        "{\"rat\":\"LTE\",\"pci\":115,\"earfcn\":66786,\"prov\":{\"src\":\"diag\","
        "\"origin\":\"0xB193\",\"imei\":\"000000000000000\",\"captured_at\":1719873600.5,"
        "\"log_tick\":60345938315396},\"observation_type\":\"serving\","
        "\"is_serving\":true,\"band\":66,\"duplex\":\"FDD\",\"bandwidth_rb\":100,"
        "\"bandwidth\":20,\"tx_antennas\":2}");

    /* Alias guard: a second full EARFCN under the same key (B3 1250) gets
     * nothing, and from then on neither does 66786. */
    diag_native_obs_t b3 = o;
    b3.earfcn = 1250; b3.has_bandwidth_rb = false; b3.has_tx_antennas = false;
    diag_native_obs_t again = b3;
    again.earfcn = 66786;
    if (diag_native_lte_cell_config(map, &b3) || diag_native_lte_cell_config(map, &again)) {
        printf("  FAIL cell_config: the alias guard did not drop the config\n");
        ok = false;
    }
    diag_native_sib1_map_free(map);

    /* 0xB97F serving row with an 84-B beam. rsrp/rsrp_a need 7 decimals, which
     * a fixed %.6f renderer would round, and rsrq_a is -43.0, which must keep its .0. */
    diag_native_obs_t b;
    memset(&b, 0, sizeof(b));
    b.rat = "NR"; b.log_code = 0xB97F; b.pci = 160; b.earfcn = 524190;
    b.is_serving = true;
    b.has_rsrp = true; b.rsrp = -108.5078125;
    b.has_rsrq = true; b.rsrq = -15.296875;
    b.has_beam = true; b.beam_ssb_index = 4;
    b.has_beam_rsrp_a = true; b.beam_rsrp_a = -84.1640625;
    b.has_beam_rsrp_b = true; b.beam_rsrp_b = -86.1796875;
    b.has_beam_rsrq_a = true; b.beam_rsrq_a = -43.0;
    b.has_beam_rsrq_b = true; b.beam_rsrq_b = -16.2265625;
    b.has_serving_ssb_index = true; b.serving_ssb_index = 4;
    b.has_ssb_periodicity_ms = true; b.ssb_periodicity_ms = 20;
    ok &= check_serialize_one("b97f_beams_ssb", &b,
        "{\"rat\":\"NR\",\"pci\":160,\"earfcn\":524190,\"observation_type\":\"serving\","
        "\"is_serving\":true,\"prov\":{\"src\":\"diag\",\"origin\":\"0xB97F\","
        "\"imei\":\"000000000000000\",\"captured_at\":1719873600.5,"
        "\"log_tick\":60345938315396},\"rsrp\":-108.5078125,\"rsrq\":-15.296875,"
        "\"beams\":[{\"ssb_index\":4,\"rsrp_a\":-84.1640625,\"rsrp_b\":-86.1796875,"
        "\"rsrq_a\":-43.0,\"rsrq_b\":-16.2265625}],\"serving_ssb_index\":4,"
        "\"ssb_periodicity_ms\":20}");

    if (ok)
        printf("  ok   0xB197 cell config + 0xB97F beams, learn -> attach -> render\n");
    return ok;
}

/* The live GSMTAP framer through the C surface, against a pinned expected
 * frame for the same payload. */
static bool check_gsmtap_frame(void) {
    bool ok = true;
    static const char *kWant =
        "02040d0013ab0000000003ea0500000068400600312340abcde182352c8020610b"
        "089848c306e38263f42280700964760000000000";
    uint8_t payload[256], want[256], frame[512];
    size_t len = unhex(kHex_b0c0_ident_eg25g_v20, payload, sizeof(payload));
    size_t wlen = unhex(kWant, want, sizeof(want));
    int n = diag_native_gsmtap_frame(0xB0C0, payload, len, frame, sizeof(frame));
    if (n != (int)wlen || memcmp(frame, want, wlen) != 0) {
        printf("FAIL gsmtap_frame: 0xB0C0 frame is %d bytes, want %zu, or differs\n",
               n, wlen);
        ok = false;
    }
    /* Too small an output buffer declines; it never truncates a frame. */
    if (diag_native_gsmtap_frame(0xB0C0, payload, len, frame, wlen - 1) != 0) {
        printf("FAIL gsmtap_frame: a short buffer did not decline\n");
        ok = false;
    }
    /* A payload that does not parse is a decline (0), not "no framer". */
    if (diag_native_gsmtap_frame(0xB0C0, payload, 3, frame, sizeof(frame)) != 0) {
        printf("FAIL gsmtap_frame: a 3-byte 0xB0C0 was not declined\n");
        ok = false;
    }
    /* LTE NAS, synthetic, with pinned frames: an EMM INFORMATION (07 61)
     * behind the NAS-OTA wrapper
     * frames on 0xB0E2 (downlink) and 0xB0ED (uplink flag set); 0xB0E1 frames
     * its protected PDU with the SEC_HEADER sub-type; and an Attach reject
     * with its mandatory EMM cause missing fails the TS 24.301 structure
     * check, so it is declined. */
    static const struct { uint16_t code; const char *in, *want; } nas[] = {
        { 0xB0E2, "010905000761", "020412000000000000000000000000000761" },
        { 0xB0ED, "010905000761", "020412004000000000000000000000000761" },
        { 0xB0E1, "010905002700000000055201c1",
          "020412004000000000000000010000002700000000055201c1" },
        { 0xB0E2, "010905000744", NULL },
    };
    for (size_t i = 0; i < sizeof(nas) / sizeof(nas[0]); i++) {
        uint8_t in[64], w[64];
        size_t il = unhex(nas[i].in, in, sizeof(in));
        int m = diag_native_gsmtap_frame(nas[i].code, in, il, frame, sizeof(frame));
        if (nas[i].want == NULL) {
            if (m != 0) {
                printf("FAIL gsmtap_frame: 0x%04X %s framed (%d), want declined\n",
                       nas[i].code, nas[i].in, m);
                ok = false;
            }
            continue;
        }
        size_t wl = unhex(nas[i].want, w, sizeof(w));
        if (m != (int)wl || memcmp(frame, w, wl) != 0) {
            printf("FAIL gsmtap_frame: 0x%04X %s -> %d bytes, want %zu, or differs\n",
                   nas[i].code, nas[i].in, m, wl);
            ok = false;
        }
    }
    /* A measurement code is no candidate: -1, and every eligible code
     * (0xB0C0 and the five NAS codes) has a framer. */
    if (diag_native_gsmtap_frame(0xB193, payload, len, frame, sizeof(frame)) != -1 ||
            diag_native_has_gsmtap_framer(0xB193)) {
        printf("FAIL gsmtap_frame: 0xB193 claims a native framer\n");
        ok = false;
    }
    static const uint16_t all[] = { 0xB0E1, 0xB0E2, 0xB0E3, 0xB0EC, 0xB0ED };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
        if (!diag_native_has_gsmtap_framer(all[i])) {
            printf("FAIL gsmtap_frame: 0x%04X has no native framer\n", all[i]);
            ok = false;
        }
    }
    if (!diag_native_has_gsmtap_framer(0xB0C0)) {
        printf("FAIL gsmtap_frame: 0xB0C0 has no framer\n");
        ok = false;
    }
    return ok;
}

/* The NR SIB1 cell config: 0xB821 SIB1 -> the map's NR config cache
 * -> an NR row's band / carrier_scs / bandwidth_rb / bandwidth. The record is
 * the fixture nr5g_b821_rm500q_sdx55_v9_sib1.bin (RM500Q-AE SDX55,
 * n41, 245 PRB at 30 kHz = 90 MHz). The variant differs in byte 65 only: its
 * first DL carrierBandwidth is rewritten to 200 PRB, which has no TS 38.101
 * Table 5.3.2-1 entry, so the decode gives no MHz and `bandwidth` must be
 * omitted, not rendered as a sentinel. diagspec's own tests pin the leg at
 * every PDU length; this pins the shim's cache and render. */
static const char *kHex_b821_sib1_rm500q_n41 =
    "090000000f9000cf005ef407002800640002020000007b006e80160a0800c00400d158048d15"
    "9e282623490423a001c8c9f138000c50010810c04b082802200002f46407330f9b8201000000"
    "8400020834601440350a22010400005e9e3901ccda41203bd81aa8332012017bc11b84370c6e"
    "20dc51b8c37206e48df64be20fac78809300330118080c020100001395ee430000";
static const char *kHex_b821_sib1_rm500q_n41_nrb200 =
    "090000000f9000cf005ef407002800640002020000007b006e80160a0800c00400d158048d15"
    "9e282623490423a001c8c9f138000c50010810c04b082802200002c76407330f9b8201000000"
    "8400020834601440350a22010400005e9e3901ccda41203bd81aa8332012017bc11b84370c6e"
    "20dc51b8c37206e48df64be20fac78809300330118080c020100001395ee430000";

/* Render obs and require the line to END with `tail` (the identity keys before
 * it are the record's own and pinned elsewhere). */
static bool check_render_tail(const char *name, const diag_native_obs_t *o,
                              const char *tail) {
    char buf[1024];
    int n = diag_native_obs_to_json(o, SER_IMEI, SER_CA, SER_LT, buf, sizeof(buf));
    size_t tl = strlen(tail);
    if (n < 0 || (size_t)n >= sizeof(buf) || (size_t)n < tl ||
            strcmp(buf + n - tl, tail) != 0) {
        printf("  FAIL nr_cell_config %s:\n    got:  %s\n    want: ...%s\n",
               name, n < 0 ? "(-1)" : buf, tail);
        return false;
    }
    return true;
}

static bool check_nr_cell_config(void) {
    bool ok = true;
    uint8_t sib1[256], nrb200[256];
    size_t sib1_len = unhex(kHex_b821_sib1_rm500q_n41, sib1, sizeof(sib1));
    size_t nrb200_len = unhex(kHex_b821_sib1_rm500q_n41_nrb200, nrb200, sizeof(nrb200));
    diag_native_sib1_map_t *map = diag_native_sib1_map_new();

    /* The n41 serving cell, as a later 0xB97F would report it. */
    diag_native_obs_t row;
    memset(&row, 0, sizeof(row));
    row.rat = "NR"; row.log_code = 0xB97F; row.pci = 207; row.earfcn = 521310;
    row.is_serving = true;

    if (diag_native_sib1_learn(map, 0xB821, sib1, sib1_len) != 1) {
        printf("  FAIL nr_cell_config: the n41 SIB1 did not insert its identity\n");
        ok = false;
    }
    diag_native_obs_t a = row;
    (void)diag_native_sib1_enrich(map, &a);
    if (!a.has_nr_band || a.nr_band != 41 || !a.has_nr_carrier_scs ||
            a.nr_carrier_scs != 30 || !a.has_nr_bandwidth_rb ||
            a.nr_bandwidth_rb != 245 || !a.has_nr_bandwidth || a.nr_bandwidth != 90) {
        printf("  FAIL nr_cell_config: the n41 row did not get band 41, 30 kHz, "
               "245 PRB, 90 MHz\n");
        ok = false;
    }
    ok &= check_render_tail("n41_full", &a,
        ",\"band\":41,\"carrier_scs\":30,\"bandwidth_rb\":245,\"bandwidth\":90}");

    /* A different cell gets nothing; so does an LTE row on the SAME
     * (pci, earfcn) -- it may pick up the shared identity, never the NR config. */
    diag_native_obs_t other = row;
    other.pci = 208;
    (void)diag_native_sib1_enrich(map, &other);
    diag_native_obs_t lte = row;
    lte.rat = "LTE"; lte.log_code = 0xB193;
    (void)diag_native_sib1_enrich(map, &lte);
    if (other.has_nr_band || other.has_nr_bandwidth_rb || lte.has_nr_band ||
            lte.has_nr_carrier_scs || lte.has_nr_bandwidth_rb || lte.has_nr_bandwidth) {
        printf("  FAIL nr_cell_config: config attached to another cell or an LTE row\n");
        ok = false;
    }
    diag_native_sib1_map_free(map);

    /* Non-table N_RB, learned first: bandwidth_rb rides and `bandwidth` is
     * ABSENT. The complete SIB1 learned after it changes nothing: one snapshot
     * per cell, first write wins. */
    map = diag_native_sib1_map_new();
    if (diag_native_sib1_learn(map, 0xB821, nrb200, nrb200_len) != 1 ||
            diag_native_sib1_learn(map, 0xB821, sib1, sib1_len) != 0) {
        printf("  FAIL nr_cell_config: the 200-PRB variant then the original did not "
               "learn 1 then 0\n");
        ok = false;
    }
    diag_native_obs_t b = row;
    (void)diag_native_sib1_enrich(map, &b);
    if (!b.has_nr_bandwidth_rb || b.nr_bandwidth_rb != 200 || b.has_nr_bandwidth) {
        printf("  FAIL nr_cell_config: 200 PRB must ride with no MHz (got rb %d/%d, "
               "MHz %d/%d)\n", b.has_nr_bandwidth_rb, b.nr_bandwidth_rb,
               b.has_nr_bandwidth, b.nr_bandwidth);
        ok = false;
    }
    ok &= check_render_tail("nrb200_no_mhz", &b,
        ",\"band\":41,\"carrier_scs\":30,\"bandwidth_rb\":200}");
    diag_native_sib1_map_free(map);

    /* Key order on the one NR row that carries everything: identity, scs, then
     * the config, as _enrich -> add_nr_scs -> add_nr_cell_config emit them. A
     * field the SIB1 did not bind is skipped on its own. */
    diag_native_obs_t m;
    memset(&m, 0, sizeof(m));
    m.rat = "NR"; m.log_code = 0xB821; m.pci = 7; m.earfcn = 632064;
    m.is_serving = true;
    m.has_sinr = true; m.sinr = 12.5;
    m.has_scs = true; m.scs = 30;
    m.has_nr_carrier_scs = true; m.nr_carrier_scs = 30;
    m.has_nr_bandwidth_rb = true; m.nr_bandwidth_rb = 273;
    m.has_nr_bandwidth = true; m.nr_bandwidth = 100;
    ok &= check_serialize_one("b821_nr_cell_config_no_band", &m,
        "{\"rat\":\"NR\",\"pci\":7,\"earfcn\":632064,\"observation_type\":\"serving\","
        "\"is_serving\":true,\"prov\":{\"src\":\"diag\",\"origin\":\"0xB821\","
        "\"imei\":\"000000000000000\",\"captured_at\":1719873600.5,"
        "\"log_tick\":60345938315396},\"sinr\":12.5,\"scs\":30,\"carrier_scs\":30,"
        "\"bandwidth_rb\":273,\"bandwidth\":100}");

    if (ok)
        printf("  ok   NR SIB1 cell config: learn -> attach -> render, absent MHz, "
               "first write wins, no LTE leak\n");
    return ok;
}

/* ---- Cell security events -------------------------------------------------
 *
 * PDUs are built bit by bit from the TS 36.331 / 24.301 layouts and framed in
 * a v20 0xB0C0 header (PCI 100, EARFCN 5230) or a 4-byte EMM OTA header. The
 * SIB1 uses the 001/01 test PLMN. */
typedef struct {
    uint8_t b[64];
    size_t bits;
} bitw_t;

static void bw(bitw_t *w, uint64_t v, int n) {
    for (int i = n - 1; i >= 0; i--) {
        if (w->bits / 8 >= sizeof(w->b))
            return;
        if ((v >> i) & 1)
            w->b[w->bits / 8] |= (uint8_t)(0x80 >> (w->bits % 8));
        w->bits++;
    }
}

static size_t bw_len(const bitw_t *w, size_t min_len) {
    size_t n = (w->bits + 7) / 8;
    return n < min_len ? min_len : n;
}

static size_t b0c0_v20(uint8_t chan, const uint8_t *pdu, size_t pdu_len,
                       uint8_t *out, size_t out_sz) {
    static const uint8_t head[12] = {0x14, 0x0e, 0x00, 0x00, 0x64, 0x00, 0x6e, 0x14,
                                     0x00, 0x00, 0x00, 0x00};
    if (19 + pdu_len > out_sz)
        return 0;
    memcpy(out, head, 12);
    out[12] = chan;
    memset(out + 13, 0, 4);
    out[17] = (uint8_t)(pdu_len & 0xff);
    out[18] = (uint8_t)(pdu_len >> 8);
    memcpy(out + 19, pdu, pdu_len);
    return 19 + pdu_len;
}

#define V20_BCCH_DL_SCH 2
#define V20_DL_DCCH     7
#define V20_UL_CCCH     8

static char sec_lines[8][1024];
static int sec_count;

static void sec_collect(void *ctx, const char *json) {
    (void)ctx;
    if (sec_count < 8)
        snprintf(sec_lines[sec_count], sizeof(sec_lines[0]), "%s", json);
    sec_count++;
}

static int sec_feed(diag_native_security_t *st, uint16_t code, const uint8_t *p, size_t n) {
    sec_count = 0;
    memset(sec_lines, 0, sizeof(sec_lines));
    return diag_native_security_feed(st, code, p, n, "000000000000000", 1.5, 7,
                                     sec_collect, NULL);
}

static size_t smc_pdu(uint8_t *out, int cipher, int integ) {
    bitw_t w;
    memset(&w, 0, sizeof(w));
    bw(&w, 0, 1); bw(&w, 6, 4);          /* DL-DCCH c1 securityModeCommand */
    bw(&w, 1, 2);                        /* transaction id */
    bw(&w, 0, 1); bw(&w, 0, 2);          /* c1, securityModeCommand-r8 */
    bw(&w, 0, 1);                        /* no nonCriticalExtension */
    bw(&w, 0, 1);                        /* SecurityConfigSMC extension bit */
    bw(&w, 0, 1); bw(&w, (uint64_t)cipher, 3);
    bw(&w, 0, 1); bw(&w, (uint64_t)integ, 3);
    size_t n = bw_len(&w, 3);
    memcpy(out, w.b, n);
    return n;
}

static size_t release_pdu(uint8_t *out, int rat_choice, uint64_t arfcn, int arfcn_bits) {
    bitw_t w;
    memset(&w, 0, sizeof(w));
    bw(&w, 0, 1); bw(&w, 5, 4);          /* DL-DCCH c1 rrcConnectionRelease */
    bw(&w, 0, 2);
    bw(&w, 0, 1); bw(&w, 0, 2);          /* c1, rrcConnectionRelease-r8 */
    bw(&w, rat_choice >= 0 ? 4 : 0, 3);  /* redirectedCarrierInfo present */
    bw(&w, 1, 2);                        /* releaseCause other */
    if (rat_choice >= 0) {
        bw(&w, 0, 1); bw(&w, (uint64_t)rat_choice, 3);
        bw(&w, arfcn, arfcn_bits);
        if (rat_choice == 1) {
            bw(&w, 0, 1);                /* dcs1800 */
            bw(&w, 0, 2);                /* followingARFCNs explicitList */
            bw(&w, 0, 5);                /* empty */
        }
    }
    size_t n = bw_len(&w, 4);
    memcpy(out, w.b, n);
    return n;
}

static size_t sib1_pdu(uint8_t *out, int sched_count) {
    bitw_t w;
    memset(&w, 0, sizeof(w));
    bw(&w, 0, 1); bw(&w, 1, 1);          /* BCCH-DL-SCH c1 SIB1 */
    bw(&w, 0, 3);                        /* no p-Max, tdd-Config, extension */
    bw(&w, 0, 1);                        /* no csg-Identity */
    bw(&w, 0, 3);                        /* one PLMN */
    bw(&w, 1, 1); bw(&w, 0, 4); bw(&w, 0, 4); bw(&w, 1, 4);   /* MCC 001 */
    bw(&w, 0, 1); bw(&w, 0, 4); bw(&w, 1, 4);                 /* MNC 01 */
    bw(&w, 1, 1);                        /* notReserved */
    bw(&w, 0x1234, 16);                  /* TAC */
    bw(&w, 0x0ABCDE1, 28);               /* cellIdentity */
    bw(&w, 1, 1); bw(&w, 0, 1); bw(&w, 0, 1);
    bw(&w, 0, 1); bw(&w, 6, 6);          /* cellSelectionInfo */
    bw(&w, 1, 6);                        /* band 2 */
    bw(&w, (uint64_t)(sched_count - 1), 5);
    for (int i = 0; i < 8; i++)
        bw(&w, 0, 8);                    /* the SchedulingInfo bodies and the rest */
    size_t n = bw_len(&w, 10);
    memcpy(out, w.b, n);
    return n;
}

static size_t emm_record(const uint8_t *nas, size_t nas_len, uint8_t *out) {
    static const uint8_t head[4] = {0x01, 0x09, 0x05, 0x00};
    memcpy(out, head, 4);
    memcpy(out + 4, nas, nas_len);
    return 4 + nas_len;
}

static bool sec_expect(const char *what, int got, int want, const char *needle) {
    if (got != want || sec_count != want) {
        printf("  FAIL security %s: %d events (%d emitted), want %d\n", what, got,
               sec_count, want);
        return false;
    }
    if (needle != NULL && strstr(sec_lines[0], needle) == NULL) {
        printf("  FAIL security %s: '%s' not in %s\n", what, needle, sec_lines[0]);
        return false;
    }
    return true;
}

static bool check_security_events(void) {
    bool ok = true;
    uint8_t pdu[64], rec[128];
    size_t n;

    diag_native_security_t *st = diag_native_security_new();
    if (st == NULL) {
        printf("  FAIL security: allocation\n");
        return false;
    }

    ok &= diag_native_is_security_source(0xB0C0) && diag_native_is_security_source(0xB0EC) &&
          diag_native_is_security_source(0xB0ED) && !diag_native_is_security_source(0xB193);
    ok &= diag_native_security_feed(NULL, 0xB0C0, pdu, 1, "", 0, 0, sec_collect, NULL) == -1;
    ok &= sec_feed(st, 0xB193, pdu, 1) == 0;

    /* RRC SecurityModeCommand */
    n = b0c0_v20(V20_DL_DCCH, pdu, smc_pdu(pdu, 0, 2), rec, sizeof(rec));
    ok &= sec_expect("rrc eea0", sec_feed(st, 0xB0C0, rec, n), 1,
            "{\"schema\":\"cell-security/1\",\"event\":\"null_security\",\"layer\":\"rrc\","
            "\"rat\":\"LTE\",\"pci\":100,\"earfcn\":5230,\"ciphering\":\"eea0\","
            "\"integrity\":\"eia2\",\"prov\":{\"src\":\"diag\",\"origin\":\"0xB0C0\"");
    n = b0c0_v20(V20_DL_DCCH, pdu, smc_pdu(pdu, 2, 0), rec, sizeof(rec));
    ok &= sec_expect("rrc eia0", sec_feed(st, 0xB0C0, rec, n), 1,
                     "\"ciphering\":\"eea2\",\"integrity\":\"eia0\"");
    n = b0c0_v20(V20_DL_DCCH, pdu, smc_pdu(pdu, 2, 2), rec, sizeof(rec));
    ok &= sec_expect("rrc eea2/eia2", sec_feed(st, 0xB0C0, rec, n), 0, NULL);
    /* A PDU cut before the algorithms would read them as zeros: eea0/eia0 */
    smc_pdu(pdu, 2, 2);
    n = b0c0_v20(V20_DL_DCCH, pdu, 1, rec, sizeof(rec));
    ok &= sec_expect("rrc truncated smc", sec_feed(st, 0xB0C0, rec, n), 0, NULL);
    /* The same bits on another channel are not an SMC */
    n = b0c0_v20(V20_UL_CCCH + 1, pdu, smc_pdu(pdu, 0, 0), rec, sizeof(rec));
    ok &= sec_expect("smc on UL-DCCH", sec_feed(st, 0xB0C0, rec, n), 0, NULL);

    /* RRCConnectionRelease */
    n = b0c0_v20(V20_DL_DCCH, pdu, release_pdu(pdu, 1, 512, 10), rec, sizeof(rec));
    ok &= sec_expect("geran redirect", sec_feed(st, 0xB0C0, rec, n), 1,
            "\"event\":\"redirect\",\"layer\":\"rrc\",\"rat\":\"LTE\",\"pci\":100,"
            "\"earfcn\":5230,\"redirect\":\"geran\",\"release_cause\":\"other\","
            "\"redirect_arfcn\":512");
    n = b0c0_v20(V20_DL_DCCH, pdu, release_pdu(pdu, 0, 5230, 16), rec, sizeof(rec));
    ok &= sec_expect("eutra redirect", sec_feed(st, 0xB0C0, rec, n), 1,
                     "\"redirect\":\"eutra\",\"release_cause\":\"other\",\"redirect_arfcn\":5230");
    n = b0c0_v20(V20_DL_DCCH, pdu, release_pdu(pdu, -1, 0, 0), rec, sizeof(rec));
    ok &= sec_expect("plain release", sec_feed(st, 0xB0C0, rec, n), 0, NULL);

    /* SIB1 schedulingInfoList, reported once per cell */
    n = b0c0_v20(V20_BCCH_DL_SCH, pdu, sib1_pdu(pdu, 1), rec, sizeof(rec));
    ok &= sec_expect("sib1 one SI", sec_feed(st, 0xB0C0, rec, n), 1,
            "\"event\":\"incomplete_sib1\",\"layer\":\"rrc\",\"rat\":\"LTE\",\"pci\":100,"
            "\"earfcn\":5230,\"mcc\":\"001\",\"mnc\":\"01\",\"tac\":4660,"
            "\"cell_id\":11259361,\"scheduling_info_count\":1");
    ok &= sec_expect("sib1 repeat", sec_feed(st, 0xB0C0, rec, n), 0, NULL);
    n = b0c0_v20(V20_BCCH_DL_SCH, pdu, sib1_pdu(pdu, 4), rec, sizeof(rec));
    ok &= sec_expect("sib1 four SIs", sec_feed(st, 0xB0C0, rec, n), 0, NULL);

    /* Real SIB1s schedule several SI messages */
    n = unhex(kHex_b0c0_ident_eg25g_v20, rec, sizeof(rec));
    ok &= sec_expect("real sib1 v20", sec_feed(st, 0xB0C0, rec, n), 0, NULL);
    n = unhex(kHex_b0c0_ident_rm520ngl, rec, sizeof(rec));
    ok &= sec_expect("real sib1 v27", sec_feed(st, 0xB0C0, rec, n), 0, NULL);

    /* NAS: SMC, plain and inside an integrity-protected header */
    static const uint8_t nas_smc_eea0[] = {0x07, 0x5D, 0x02, 0x00, 0x02, 0xE0, 0xE0};
    n = emm_record(nas_smc_eea0, sizeof(nas_smc_eea0), rec);
    ok &= sec_expect("nas eea0", sec_feed(st, 0xB0EC, rec, n), 1,
            "\"event\":\"null_security\",\"layer\":\"nas\",\"rat\":\"LTE\",\"pci\":100,"
            "\"earfcn\":5230,\"ciphering\":\"eea0\",\"integrity\":\"eia2\"");
    static const uint8_t nas_smc_prot[] = {0x37, 0x11, 0x22, 0x33, 0x44, 0x00,
                                           0x07, 0x5D, 0x20, 0x00, 0x02, 0xE0, 0xE0};
    n = emm_record(nas_smc_prot, sizeof(nas_smc_prot), rec);
    ok &= sec_expect("nas protected eia0", sec_feed(st, 0xB0EC, rec, n), 1,
                     "\"ciphering\":\"eea2\",\"integrity\":\"eia0\"");
    static const uint8_t nas_smc_ok[] = {0x07, 0x5D, 0x22, 0x00, 0x02, 0xE0, 0xE0};
    n = emm_record(nas_smc_ok, sizeof(nas_smc_ok), rec);
    ok &= sec_expect("nas eea2", sec_feed(st, 0xB0EC, rec, n), 0, NULL);
    n = emm_record(nas_smc_eea0, 4, rec);
    ok &= sec_expect("nas short smc", sec_feed(st, 0xB0EC, rec, n), 0, NULL);
    /* An uplink SMC is not one the network sent */
    n = emm_record(nas_smc_eea0, sizeof(nas_smc_eea0), rec);
    ok &= sec_expect("nas uplink smc", sec_feed(st, 0xB0ED, rec, n), 0, NULL);

    /* Identity requests. The plain release above left the state disconnected. */
    static const uint8_t id_req_imsi[] = {0x07, 0x55, 0x01};
    static const uint8_t auth_resp[] = {0x07, 0x53, 0x08, 0, 0, 0, 0, 0, 0, 0, 0};
    static const uint8_t attach_req[] = {0x07, 0x41, 0x71, 0x0b};
    static const uint8_t attach_rej_8[] = {0x07, 0x44, 0x08};
    static const uint8_t conn_req[] = {0x40, 0x00, 0x00, 0x00, 0x00, 0x00};
    n = emm_record(id_req_imsi, sizeof(id_req_imsi), rec);
    ok &= sec_expect("id after disconnect", sec_feed(st, 0xB0EC, rec, n), 1,
            "\"event\":\"identity_request\",\"layer\":\"nas\",\"rat\":\"LTE\",\"pci\":100,"
            "\"earfcn\":5230,\"reason\":\"no_connection_request\",\"identity_type\":\"IMSI\"");

    n = b0c0_v20(V20_UL_CCCH, conn_req, sizeof(conn_req), rec, sizeof(rec));
    ok &= sec_expect("connection request", sec_feed(st, 0xB0C0, rec, n), 0, NULL);
    n = emm_record(attach_req, sizeof(attach_req), rec);
    ok &= sec_expect("attach request", sec_feed(st, 0xB0ED, rec, n), 0, NULL);
    n = emm_record(id_req_imsi, sizeof(id_req_imsi), rec);
    ok &= sec_expect("id during attach", sec_feed(st, 0xB0EC, rec, n), 0, NULL);
    n = emm_record(auth_resp, sizeof(auth_resp), rec);
    ok &= sec_expect("auth response", sec_feed(st, 0xB0ED, rec, n), 0, NULL);
    n = emm_record(id_req_imsi, sizeof(id_req_imsi), rec);
    ok &= sec_expect("id after auth", sec_feed(st, 0xB0EC, rec, n), 1,
                     "\"reason\":\"after_auth\",\"identity_type\":\"IMSI\"");
    /* Still in the identity request: a release now is a disconnect without auth */
    n = b0c0_v20(V20_DL_DCCH, pdu, release_pdu(pdu, -1, 0, 0), rec, sizeof(rec));
    ok &= sec_expect("release after id", sec_feed(st, 0xB0C0, rec, n), 1,
                     "\"reason\":\"disconnect_without_auth\"");

    n = b0c0_v20(V20_UL_CCCH, conn_req, sizeof(conn_req), rec, sizeof(rec));
    sec_feed(st, 0xB0C0, rec, n);
    n = emm_record(id_req_imsi, sizeof(id_req_imsi), rec);
    sec_feed(st, 0xB0EC, rec, n);
    n = emm_record(attach_rej_8, sizeof(attach_rej_8), rec);
    ok &= sec_expect("attach reject #8", sec_feed(st, 0xB0EC, rec, n), 1,
                     "\"reason\":\"attach_reject_without_auth\"");

    /* Garbage never decodes to an event */
    for (size_t len = 0; len < 40; len++) {
        uint8_t junk[40];
        for (size_t i = 0; i < len; i++)
            junk[i] = (uint8_t)(i * 37 + len);
        sec_feed(st, 0xB0C0, junk, len);
        sec_feed(st, 0xB0EC, junk, len);
        sec_feed(st, 0xB0ED, junk, len);
    }

    diag_native_security_free(st);
    if (ok)
        printf("  ok security events\n");
    return ok;
}

int main(void) {
    bool ok = true;

    uint16_t codes[16];
    size_t n_codes = diag_native_codes(codes, 16);
    printf("native legs: %zu (", n_codes);
    for (size_t i = 0; i < n_codes && i < 16; i++)
        printf("%s0x%04X", i ? " " : "", codes[i]);
    printf(")\n");

    ok &= check("b192_rm520ngl_sdx62", 0xB192, kHex_b192_rm520ngl_sdx62, kExp_b192_rm520ngl_sdx62,
                sizeof(kExp_b192_rm520ngl_sdx62) / sizeof(kExp_b192_rm520ngl_sdx62[0]));
    ok &= check("b192_eg25g_mdm9207", 0xB192, kHex_b192_eg25g_mdm9207, kExp_b192_eg25g_mdm9207,
                sizeof(kExp_b192_eg25g_mdm9207) / sizeof(kExp_b192_eg25g_mdm9207[0]));
    ok &= check("b195_lv55_sdx55_168B", 0xB195, kHex_b195_lv55_sdx55_168B, kExp_b195_lv55_sdx55_168B,
                sizeof(kExp_b195_lv55_sdx55_168B) / sizeof(kExp_b195_lv55_sdx55_168B[0]));
    ok &= check("b0c0_ident_eg25g_v20", 0xB0C0, kHex_b0c0_ident_eg25g_v20, kExp_b0c0_ident_eg25g_v20,
                sizeof(kExp_b0c0_ident_eg25g_v20) / sizeof(kExp_b0c0_ident_eg25g_v20[0]));
    ok &= check("b0c0_ident_rm520ngl", 0xB0C0, kHex_b0c0_ident_rm520ngl, kExp_b0c0_ident_rm520ngl,
                sizeof(kExp_b0c0_ident_rm520ngl) / sizeof(kExp_b0c0_ident_rm520ngl[0]));
    ok &= check("b97f_rm500q_sdx55_v7", 0xB97F, kHex_b97f_rm500q_sdx55_v7, kExp_b97f_rm500q_sdx55_v7,
                sizeof(kExp_b97f_rm500q_sdx55_v7) / sizeof(kExp_b97f_rm500q_sdx55_v7[0]));
    ok &= check("b97f_rm520ngl_v9", 0xB97F, kHex_b97f_rm520ngl_v9, kExp_b97f_rm520ngl_v9,
                sizeof(kExp_b97f_rm520ngl_v9) / sizeof(kExp_b97f_rm520ngl_v9[0]));
    /* 0xB193 across its three structurally distinct record shapes:
     * bitpacked-with-serving-flag (v59), 12-byte-header multi-cell (v48), and
     * inline-serving-no-array (v18). One arm per shape, so a dispatch regression
     * cannot hide behind the other two. */
    ok &= check("b193_rm520ngl_sdx62_v59", 0xB193, kHex_b193_rm520ngl_sdx62_v59,
                kExp_b193_rm520ngl_sdx62_v59,
                sizeof(kExp_b193_rm520ngl_sdx62_v59) / sizeof(kExp_b193_rm520ngl_sdx62_v59[0]));
    ok &= check("b193_m2000_sdx55_v48_3cell", 0xB193, kHex_b193_m2000_sdx55_v48_3cell,
                kExp_b193_m2000_sdx55_v48_3cell,
                sizeof(kExp_b193_m2000_sdx55_v48_3cell) / sizeof(kExp_b193_m2000_sdx55_v48_3cell[0]));
    ok &= check("b193_eg25g_mdm9207_v18", 0xB193, kHex_b193_eg25g_mdm9207_v18,
                kExp_b193_eg25g_mdm9207_v18,
                sizeof(kExp_b193_eg25g_mdm9207_v18) / sizeof(kExp_b193_eg25g_mdm9207_v18[0]));
    ok &= check_routing_contract();
    ok &= check_capacity_clamp();
    for (size_t i = 0; i < sizeof(kGnssCases) / sizeof(kGnssCases[0]); i++)
        ok &= check_gnss(&kGnssCases[i]);
    ok &= check_gnss_routing_contract();
    ok &= check_gnss_tracker_contract();
    ok &= check_sib1_map_contract();
    ok &= check_lte_meas_neighbours();
    ok &= check_b17f_decode();
    ok &= check_serialize();
    ok &= check_cell_config_and_beams();
    ok &= check_nr_cell_config();
    ok &= check_gsmtap_frame();
    ok &= check_security_events();

    printf("%s\n", ok ? "PASS: all diag_native_decode tests"
                      : "FAIL: diag_native_decode tests");
    return ok ? 0 : 1;
}

#endif /* CELL_SELFTEST */
