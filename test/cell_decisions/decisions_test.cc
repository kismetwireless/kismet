/* Tests for the cell phy decision layer (phy_cell_decisions.cc): the LTE band and
 * frequency tables, band labelling, and validation of helper JSON.  Synthetic
 * values only.
 *
 *   make test/cell_decisions/decisions_test && test/cell_decisions/decisions_test
 */

#include "config.h"

#include <algorithm>
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "phy_cell_decisions.h"
#include "diagspec/enrichment/cpp/lte_band.h"

using namespace cell_decisions;
using nlohmann::json;

static int failures = 0;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        failures++; \
    } \
} while (0)

/* Counted mismatches print their first few cases */
#define CHECK_N(c, counter, ...) do { \
    if (!(c)) { \
        if ((counter)++ < 5) { \
            fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
            fprintf(stderr, __VA_ARGS__); \
            fprintf(stderr, "\n"); \
        } \
    } \
} while (0)

/* TS 36.101 Table 5.7.3-1 downlink, transcribed separately from the server's
 * tables: band, F_DL_low in kHz, N_Offs-DL, last EARFCN */
struct spec_row { int band; uint64_t flow_khz; uint32_t noffs; uint32_t nmax; };
static constexpr spec_row kSpec[] = {
    {1,2110000,0,599},{2,1930000,600,1199},{3,1805000,1200,1949},{4,2110000,1950,2399},
    {5,869000,2400,2649},{6,875000,2650,2749},{7,2620000,2750,3449},{8,925000,3450,3799},
    {9,1844900,3800,4149},{10,2110000,4150,4749},{11,1475900,4750,4949},{12,729000,5010,5179},
    {13,746000,5180,5279},{14,758000,5280,5379},{17,734000,5730,5849},{18,860000,5850,5999},
    {19,875000,6000,6149},{20,791000,6150,6449},{21,1495900,6450,6599},{22,3510000,6600,7399},
    {23,2180000,7500,7699},{24,1525000,7700,8039},{25,1930000,8040,8689},{26,859000,8690,9039},
    {27,852000,9040,9209},{28,758000,9210,9659},{29,717000,9660,9769},{30,2350000,9770,9869},
    {31,462500,9870,9919},{32,1452000,9920,10359},{33,1900000,36000,36199},{34,2010000,36200,36349},
    {35,1850000,36350,36949},{36,1930000,36950,37549},{37,1910000,37550,37749},{38,2570000,37750,38249},
    {39,1880000,38250,38649},{40,2300000,38650,39649},{41,2496000,39650,41589},{42,3400000,41590,43589},
    {43,3600000,43590,45589},{44,703000,45590,46589},{45,1447000,46590,46789},{46,5150000,46790,54539},
    {47,5855000,54540,55239},{48,3550000,55240,56739},{49,3550000,56740,58239},{50,1432000,58240,59089},
    {51,1427000,59090,59139},{52,3300000,59140,60139},{53,2483500,60140,60254},{54,1670000,60255,60304},
    {65,2110000,65536,66435},{66,2110000,66436,67335},{67,738000,67336,67535},{68,753000,67536,67835},
    {69,2570000,67836,68335},{70,1995000,68336,68585},{71,617000,68586,68935},{72,461000,68936,68985},
    {73,460000,68986,69035},{74,1475000,69036,69465},{75,1432000,69466,70315},{76,1427000,70316,70365},
    {85,728000,70366,70545},{87,420000,70546,70595},{88,422000,70596,70645},{103,757000,70646,70655},
    {106,935000,70656,70705},{111,1820000,73386,73485},
};

static const spec_row *spec_for(uint32_t e) {
    for (const auto& r : kSpec)
        if (e >= r.noffs && e <= r.nmax)
            return &r;
    return nullptr;
}

static const spec_row *spec_band(int b) {
    for (const auto& r : kSpec)
        if (r.band == b)
            return &r;
    return nullptr;
}

/* F_DL = F_DL_low + 0.1 MHz * (EARFCN - N_Offs-DL), in integer kHz */
static uint64_t spec_khz(uint32_t e) {
    auto r = spec_for(e);
    return r ? r->flow_khz + 100ULL * (e - r->noffs) : 0;
}

/* label_band's rule among same-duplex bands that hold the carrier: the wider
 * downlink, then the higher band number */
static bool better(int a, int b) {
    auto ra = spec_band(a), rb = spec_band(b);
    const uint32_t wa = ra->nmax - ra->noffs, wb = rb->nmax - rb->noffs;
    if (wa != wb)
        return wa > wb;
    return a > b;
}

static bool same_duplex(int a, int b) {
    return lte_band_duplex(a) == lte_band_duplex(b);
}

static void test_tables_match_the_helper_and_spec() {
    long helper = 0, coverage = 0, khz = 0, spec = 0;

    for (uint32_t e = 0; e <= 300000; e++) {
        const int s = earfcn_to_band(e);
        CHECK_N(s == lte_band::earfcn_to_band(e), helper,
                "EARFCN %u: server band %d, helper band %d", e, s, lte_band::earfcn_to_band(e));
        const uint64_t k = arfcn_to_khz("LTE", e);
        CHECK_N((s != 0) == (k != 0), coverage,
                "EARFCN %u: band %d but %llu kHz", e, s, (unsigned long long) k);
        CHECK_N(k == spec_khz(e), khz, "EARFCN %u: %llu kHz, TS 36.101 gives %llu",
                e, (unsigned long long) k, (unsigned long long) spec_khz(e));
        auto sr = spec_for(e);
        CHECK_N((sr ? sr->band : 0) == s, spec, "EARFCN %u: band %d, TS 36.101 gives %d",
                e, s, sr ? sr->band : 0);
    }

    CHECK(helper == 0);
    CHECK(coverage == 0);
    CHECK(khz == 0);
    CHECK(spec == 0);
    printf("EARFCN 0..300000: %ld helper, %ld coverage, %ld kHz, %ld band mismatches\n",
            helper, coverage, khz, spec);
}

static void test_duplex_matches_the_helper() {
    long bad = 0;

    /* Every band in the EARFCN table: the helper also classes the reserved
     * bands 15 and 16 as FDD, but no EARFCN reaches them */
    for (int b = -1; b <= 1100; b++) {
        const char *s = lte_duplex_name(lte_band_duplex(b));
        if (spec_band(b) == nullptr) {
            CHECK_N(s == nullptr, bad, "band %d is not in the table but has duplex %s", b, s);
            continue;
        }
        const char *h = lte_band::band_to_duplex(b);
        CHECK_N(s != nullptr && h != nullptr && std::string(s) == h, bad,
                "band %d: server %s, helper %s", b, s ? s : "none", h ? h : "none");
    }
    CHECK(bad == 0);
}

static void test_nr_and_wcdma_frequencies() {
    CHECK(arfcn_to_khz("NR", 0) == 0);
    CHECK(arfcn_to_khz("NR", 599999) == 2999995);
    CHECK(arfcn_to_khz("NR", 600000) == 3000000);
    CHECK(arfcn_to_khz("NR", 2016666) == 3000000 + 1416666ULL * 15);
    CHECK(arfcn_to_khz("NR", 2016667) == 24250080);
    CHECK(arfcn_to_khz("NR", 3279165) == 24250080 + 1262498ULL * 60);
    CHECK(arfcn_to_khz("NR", 3279166) == 0);
    CHECK(arfcn_to_khz("WCDMA", 10700) == 2140000);
    CHECK(arfcn_to_khz("GSM", 100) == 0);
    CHECK(arfcn_to_khz("LTE", 4294967295u) == 0);
}

/* Bands a carrier can be reported under: every band whose EARFCNs reach the
 * same downlink frequency */
static std::map<uint64_t, std::vector<int>> alias_groups() {
    std::map<uint64_t, std::set<int>> by_freq;
    for (const auto& r : kSpec)
        for (uint32_t e = r.noffs; e <= r.nmax; e++)
            by_freq[arfcn_to_khz("LTE", e)].insert(r.band);

    std::map<uint64_t, std::vector<int>> out;
    for (const auto& [f, bands] : by_freq)
        if (f != 0 && bands.size() > 1)
            out[f] = std::vector<int>(bands.begin(), bands.end());
    return out;
}

static void test_label_band_order_independence() {
    long perms = 0, wrong = 0, moved = 0, mixed = 0;
    std::set<std::vector<int>> groups;

    for (const auto& [f, b] : alias_groups()) {
        groups.insert(b);
        const int n = b.size();

        /* Every ordering of every subset of one duplex mode settles on the
         * same band, and re-reporting a band already seen doesn't move it */
        for (int mask = 1; mask < (1 << n); mask++) {
            std::vector<int> sub;
            for (int i = 0; i < n; i++)
                if (mask & (1 << i))
                    sub.push_back(b[i]);
            if (!std::all_of(sub.begin(), sub.end(),
                        [&](int x) { return same_duplex(x, sub[0]); }))
                continue;

            int want = sub[0];
            for (int x : sub)
                if (better(x, want))
                    want = x;

            std::sort(sub.begin(), sub.end());
            do {
                perms++;
                int cur = 0;
                for (int x : sub)
                    cur = label_band("LTE", cur, x, f);
                CHECK_N(cur == want, wrong, "%llu kHz: B%d, want B%d",
                        (unsigned long long) f, cur, want);
                for (int x : sub)
                    CHECK_N(label_band("LTE", cur, x, f) == cur, wrong,
                            "%llu kHz: B%d moved by B%d", (unsigned long long) f, cur, x);
            } while (std::next_permutation(sub.begin(), sub.end()));
        }

        /* Across duplex modes the bands are different carriers: newest wins */
        for (int a : b)
            for (int c : b)
                if (!same_duplex(a, c)) {
                    mixed++;
                    CHECK_N(label_band("LTE", a, c, f) == c, moved,
                            "%llu kHz: B%d then B%d (other duplex) gave B%d",
                            (unsigned long long) f, a, c, label_band("LTE", a, c, f));
                }
    }

    CHECK(wrong == 0);
    CHECK(moved == 0);
    printf("label_band: %zu alias groups, %ld orderings, %ld cross-duplex pairs\n",
            groups.size(), perms, mixed);
}

static void test_label_band_band_edges() {
    long bad = 0;
    for (const auto& a : kSpec)
        for (const auto& b : kSpec) {
            if (a.band == b.band)
                continue;
            for (uint32_t e : {a.noffs, a.nmax}) {
                const uint64_t f = arfcn_to_khz("LTE", e);
                const bool b_holds = f >= spec_khz(b.noffs) && f <= spec_khz(b.nmax);
                const int want = (b_holds && same_duplex(a.band, b.band)) ?
                    (better(a.band, b.band) ? a.band : b.band) : a.band;
                const int got = label_band("LTE", b.band, a.band, f);
                CHECK_N(got == want, bad, "EARFCN %u: current B%d, incoming B%d gave B%d, want B%d",
                        e, b.band, a.band, got, want);
            }
        }
    CHECK(bad == 0);
}

static void test_label_band_cases() {
    /* Same carrier, same duplex: the wider band, either order */
    CHECK(label_band("LTE", 4, 66, 2145000) == 66);
    CHECK(label_band("LTE", 66, 4, 2145000) == 66);
    CHECK(label_band("LTE", 65, 66, 2145000) == 66);
    CHECK(label_band("LTE", 66, 65, 2145000) == 66);
    CHECK(label_band("LTE", 2, 25, 1950000) == 25);
    CHECK(label_band("LTE", 25, 2, 1950000) == 25);
    CHECK(label_band("LTE", 12, 85, 735000) == 85);
    CHECK(label_band("LTE", 17, 12, 735000) == 12);

    /* Different duplex at one frequency: a different carrier, newest wins */
    CHECK(label_band("LTE", 2, 36, 1950000) == 36);     /* {2,25,36} */
    CHECK(label_band("LTE", 36, 2, 1950000) == 2);
    CHECK(label_band("LTE", 25, 36, 1950000) == 36);
    CHECK(label_band("LTE", 7, 41, 2650000) == 41);     /* {7,41} */
    CHECK(label_band("LTE", 41, 7, 2650000) == 7);
    CHECK(label_band("LTE", 12, 44, 735000) == 44);     /* {12,17,44,85} */
    CHECK(label_band("LTE", 44, 85, 735000) == 85);
    CHECK(label_band("LTE", 13, 44, 750000) == 44);     /* {13,44,67} */
    CHECK(label_band("LTE", 67, 13, 750000) == 13);
    CHECK(label_band("LTE", 44, 67, 750000) == 67);
    CHECK(label_band("LTE", 14, 44, 760000) == 44);     /* {14,28,44,68} */
    CHECK(label_band("LTE", 28, 68, 760000) == 28);
    CHECK(label_band("LTE", 68, 28, 760000) == 28);
    CHECK(label_band("LTE", 20, 44, 795000) == 44);     /* {20,28,44} */
    CHECK(label_band("LTE", 44, 20, 795000) == 20);
    CHECK(label_band("LTE", 74, 75, 1480000) == 75);    /* {11,21,50,74,75} */
    CHECK(label_band("LTE", 75, 74, 1480000) == 74);
    CHECK(label_band("LTE", 11, 74, 1480000) == 74);
    CHECK(label_band("LTE", 50, 75, 1480000) == 75);

    /* The cell moved: the frequency is only in the incoming band */
    CHECK(label_band("LTE", 66, 2, 1950000) == 2);

    /* No frequency: keep what is shown, but take a first band */
    CHECK(label_band("LTE", 4, 66, 0) == 4);
    CHECK(label_band("LTE", 66, 4, 0) == 66);
    CHECK(label_band("LTE", 0, 66, 0) == 66);
    CHECK(label_band("LTE", 4, 0, 0) == 4);
    CHECK(label_band("LTE", 4, 41, 0) == 4);

    /* No incoming band leaves the label alone */
    CHECK(label_band("LTE", 66, 0, 2145000) == 66);
    CHECK(label_band("LTE", 66, -5, 2145000) == 66);
    CHECK(label_band("LTE", 0, 0, 2145000) == 0);
    CHECK(label_band("NR", 78, 0, 3500000) == 78);
    CHECK(label_band("LTE", -5, 4, 2145000) == 4);

    /* Bands outside the table: newest wins */
    CHECK(label_band("LTE", 66, 200, 2145000) == 200);
    CHECK(label_band("LTE", 200, 66, 2145000) == 66);

    /* Only LTE has a table: any other RAT takes the newest band */
    CHECK(label_band("NR", 66, 4, 2145000) == 4);
    CHECK(label_band("NR", 66, 4, 0) == 4);
    CHECK(label_band("NR", 77, 78, 3500000) == 78);
    CHECK(label_band("WCDMA", 1, 4, 2140000) == 4);
    CHECK(label_band("", 4, 66, 2145000) == 66);
}

static void test_key_strings() {
    /* The key is the device MAC, so its format is pinned */
    CHECK(derive_key("LTE", plmn_from_digits("001", "01"), 1, 4096, 1, true, 100).key ==
            "00101_1_4096");
    CHECK(derive_key("LTE", plmn_from_digits("001", "01"), -1, 4096, -1, false, 0).key ==
            "00101_0_4096");
    CHECK(derive_key("LTE", plmn_t(), -1, -1, 1, true, 100).key == "LTE_pci1_f2120000");
    CHECK(derive_key("LTE", plmn_t(), -1, -1, 1, true, 2300).key == "LTE_pci1_f2145000");
    CHECK(derive_key("LTE", plmn_t(), -1, -1, 1, true, 66786).key == "LTE_pci1_f2145000");
    CHECK(derive_key("LTE", plmn_t(), -1, -1, 1, true, 4294967295u).key == "LTE_pci1_e4294967295");
    CHECK(derive_key("LTE", plmn_t(), -1, -1, 0, true, 0).key == "LTE_pci0_f2110000");
    CHECK(!derive_key("LTE", plmn_t(), -1, -1, -1, true, 100).valid);
    CHECK(!derive_key("LTE", plmn_t(), -1, -1, 1, false, 0).valid);

    /* A full-identity cell's promotion peer is the partial device's key */
    for (const char *rat : {"LTE", "NR", "WCDMA"}) {
        auto p = pci_promotion(rat, 1, true, 2300, true);
        CHECK(p.active && p.register_self);
        CHECK(p.peer_cell_key == derive_key(rat, plmn_t(), -1, -1, 1, true, 2300).key);
        CHECK(p.map_key == promotion_map_key(rat, 1, 2300));
        CHECK(pci_promotion(rat, 1, true, 2300, false).map_key == p.map_key);
    }
    CHECK(promotion_map_key("LTE", 1, 2300) != promotion_map_key("NR", 1, 2300));
    CHECK(promotion_map_key("LTE", 1, 2300) == promotion_map_key("LTE", 1, 66786));

    /* Both related-device edges, one relationship name */
    auto links = related_links(true);
    CHECK(links.size() == 2);
    if (links.size() == 2) {
        CHECK(links[0].from_self != links[1].from_self);
        CHECK(std::string(links[0].relationship) == links[1].relationship);
    }
    CHECK(related_links(false).empty());
}

static void test_json_validation() {
    /* Hostile numbers are absent, never converted */
    const char *bad_ints[] = {
        "1e30", "-1e30", "2300.9", "-1", "68719476736", "18446744073709551615",
        "9223372036854775808", "-9223372036854775808", "\"2300\"", "null", "true",
        "[1]", "{}", "1.0",
    };
    for (const char *v : bad_ints) {
        auto j = json::parse(std::string("{\"earfcn\":") + v + ",\"pci\":" + v +
                ",\"band\":" + v + ",\"tac\":" + v + ",\"cell_id\":" + v +
                ",\"bandwidth\":" + v + ",\"cqi\":" + v + "}");
        auto f = cell_fields(j);
        CHECK(!f.earfcn && !f.pci && !f.band && !f.tac && !f.cell_id &&
                !f.bandwidth && !f.cqi);
    }

    auto f = cell_fields(json::parse("{}"));
    CHECK(!f.earfcn && !f.pci && !f.band && !f.rsrp);
    for (const char *s : {"[]", "5", "\"x\"", "null"}) {
        auto g = cell_fields(json::parse(s));
        CHECK(!g.earfcn && !g.rsrp && !plmn_from_json(json::parse(s)).present);
    }

    /* Range edges */
    f = cell_fields(json::parse(
            "{\"earfcn\":3279165,\"pci\":1007,\"band\":1024,\"tac\":16777215,"
            "\"cell_id\":68719476735,\"bandwidth\":400,\"cqi\":15}"));
    CHECK(f.earfcn == 3279165 && f.pci == 1007 && f.band == 1024 &&
            f.tac == 16777215 && f.cell_id == 68719476735LL && f.bandwidth == 400 && f.cqi == 15);
    f = cell_fields(json::parse(
            "{\"earfcn\":3279166,\"pci\":1008,\"band\":1025,\"tac\":16777216,"
            "\"cell_id\":68719476736,\"bandwidth\":401,\"cqi\":16}"));
    CHECK(!f.earfcn && !f.pci && !f.band && !f.tac && !f.cell_id && !f.bandwidth && !f.cqi);
    f = cell_fields(json::parse("{\"earfcn\":0,\"pci\":0,\"band\":0,\"tac\":0,\"cell_id\":0,"
            "\"bandwidth\":0,\"cqi\":0}"));
    CHECK(f.earfcn == 0 && f.pci == 0 && !f.band && f.tac == 0 && f.cell_id == 0 &&
            !f.bandwidth && f.cqi == 0);
    CHECK(cell_fields(json::parse("{\"band\":65602}")).band == std::nullopt);
    CHECK(cell_fields(json::parse("{\"band\":4294967362}")).band == std::nullopt);

    /* Signals take floats, truncated toward zero, inside the range */
    f = cell_fields(json::parse("{\"rsrp\":-104.19,\"rsrq\":-10.9,\"sinr\":250,"
            "\"snr\":0.5,\"rssi\":-70}"));
    CHECK(f.rsrp == -104 && f.rsrq == -10 && f.sinr == 250 && f.snr == 0 && f.rssi == -70);
    f = cell_fields(json::parse("{\"rsrp\":-300.9,\"rsrq\":300.9}"));
    CHECK(f.rsrp == -300 && f.rsrq == 300);
    for (const char *v : {"1e30", "-1e30", "-301", "301", "-32768", "32767",
            "18446744073709551615", "\"-90\"", "null", "false"}) {
        auto g = cell_fields(json::parse(std::string("{\"rsrp\":") + v + ",\"rssi\":" + v +
                ",\"sinr\":" + v + ",\"snr\":" + v + ",\"rsrq\":" + v + "}"));
        CHECK(!g.rsrp && !g.rssi && !g.sinr && !g.snr && !g.rsrq);
    }

    /* PLMN: numbers must be in-range integers; strings keep their digits */
    CHECK(plmn_from_json(json::parse("{\"mcc\":\"001\",\"mnc\":\"01\"}")).joined() == "00101");
    CHECK(plmn_from_json(json::parse("{\"mcc\":1,\"mnc\":1}")).joined() == "00101");
    CHECK(plmn_from_json(json::parse("{\"mcc\":\"001\",\"mnc\":1}")).joined() == "00101");
    CHECK(plmn_from_json(json::parse("{\"mcc\":1,\"mnc\":\"01\"}")).joined() == "00101");
    for (const char *s : {
            "{\"mcc\":1e30,\"mnc\":1}", "{\"mcc\":1,\"mnc\":1e30}", "{\"mcc\":1.5,\"mnc\":1}",
            "{\"mcc\":-1,\"mnc\":1}", "{\"mcc\":1000,\"mnc\":1}", "{\"mcc\":1,\"mnc\":-1}",
            "{\"mcc\":18446744073709551615,\"mnc\":1}", "{\"mcc\":\"001\",\"mnc\":1e30}",
            "{\"mcc\":1e30,\"mnc\":\"01\"}", "{\"mcc\":\"99999999999999999999\",\"mnc\":1}",
            "{\"mcc\":\"0x1\",\"mnc\":\"01\"}", "{\"mcc\":1}", "{\"mcc\":null,\"mnc\":null}"})
        CHECK(!plmn_from_json(json::parse(s)).present);
}

int main() {
    test_tables_match_the_helper_and_spec();
    test_duplex_matches_the_helper();
    test_nr_and_wcdma_frequencies();
    test_label_band_order_independence();
    test_label_band_band_edges();
    test_label_band_cases();
    test_key_strings();
    test_json_validation();

    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    printf("all cell decision tests passed\n");
    return 0;
}
