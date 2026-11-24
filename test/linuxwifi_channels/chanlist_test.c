/* Tests for mac80211_build_chanlist (capture_linux_wifi/linux_chanlist.c),
 * which turns the enabled frequencies nl80211 reports into the linux wifi
 * hop list.  HT40, VHT80 and VHT160 channels are offered only when the
 * kernel has every 20MHz channel they cover enabled and doesn't forbid the
 * width: 140HT40+ used to be offered with 144 disabled (older chips, some
 * ETSI domains), and every hop to it failed.
 *
 *   make -C capture_linux_wifi chanlist_test && test/linuxwifi_channels/chanlist_test
 *   tools/unit.sh <tree> test/linuxwifi_channels/chanlist_test.c \
 *       capture_linux_wifi/linux_chanlist.c wifi_ht_channels.c --flavor asan
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../capture_linux_wifi/linux_chanlist.h"
#include "../../capture_linux_wifi/linux_netlink_control.h"

static int failures = 0;

#define ALL_BAND (MAC80211_BAND_HT40 | MAC80211_BAND_HT80 | MAC80211_BAND_HT160)
#define HT_VHT (MAC80211_GET_HT | MAC80211_GET_VHT)

struct phy {
    struct mac80211_freq_info freqs[MAC80211_MAX_FREQS];
    size_t n;
};

struct result {
    char **list;
    size_t n;
    int ret;
};

static unsigned int chan_freq(unsigned int c) {
    if (c == 14)
        return 2484;
    if (c <= 13)
        return 2407 + 5 * c;
    return 5000 + 5 * c;
}

static void add(struct phy *p, unsigned int freq, unsigned int chan, unsigned int band_caps) {
    struct mac80211_freq_info *fi = &p->freqs[p->n++];

    memset(fi, 0, sizeof(*fi));
    fi->freq = freq;
    fi->chan = chan;
    fi->band_caps = band_caps;
}

static void add_chan(struct phy *p, unsigned int c, unsigned int band_caps) {
    add(p, chan_freq(c), c, band_caps);
}

/* 5GHz U-NII-1 to U-NII-3 as the kernel lists them, optionally without one */
static void add_5ghz(struct phy *p, unsigned int skip, unsigned int band_caps) {
    static const unsigned int chans[] = {
        36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
        132, 136, 140, 144, 149, 153, 157, 161, 165,
    };
    size_t i;

    for (i = 0; i < sizeof(chans) / sizeof(chans[0]); i++)
        if (chans[i] != skip)
            add_chan(p, chans[i], band_caps);
}

static void set_flags(struct phy *p, unsigned int chan, unsigned int flags) {
    size_t i;

    for (i = 0; i < p->n; i++)
        if (p->freqs[i].chan == chan && p->freqs[i].freq < 5925)
            p->freqs[i].flags |= flags;
}

static struct result build(const struct phy *p, unsigned int ext, unsigned int def20, unsigned int exp20) {
    struct result r;

    r.ret = mac80211_build_chanlist(p->freqs, p->n, ext, def20, exp20, &r.list, &r.n);
    return r;
}

static void release(struct result *r) {
    size_t i;

    for (i = 0; i < r->n; i++)
        free(r->list[i]);
    free(r->list);
}

static int has(const struct result *r, const char *name) {
    size_t i;

    for (i = 0; i < r->n; i++)
        if (strcmp(r->list[i], name) == 0)
            return 1;

    return 0;
}

static void expect(const char *test, const struct result *r, const char *name, int want) {
    if (has(r, name) != want) {
        printf("FAIL %s: %s %s\n", test, name, want ? "missing" : "offered");
        failures++;
    }
}

static void expect_count(const char *test, const struct result *r, size_t want) {
    if (r->ret < 0 || (size_t) r->ret != r->n || r->n != want) {
        printf("FAIL %s: ret %d, %zu channels, want %zu\n", test, r->ret, r->n, want);
        failures++;
    }
}

static void test_all_enabled(void) {
    struct phy p = { .n = 0 };
    struct result r;

    add_5ghz(&p, 0, ALL_BAND);
    r = build(&p, HT_VHT, 0, 0);

    expect("all", &r, "140HT40+", 1);
    expect("all", &r, "144HT40-", 1);
    expect("all", &r, "140HT40-", 0);
    expect("all", &r, "36HT40+", 1);
    expect("all", &r, "40HT40-", 1);
    expect("all", &r, "64HT40-", 1);
    expect("all", &r, "64HT40+", 0);
    expect("all", &r, "140VHT80", 1);
    expect("all", &r, "144VHT80", 1);
    expect("all", &r, "100VHT160", 1);
    expect("all", &r, "36VHT160", 1);
    expect("all", &r, "149VHT80", 1);
    expect("all", &r, "165HT40+", 0);

    /* Base channel, then its wider ones, in the kernel's order */
    if (r.n < 3 || strcmp(r.list[0], "36") != 0 || strcmp(r.list[1], "36HT40+") != 0 ||
            strcmp(r.list[2], "36VHT80") != 0) {
        printf("FAIL all: list starts %s %s %s\n", r.n > 0 ? r.list[0] : "-",
                r.n > 1 ? r.list[1] : "-", r.n > 2 ? r.list[2] : "-");
        failures++;
    }

    release(&r);
}

static void test_144_disabled(void) {
    struct phy p = { .n = 0 };
    struct result r;

    add_5ghz(&p, 144, ALL_BAND);
    r = build(&p, HT_VHT, 0, 0);

    expect("no144", &r, "140", 1);
    expect("no144", &r, "144", 0);
    expect("no144", &r, "140HT40+", 0);
    expect("no144", &r, "144HT40-", 0);
    expect("no144", &r, "132HT40+", 1);
    expect("no144", &r, "136HT40-", 1);
    expect("no144", &r, "132VHT80", 0);
    expect("no144", &r, "140VHT80", 0);
    expect("no144", &r, "116VHT80", 1);
    expect("no144", &r, "100VHT160", 1);

    release(&r);
}

static void test_no_ht40_plus(void) {
    struct phy p = { .n = 0 };
    struct result r;

    add_5ghz(&p, 0, ALL_BAND);
    set_flags(&p, 140, MAC80211_FREQ_NO_HT40PLUS);
    set_flags(&p, 36, MAC80211_FREQ_NO_HT40PLUS);
    set_flags(&p, 40, MAC80211_FREQ_NO_HT40MINUS);
    r = build(&p, HT_VHT, 0, 0);

    expect("noht40", &r, "140HT40+", 0);
    expect("noht40", &r, "36HT40+", 0);
    expect("noht40", &r, "40HT40-", 0);
    /* The flags are per primary, as the kernel checks them */
    expect("noht40", &r, "144HT40-", 1);
    expect("noht40", &r, "44HT40+", 1);
    /* and don't limit the 80MHz and 160MHz widths */
    expect("noht40", &r, "140VHT80", 1);
    expect("noht40", &r, "36VHT80", 1);
    expect("noht40", &r, "36VHT160", 1);

    release(&r);
}

static void test_no_80_160(void) {
    struct phy p = { .n = 0 };
    struct result r;

    add_5ghz(&p, 0, ALL_BAND);
    /* A covered channel that can't be part of an 80MHz or 160MHz channel
     * rules out the whole block */
    set_flags(&p, 144, MAC80211_FREQ_NO_80MHZ);
    set_flags(&p, 128, MAC80211_FREQ_NO_160MHZ);
    r = build(&p, HT_VHT, 0, 0);

    expect("no80", &r, "132VHT80", 0);
    expect("no80", &r, "136VHT80", 0);
    expect("no80", &r, "140VHT80", 0);
    expect("no80", &r, "144VHT80", 0);
    expect("no80", &r, "140HT40+", 1);
    expect("no80", &r, "116VHT80", 1);
    expect("no160", &r, "100VHT160", 0);
    expect("no160", &r, "100VHT80", 1);
    expect("no160", &r, "128HT40-", 1);
    expect("no160", &r, "36VHT160", 1);

    release(&r);
}

static void test_band_caps(void) {
    struct phy p = { .n = 0 };
    struct result r;

    /* HT40 only: no VHT widths even when asked for */
    add_5ghz(&p, 0, MAC80211_BAND_HT40);
    r = build(&p, HT_VHT, 0, 0);
    expect("ht40only", &r, "140HT40+", 1);
    expect("ht40only", &r, "140VHT80", 0);
    expect("ht40only", &r, "36VHT160", 0);
    release(&r);

    /* No HT requested: base channels only */
    r = build(&p, 0, 0, 0);
    expect_count("noht", &r, 25);
    expect("noht", &r, "140HT40+", 0);
    release(&r);

    /* HT20 by default, or as well */
    r = build(&p, MAC80211_GET_HT, 1, 0);
    expect("ht20", &r, "36HT20", 1);
    expect("ht20", &r, "36", 0);
    release(&r);

    r = build(&p, MAC80211_GET_HT, 0, 1);
    expect("expand", &r, "36HT20", 1);
    expect("expand", &r, "36", 1);
    release(&r);
}

static void test_24ghz(void) {
    struct phy p = { .n = 0 };
    struct result r;
    unsigned int c;

    for (c = 1; c <= 11; c++)
        add_chan(&p, c, MAC80211_BAND_HT40);
    r = build(&p, MAC80211_GET_HT, 0, 0);

    expect("2.4", &r, "1HT40+", 1);
    expect("2.4", &r, "6HT40+", 1);
    expect("2.4", &r, "6HT40-", 1);
    expect("2.4", &r, "11HT40-", 1);
    release(&r);

    /* Channels 1-9 only: 6HT40+ needs 10 */
    p.n = 0;
    for (c = 1; c <= 9; c++)
        add_chan(&p, c, MAC80211_BAND_HT40);
    r = build(&p, MAC80211_GET_HT, 0, 0);

    expect("2.4short", &r, "1HT40+", 1);
    expect("2.4short", &r, "6HT40+", 0);
    expect("2.4short", &r, "6HT40-", 1);
    release(&r);
}

static void test_other_bands(void) {
    struct phy p = { .n = 0 };
    struct result r;

    add(&p, 5955, 1, ALL_BAND);
    add(&p, 5935, 2, ALL_BAND);
    add(&p, 58320, 1, 0);
    add(&p, 4940, 188, 0);
    r = build(&p, HT_VHT, 1, 0);

    expect_count("other", &r, 4);
    expect("other", &r, "1W6e", 1);
    expect("other", &r, "2W6e", 1);
    expect("other", &r, "58320", 1);
    expect("other", &r, "188HT20", 1);
    release(&r);

    p.n = 0;
    r = build(&p, HT_VHT, 0, 0);
    if (r.ret != 0 || r.n != 0 || r.list != NULL) {
        printf("FAIL empty: ret %d n %zu list %p\n", r.ret, r.n, (void *) r.list);
        failures++;
    }
}

int main(void) {
    test_all_enabled();
    test_144_disabled();
    test_no_ht40_plus();
    test_no_80_160();
    test_band_caps();
    test_24ghz();
    test_other_bands();

    printf("%s: %d failed\n", failures ? "FAIL" : "ok", failures);

    return failures != 0;
}
