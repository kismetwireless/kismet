/* Consistency checks for the wifi_ht_channels table, which the linux wifi,
 * usbwifi, macOS and bladerf helpers use to build hop lists and to accept
 * HT40+/HT40-/VHT80/VHT160 channels.  Every HT40 flag must name a real
 * 802.11 40MHz pair, both channels of a pair must carry it, and the 80MHz
 * and 160MHz flags must match their 802.11 groups and centre frequencies.
 *
 *   tools/unit.sh <tree> test/wifi_ht_channels/ht_table_test.c wifi_ht_channels.c --flavor asan
 */

#include <stdio.h>

#include "../../wifi_ht_channels.h"

static int failures = 0;

#define FAIL(...) do { printf("FAIL " __VA_ARGS__); printf("\n"); failures++; } while (0)

/* 5GHz 40MHz pairs, by lower primary; 165/169 and up need the U-NII-4
 * channels, which aren't in the table */
static const unsigned int pairs40[] = {
    36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157,
};

/* 80MHz and 160MHz groups, by lowest primary */
static const unsigned int groups80[] = { 36, 52, 100, 116, 132, 149 };
static const unsigned int groups160[] = { 36, 100 };

#define NELEM(a) (sizeof(a) / sizeof((a)[0]))

static int exists(unsigned int c) {
    return c > 0 && c <= MAX_WIFI_HT_CHANNEL && wifi_ht_channels[c].chan != 0;
}

static int is_lower40(unsigned int c) {
    unsigned int i;

    for (i = 0; i < NELEM(pairs40); i++)
        if (pairs40[i] == c)
            return 1;

    return 0;
}

/* Lowest primary of the group holding c, or 0 */
static unsigned int group_of(const unsigned int *groups, size_t ngroups, unsigned int width, unsigned int c) {
    unsigned int i;
    unsigned int nchans = width / 20;

    for (i = 0; i < ngroups; i++)
        if (c >= groups[i] && c < groups[i] + nchans * 4 && (c - groups[i]) % 4 == 0)
            return groups[i];

    return 0;
}

static double expect_freq(unsigned int c) {
    if (c >= 1 && c <= 13)
        return 2407 + 5 * c;
    if (c == 14)
        return 2484;
    if (c >= 182)
        return 4000 + 5 * c;
    return 5000 + 5 * c;
}

static void check_entry(unsigned int c) {
    const wifi_channel *w = &wifi_ht_channels[c];
    unsigned int g;

    if (w->chan != c)
        FAIL("[%u]: chan %u", c, w->chan);

    if (w->freq != expect_freq(c))
        FAIL("[%u]: freq %.0f, want %.0f", c, w->freq, expect_freq(c));

    if (c <= 14) {
        if ((w->flags & WIFI_HT_HT40PLUS) && c + 4 > 13)
            FAIL("%uHT40+: no channel %u", c, c + 4);
        if ((w->flags & WIFI_HT_HT40MINUS) && c < 5)
            FAIL("%uHT40-: no channel %u", c, c - 4);
        if (w->flags & (WIFI_HT_HT80 | WIFI_HT_HT160))
            FAIL("[%u]: 80/160MHz flag in 2.4GHz", c);
        return;
    }

    if (c >= 182) {
        if (w->flags & WIFI_HT_MASK)
            FAIL("[%u]: HT flag on a 4.9GHz channel", c);
        return;
    }

    /* Reserved entries are the 40/80/160MHz centres, never tuned as primaries */
    if (w->flags & WIFI_OTHER_RESERVED) {
        if (w->flags & WIFI_HT_MASK)
            FAIL("[%u]: HT flag on a reserved centre channel", c);
        return;
    }

    if ((w->flags & WIFI_HT_HT40PLUS) && !is_lower40(c))
        FAIL("%uHT40+: %u/%u is not a 40MHz channel", c, c, c + 4);

    if ((w->flags & WIFI_HT_HT40MINUS) && !(c >= 4 && is_lower40(c - 4)))
        FAIL("%uHT40-: %u/%u is not a 40MHz channel", c, c - 4, c);

    /* Both primaries of a pair in the table carry its direction */
    if (is_lower40(c) && exists(c + 4)) {
        if (!(w->flags & WIFI_HT_HT40PLUS))
            FAIL("%uHT40+ missing (%u/%u)", c, c, c + 4);
        if (!(wifi_ht_channels[c + 4].flags & WIFI_HT_HT40MINUS))
            FAIL("%uHT40- missing (%u/%u)", c + 4, c, c + 4);
    }

    g = group_of(groups80, NELEM(groups80), 80, c);
    if (w->flags & WIFI_HT_HT80) {
        if (g == 0)
            FAIL("%uVHT80: not in an 80MHz group", c);
        else if (w->freq80 != 5000 + 5 * (g + 6))
            FAIL("%uVHT80: centre %.0f, want %u", c, w->freq80, 5000 + 5 * (g + 6));
    } else if (g != 0) {
        FAIL("%uVHT80 missing (group %u-%u)", c, g, g + 12);
    }

    g = group_of(groups160, NELEM(groups160), 160, c);
    if (w->flags & WIFI_HT_HT160) {
        if (g == 0)
            FAIL("%uVHT160: not in a 160MHz group", c);
        else if (w->freq160 != 5000 + 5 * (g + 14))
            FAIL("%uVHT160: centre %.0f, want %u", c, w->freq160, 5000 + 5 * (g + 14));
    }
}

int main(void) {
    unsigned int c, n = 0;

    for (c = 0; c <= MAX_WIFI_HT_CHANNEL; c++) {
        if (wifi_ht_channels[c].chan == 0 && wifi_ht_channels[c].freq == 0)
            continue;
        check_entry(c);
        n++;
    }

    /* The channels the table must offer, as the hop list builds them */
    if (!(wifi_ht_channels[140].flags & WIFI_HT_HT40PLUS))
        FAIL("140HT40+ not offered");
    if (wifi_ht_channels[140].flags & WIFI_HT_HT40MINUS)
        FAIL("140HT40- offered");
    if (!(wifi_ht_channels[144].flags & WIFI_HT_HT40MINUS))
        FAIL("144HT40- not offered");

    printf("%s: %u entries, %d failed\n", failures ? "FAIL" : "ok", n, failures);

    return failures != 0;
}
