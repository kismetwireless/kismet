/* Tests for the nl80211 wiphy dump collector in
 * capture_linux_wifi/linux_netlink_control.c (nl80211_freqlist_cb), fed
 * synthetic split dumps without a radio.  A split dump sends a band's HT and
 * VHT capabilities once, ahead of its frequencies, so the collector keeps
 * them across messages; it must not keep them across dumps, or the second
 * radio a helper opens gets the first one's HT40 and VHT widths.
 *
 *   make -C capture_linux_wifi freqlist_dump_test && test/linuxwifi_channels/freqlist_dump_test
 *   tools/unit.sh <tree> test/linuxwifi_channels/freqlist_dump_test.c \
 *       capture_linux_wifi/linux_chanlist.c wifi_ht_channels.c \
 *       --cflags -I/usr/include/libnl3 --libs "-lnl-genl-3 -lnl-3" --flavor asan
 */

/* The collector is static; build it into this test */
#include "../../capture_linux_wifi/linux_netlink_control.c"

#include <stdlib.h>

#if defined(SYS_LINUX) && defined(HAVE_LINUX_NETLINK)

static int failures = 0;

static struct nlattr *nest_start(struct nl_msg *m, int type) {
    struct nlattr *start = (struct nlattr *) nlmsg_tail(nlmsg_hdr(m));

    /* The kernel nests without NLA_F_NESTED (nla_nest_start_noflag) */
    if (nla_put(m, type, 0, NULL) < 0)
        return NULL;

    return start;
}

static void nest_end(struct nl_msg *m, struct nlattr *start) {
    start->nla_len = (unsigned char *) nlmsg_tail(nlmsg_hdr(m)) - (unsigned char *) start;
}

/* One split-dump message: an optional phy name, then one band with optional
 * HT and VHT capabilities and up to one frequency (0 for none) */
static struct nl_msg *wiphy_msg(const char *phy, int band, int ht_capa, int vht_capa,
        unsigned int freq) {
    struct nl_msg *m = nlmsg_alloc();
    struct nlattr *bands, *b, *freqs, *f;

    if (m == NULL)
        return NULL;

    if (genlmsg_put(m, 0, 0, 0x10, 0, 0, NL80211_CMD_NEW_WIPHY, 0) == NULL)
        goto fail;

    if (phy != NULL && nla_put_string(m, NL80211_ATTR_WIPHY_NAME, phy) < 0)
        goto fail;

    if ((bands = nest_start(m, NL80211_ATTR_WIPHY_BANDS)) == NULL)
        goto fail;
    if ((b = nest_start(m, band)) == NULL)
        goto fail;

    if (ht_capa >= 0 && nla_put_u16(m, NL80211_BAND_ATTR_HT_CAPA, (uint16_t) ht_capa) < 0)
        goto fail;
    if (vht_capa >= 0 && nla_put_u32(m, NL80211_BAND_ATTR_VHT_CAPA, (uint32_t) vht_capa) < 0)
        goto fail;

    if ((freqs = nest_start(m, NL80211_BAND_ATTR_FREQS)) == NULL)
        goto fail;

    if (freq != 0) {
        if ((f = nest_start(m, 0)) == NULL)
            goto fail;
        if (nla_put_u32(m, NL80211_FREQUENCY_ATTR_FREQ, freq) < 0)
            goto fail;
        nest_end(m, f);
    }

    nest_end(m, freqs);
    nest_end(m, b);
    nest_end(m, bands);

    return m;

fail:
    nlmsg_free(m);
    return NULL;
}

static void feed(struct nl80211_channel_block *cb, const char *phy, int band, int ht_capa,
        int vht_capa, unsigned int freq) {
    struct nl_msg *m = wiphy_msg(phy, band, ht_capa, vht_capa, freq);

    if (m == NULL) {
        printf("FAIL: could not build a test message\n");
        failures++;
        return;
    }

    nl80211_freqlist_cb(m, cb);
    nlmsg_free(m);
}

static void expect(const char *what, const struct nl80211_channel_block *cb, unsigned int freq,
        int present, unsigned int band_caps) {
    size_t i;

    for (i = 0; i < cb->nfreqs; i++) {
        if (cb->freqs[i].freq != freq)
            continue;

        if (!present) {
            printf("FAIL: %s: %u collected, expected it skipped\n", what, freq);
            failures++;
        } else if (cb->freqs[i].band_caps != band_caps) {
            printf("FAIL: %s: %u band caps 0x%x, expected 0x%x\n", what, freq,
                    cb->freqs[i].band_caps, band_caps);
            failures++;
        }

        return;
    }

    if (present) {
        printf("FAIL: %s: %u not collected\n", what, freq);
        failures++;
    }
}

/* VHT capability bits 2-3: supported channel widths, 1 = 160MHz */
#define VHT_CAPA_160 (1 << 2)

int main(void) {
    char phy_a[] = "phy-a";
    char phy_b[] = "phy-b";
    char phy_c[] = "phy-c";

    /* Zero is a fresh dump, as mac80211_get_chanlist starts one */
    struct nl80211_channel_block a = { .phyname = phy_a };
    struct nl80211_channel_block b = { .phyname = phy_b };
    struct nl80211_channel_block c = { .phyname = phy_c };

    /* Radio A: 2.4GHz with HT40, 5GHz with VHT and 160MHz, one frequency per
     * message after the capabilities, as split dumps arrive */
    feed(&a, "phy-other", 0, 1 << 1, -1, 0);
    feed(&a, "phy-other", 0, -1, -1, 2422);
    feed(&a, phy_a, 0, 1 << 1, -1, 0);
    feed(&a, phy_a, 0, -1, -1, 2412);
    feed(&a, phy_a, 0, -1, -1, 2437);
    feed(&a, phy_a, 1, 1 << 1, VHT_CAPA_160, 0);
    feed(&a, phy_a, 1, -1, -1, 5180);

    expect("radio a", &a, 2422, 0, 0);
    expect("radio a", &a, 2412, 1, MAC80211_BAND_HT40);
    expect("radio a", &a, 2437, 1, MAC80211_BAND_HT40);
    expect("radio a", &a, 5180, 1, MAC80211_BAND_HT40 | MAC80211_BAND_HT80 | MAC80211_BAND_HT160);

    /* Radio C, a second dump after A ended on band 1: the same band index,
     * with no capabilities */
    feed(&c, phy_c, 1, -1, -1, 0);
    feed(&c, phy_c, 1, -1, -1, 5745);

    expect("radio c", &c, 5745, 1, 0);

    /* Radio B, a third dump: an unnamed message ahead of the phy's own is
     * not the last radio's; then 5GHz with HT20 only */
    feed(&b, NULL, 1, -1, -1, 5200);
    feed(&b, phy_b, 1, 0, -1, 0);
    feed(&b, phy_b, 1, -1, -1, 5180);

    expect("radio b", &b, 5200, 0, 0);
    expect("radio b", &b, 5180, 1, 0);

    free(a.freqs);
    free(b.freqs);
    free(c.freqs);

    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }

    printf("freqlist dump: all tests passed\n");
    return 0;
}

#else

int main(void) {
    printf("freqlist dump: skipped, no nl80211\n");
    return 0;
}

#endif
