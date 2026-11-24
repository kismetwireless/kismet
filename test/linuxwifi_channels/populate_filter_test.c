/* Tests for the band filter in populate_chanlist
 * (capture_linux_wifi/capture_linux_wifi.c), which keeps the netlink channel
 * names in the source's band= set.  Each name goes through
 * chantranslate_callback; a name it can't parse returns NULL, which the filter
 * dereferenced, and every translated channel leaked.  The WEXT fallback
 * counted only 2.4/5/6 GHz frequencies but wrote every other one too, past
 * the end of the list.
 *
 * The helper is built into this test with its main renamed, and the netlink
 * and WEXT fetches are replaced by fixed lists through the linker.  It links
 * ../libkismetdatasource.a; build that at the top level first:
 *
 *   make libkismetdatasource.a
 *   make -C capture_linux_wifi populate_filter_test && test/linuxwifi_channels/populate_filter_test
 *   tools/unit.sh <tree> test/linuxwifi_channels/populate_filter_test.c \
 *       interface_control.c wifi_ht_channels.c capture_linux_wifi/linux_wireless_control.c \
 *       capture_linux_wifi/linux_netlink_control.c capture_linux_wifi/linux_chanlist.c \
 *       capture_linux_wifi/linux_nexmon_control.c capture_linux_wifi/linux_wireless_rfkill.c \
 *       --set framework --cflags "<pcap, libnl3, libnm and glib -I flags>" \
 *       --libs "-Wl,--wrap=mac80211_get_chanlist,--wrap=iwconfig_get_chanlist -lpcap <libnm, glib and libnl3 libs> -llzma -ldl" \
 *       --flavor asan
 */

#ifndef LINUXWIFI_SRC
#define LINUXWIFI_SRC "../../capture_linux_wifi/capture_linux_wifi.c"
#endif

#define main capture_linux_wifi_main
#include LINUXWIFI_SRC
#undef main

static int failures = 0;

static const char **fake_names = NULL;
static size_t fake_num = 0;

/* Set to make the netlink fetch fail, so populate_chanlist falls back to the
 * WEXT frequency list in fake_freqs */
static int fake_netlink_fail = 0;
static const unsigned int *fake_freqs = NULL;
static size_t fake_freq_num = 0;

int __wrap_mac80211_get_chanlist(const char *interface, unsigned int extended_flags, char *errstr,
        unsigned int default_ht20, unsigned int expand_ht20,
        char ***ret_chan_list, size_t *ret_num_chans) {
    size_t i;

    (void) interface;
    (void) extended_flags;
    (void) default_ht20;
    (void) expand_ht20;

    *ret_chan_list = NULL;
    *ret_num_chans = 0;

    if (fake_netlink_fail) {
        snprintf(errstr, STATUS_MAX, "netlink disabled by test");
        return -1;
    }

    *ret_chan_list = (char **) calloc(fake_num, sizeof(char *));
    *ret_num_chans = 0;

    if (*ret_chan_list == NULL)
        return -1;

    for (i = 0; i < fake_num; i++) {
        if (((*ret_chan_list)[i] = strdup(fake_names[i])) == NULL)
            return -1;
        (*ret_num_chans)++;
    }

    return (int) fake_num;
}

int __wrap_iwconfig_get_chanlist(const char *interface, char *errstr,
        unsigned int **chan_list, size_t *chan_list_len) {
    (void) interface;
    (void) errstr;

    *chan_list = (unsigned int *) malloc(sizeof(unsigned int) * (fake_freq_num ? fake_freq_num : 1));
    *chan_list_len = 0;

    if (*chan_list == NULL)
        return -1;

    if (fake_freq_num > 0)
        memcpy(*chan_list, fake_freqs, sizeof(unsigned int) * fake_freq_num);
    *chan_list_len = fake_freq_num;

    return (int) fake_freq_num;
}

static void check(const char *what, kis_capture_handler_t *caph, local_wifi_t *lw,
        const char **names, size_t num, const char **want, size_t want_num) {
    char msg[STATUS_MAX] = "";
    char **list = NULL;
    size_t n = 0, i;
    int ret;

    fake_names = names;
    fake_num = num;

    caph->userdata = lw;
    ret = populate_chanlist(caph, "wlan-test", msg, 0, 0, &list, &n);

    if (ret != 1) {
        printf("FAIL: %s: populate_chanlist returned %d (%s)\n", what, ret, msg);
        failures++;
        return;
    }

    if (n != want_num) {
        printf("FAIL: %s: %zu channels, expected %zu:", what, n, want_num);
        for (i = 0; i < n; i++)
            printf(" %s", list[i]);
        printf("\n");
        failures++;
    } else {
        for (i = 0; i < n; i++) {
            if (list[i] == NULL || strcmp(list[i], want[i]) != 0) {
                printf("FAIL: %s: channel %zu is '%s', expected '%s'\n", what, i,
                        list[i] ? list[i] : "(null)", want[i]);
                failures++;
            }
        }
    }

    for (i = 0; i < n; i++)
        free(list[i]);
    free(list);
}

int main(void) {
    kis_capture_handler_t *caph = cf_handler_init("linuxwifi");
    local_wifi_t lw;
    char name[] = "test";

    static const char *names[] = {
        "1", "6HT40+", "bogus", "36", "", "149VHT80", "5W6e", "2412", "-"
    };
    static const char *want_5[] = { "36", "149VHT80" };
    static const char *want_2_6[] = { "1", "6HT40+", "5W6e" };
    static const char *bad_only[] = { "bogus", "", "-" };

#ifdef HAVE_LINUX_WIRELESS
    static const unsigned int wext_freqs[] = { 2412, 5170, 5180, 58320, 5955, 5865, 5885 };
    static const char *wext_want_5[] = { "34", "36", "173", "177" };
    static const char *wext_want_2_6[] = { "1", "1W6e" };
    static const char *wext_want_any[] = { "1", "34", "36", "58320", "1W6e", "173", "177" };
#endif

    if (caph == NULL) {
        printf("FAIL: cf_handler_init\n");
        return 1;
    }

    memset(&lw, 0, sizeof(lw));
    lw.name = name;
    lw.lock_fd = -1;
    lw.datalink_type = -1;
    lw.override_dlt = -1;

    lw.band_5 = true;
    check("band=5", caph, &lw, names, sizeof(names) / sizeof(names[0]),
            want_5, sizeof(want_5) / sizeof(want_5[0]));

    lw.band_5 = false;
    lw.band_2_4 = true;
    lw.band_6 = true;
    check("band=2.4,6", caph, &lw, names, sizeof(names) / sizeof(names[0]),
            want_2_6, sizeof(want_2_6) / sizeof(want_2_6[0]));

    check("unparseable names only", caph, &lw, bad_only, sizeof(bad_only) / sizeof(bad_only[0]),
            NULL, 0);

#ifdef HAVE_LINUX_WIRELESS
    /* WEXT fallback: 60 GHz is kept only without band=, 5 GHz uses the
     * netlink edges (ch 34 and 177 are band 5), and the list is no longer
     * than the kept set */
    fake_netlink_fail = 1;
    fake_freqs = wext_freqs;
    fake_freq_num = sizeof(wext_freqs) / sizeof(wext_freqs[0]);

    lw.band_2_4 = false;
    lw.band_6 = false;
    lw.band_5 = true;
    check("wext band=5", caph, &lw, NULL, 0, wext_want_5, sizeof(wext_want_5) / sizeof(wext_want_5[0]));

    lw.band_5 = false;
    lw.band_2_4 = true;
    lw.band_6 = true;
    check("wext band=2.4,6", caph, &lw, NULL, 0,
            wext_want_2_6, sizeof(wext_want_2_6) / sizeof(wext_want_2_6[0]));

    lw.band_2_4 = false;
    lw.band_6 = false;
    lw.band_any = true;
    check("wext any band", caph, &lw, NULL, 0,
            wext_want_any, sizeof(wext_want_any) / sizeof(wext_want_any[0]));
#endif

    caph->userdata = NULL;
    cf_handler_free(caph);
    free(caph);

    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }

    printf("populate filter: all tests passed\n");
    return 0;
}
