/* Tests for mac80211_freq_to_chan (capture_linux_wifi/linux_netlink_control.c),
 * which numbers the frequencies nl80211 reports for the channel list: the
 * channels kismet can tune, and none for the S1G band around 900MHz, which
 * would otherwise wrap to numbers such as 858993158.  The 60GHz (DMG)
 * channels are 1-6 as the kernel numbers them; they used to fall into the
 * 6GHz formula and become channels such as 10474.
 *
 *   make -C capture_linux_wifi freq_to_chan_test && test/linuxwifi_channels/freq_to_chan_test
 */

#include <stdio.h>

#include "../../capture_linux_wifi/linux_netlink_control.h"

int main(void) {
    static const struct {
        unsigned int freq;
        unsigned int chan;
    } cases[] = {
        /* S1G (802.11ah), US 902-928MHz */
        { 902, 0 }, { 915, 0 }, { 927, 0 },
        { 1000, 0 }, { 2411, 0 },
        { 2412, 1 }, { 2437, 6 }, { 2472, 13 }, { 2484, 14 },
        { 5180, 36 }, { 5825, 165 },
        { 5955, 1 }, { 7115, 233 },
        /* DMG, 2160MHz apart */
        { 58320, 1 }, { 60480, 2 }, { 62640, 3 }, { 64800, 4 },
        { 66960, 5 }, { 69120, 6 },
    };
    unsigned int i, got;
    int failures = 0;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        got = mac80211_freq_to_chan(cases[i].freq);

        if (got != cases[i].chan) {
            printf("FAIL %u MHz: channel %u, want %u\n", cases[i].freq, got, cases[i].chan);
            failures++;
        }
    }

    printf("%s: %u frequencies, %d failed\n", failures ? "FAIL" : "ok",
            (unsigned int) (sizeof(cases) / sizeof(cases[0])), failures);

    return failures != 0;
}
