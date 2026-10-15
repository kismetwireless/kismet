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
*/

/* Radiotap for S1G frames, based on morse_driver monitor.c.
 *
 * Fixed fields: TSFT, flags, channel (MHz, 900 MHz spectrum flag), signal, noise.  The TLV
 * area carries the standard S1G field (type 32) and a Morse Micro vendor namespace with the
 * frequency in kHz, since the channel field can't represent half-MHz centers.
 */

#include "mm_radiotap.h"
#include "mm_util.h"

#define RT_PRESENT_TSFT         (1u << 0)
#define RT_PRESENT_FLAGS        (1u << 1)
#define RT_PRESENT_CHANNEL      (1u << 3)
#define RT_PRESENT_ANTSIGNAL    (1u << 5)
#define RT_PRESENT_ANTNOISE     (1u << 6)
#define RT_PRESENT_TLV          (1u << 28)

#define RT_FLAG_FCS             0x10
#define RT_FLAG_BADFCS          0x40

#define RT_CHAN_700MHZ          0x0001
#define RT_CHAN_800MHZ          0x0002
#define RT_CHAN_900MHZ          0x0004

#define RT_TLV_VENDOR_NAMESPACE 30
#define RT_TLV_S1G              32

#define S1G_KNOWN_PPDU          0x0001
#define S1G_KNOWN_RI            0x0002
#define S1G_KNOWN_GI            0x0004
#define S1G_KNOWN_NSS           0x0008
#define S1G_KNOWN_BW            0x0010
#define S1G_KNOWN_MCS           0x0020
#define S1G_KNOWN_COLOR         0x0040
#define S1G_KNOWN_UPLINK        0x0080

#define S1G_PPDU_1M             0
#define S1G_PPDU_SHORT          1
#define S1G_PPDU_LONG           2

/* Morse Micro OUI and vendor TLV type, from morse_driver vendor.h and s1g_radiotap.h */
#define MORSE_OUI_0             0x0C
#define MORSE_OUI_1             0xBF
#define MORSE_OUI_2             0x74
#define MORSE_VENDOR_FREQ_KHZ   35

/* Header (8), TSFT (8), flags (1), pad (1), channel (4), signal (1), noise (1) */
#define RT_FIXED_LEN            24
#define RT_S1G_TLV_LEN          12
#define RT_VENDOR_TLV_LEN       16

size_t mm_radiotap_build(const struct mm_rx_status *st, uint8_t *buf, size_t buf_len) {
    const size_t total = RT_FIXED_LEN + RT_S1G_TLV_LEN + RT_VENDOR_TLV_LEN;
    const unsigned int preamble = MM_RATECODE_PREAMBLE(st->ratecode);
    const unsigned int freq_mhz = st->freq_khz / 1000;
    uint16_t chan_flags, known, data1, data2;
    uint8_t flags = 0;
    uint8_t *p;

    if (buf_len < total)
        return 0;

    memset(buf, 0, total);

    buf[0] = 0;
    buf[1] = 0;
    mm_put_le16(buf + 2, (uint16_t) total);
    mm_put_le32(buf + 4, RT_PRESENT_TSFT | RT_PRESENT_FLAGS | RT_PRESENT_CHANNEL |
            RT_PRESENT_ANTSIGNAL | RT_PRESENT_ANTNOISE | RT_PRESENT_TLV);

    /* The chip's local timer at frame detection */
    mm_put_le64(buf + 8, st->timestamp_us);

    if (st->flags & MM_RX_FLAG_FCS_INCLUDED)
        flags |= RT_FLAG_FCS;
    if (st->flags & MM_RX_FLAG_CRC_ERROR)
        flags |= RT_FLAG_BADFCS;
    buf[16] = flags;

    if (freq_mhz <= 700)
        chan_flags = RT_CHAN_700MHZ;
    else if (freq_mhz <= 800)
        chan_flags = RT_CHAN_800MHZ;
    else
        chan_flags = RT_CHAN_900MHZ;

    mm_put_le16(buf + 18, (uint16_t) freq_mhz);
    mm_put_le16(buf + 20, chan_flags);

    buf[22] = (uint8_t) st->rssi;
    buf[23] = (uint8_t) st->noise;

    /* S1G TLV */
    p = buf + RT_FIXED_LEN;
    known = S1G_KNOWN_RI | S1G_KNOWN_COLOR | S1G_KNOWN_UPLINK;
    data1 = (uint16_t) (MM_RX_FLAG_RI(st->flags) << 2);
    data2 = (uint16_t) ((st->bss_color & 0x7) | ((st->flags & MM_RX_FLAG_UPLINK) ? 0x8 : 0) |
            ((uint16_t) (uint8_t) st->rssi << 8));

    /* Rate details only apply to S1G preambles */
    if (preamble == MM_PREAMBLE_S1G_LONG || preamble == MM_PREAMBLE_S1G_SHORT ||
            preamble == MM_PREAMBLE_S1G_1M) {
        const unsigned int ppdu = preamble == MM_PREAMBLE_S1G_LONG ? S1G_PPDU_LONG :
            preamble == MM_PREAMBLE_S1G_1M ? S1G_PPDU_1M : S1G_PPDU_SHORT;
        const unsigned int bw = MM_RATECODE_BW_IDX(st->ratecode);

        known |= S1G_KNOWN_PPDU | S1G_KNOWN_GI | S1G_KNOWN_NSS | S1G_KNOWN_MCS;
        data1 |= (uint16_t) (ppdu & 0x3);
        data1 |= (uint16_t) (MM_RATECODE_SGI(st->ratecode) << 5);
        data1 |= (uint16_t) (((MM_RATECODE_NSS(st->ratecode) - 1) & 0x3) << 6);
        data1 |= (uint16_t) (MM_RATECODE_MCS(st->ratecode) << 12);

        /* 1, 2, 4, 8 and 16 MHz */
        if (bw <= 4) {
            known |= S1G_KNOWN_BW;
            data1 |= (uint16_t) (bw << 8);
        }
    }

    mm_put_le16(p, RT_TLV_S1G);
    mm_put_le16(p + 2, 6);
    mm_put_le16(p + 4, known);
    mm_put_le16(p + 6, data1);
    mm_put_le16(p + 8, data2);

    /* Vendor namespace TLV with the exact frequency */
    p += RT_S1G_TLV_LEN;
    mm_put_le16(p, RT_TLV_VENDOR_NAMESPACE);
    mm_put_le16(p + 2, 12);
    p[4] = MORSE_OUI_0;
    p[5] = MORSE_OUI_1;
    p[6] = MORSE_OUI_2;
    /* Sub-namespace 0 */
    p[7] = 0;
    mm_put_le16(p + 8, MORSE_VENDOR_FREQ_KHZ);
    mm_put_le16(p + 10, 0);
    mm_put_le32(p + 12, st->freq_khz);

    return total;
}
