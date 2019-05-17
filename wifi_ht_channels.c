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

/* Most wifi stacks don't appear to report clean capabilities for HT, HT80, etc
 * channels, nor do they provide any info about the related control channels.
 *
 * To work around this, we need to make a big table of all the channel options
 * that we can look up the info on
 */

#include "wifi_ht_channels.h"

wifi_channel wifi_ht_channels[MAX_WIFI_HT_CHANNEL + 1] = {
    [1] = { 
        .chan = 1, 
        .freq = 2412, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40PLUS,
    },
    [2] = { 
        .chan = 2, 
        .freq = 2417, 
        .flags = WIFI_WIDTH_20MHZ 
    },
    [3] = { 
        .chan = 3, 
        .freq = 2422, 
        .flags = WIFI_WIDTH_20MHZ 
    },
    [4] = { 
        .chan = 4, 
        .freq = 2427, 
        .flags = WIFI_WIDTH_20MHZ 
    },
    [5] = { 
        .chan = 5, 
        .freq = 2432, 
        .flags = WIFI_WIDTH_20MHZ 
    },
    [6] = { 
        .chan = 6, 
        .freq = 2437, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40PLUS | WIFI_HT_HT40MINUS 
    },
    [7] = { 
        .chan = 7, 
        .freq = 2442, 
        .flags = WIFI_WIDTH_20MHZ 
    },
    [8] = { 
        .chan = 8, 
        .freq = 2447, 
        .flags = WIFI_WIDTH_20MHZ 
    },
    [9] = { 
        .chan = 9, 
        .freq = 2452, 
        .flags = WIFI_WIDTH_20MHZ 
    },
    [10] = { 
        .chan = 10, 
        .freq = 2457, 
        .flags = WIFI_WIDTH_20MHZ 
    },
    [11] = { 
        .chan = 11, 
        .freq = 2462, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40MINUS 
    },
    [12] = { 
        .chan = 12, 
        .freq = 2467, 
        .flags = WIFI_WIDTH_20MHZ 
    },
    [13] = { 
        .chan = 13, 
        .freq = 2472, 
        .flags = WIFI_WIDTH_20MHZ 
    },
    [14] = { 
        .chan = 14, 
        .freq = 2484, 
        .flags = WIFI_WIDTH_20MHZ 
    },

    [36] = { 
        /* Primary 20mhz channel for 80AC channel 42
         * and 160AC channel 50 */
        .chan = 36, 
        .freq = 5180, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40PLUS | WIFI_HT_HT80 | WIFI_HT_HT160,
        .freq80 = 5210,
        .freq160 = 5250
    },
    [38] = { 
        /* Not typically exposed */
        .chan = 38, 
        .freq = 5190, 
        .flags = WIFI_WIDTH_40MHZ | WIFI_OTHER_RESERVED
    },
    [40] = { 
        .chan = 40, 
        .freq = 5200, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40MINUS | WIFI_HT_HT80, 
        .freq80 = 5210,
    },
    [42] = { 
        /* Not typically exposed in linux as directly tunable; paired with
         * channel 36 for AC80 */
        .chan = 42, 
        .freq = 5210, 
        .flags = WIFI_WIDTH_80MHZ | WIFI_OTHER_RESERVED
    },
    [44] = { 
        .chan = 44, 
        .freq = 5220, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40PLUS | WIFI_HT_HT80,
        .freq80 = 5210,
    },
    [46] = { 
        /* Not typically exposed */
        .chan = 46, 
        .freq = 5230, 
        .flags = WIFI_WIDTH_40MHZ | WIFI_OTHER_RESERVED
    },
    [48] = { 
        .chan = 48, 
        .freq = 5240, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40MINUS | WIFI_HT_HT80,
        .freq80 = 5210,
    },
    [50] = { 
        /* Not typically exposed */
        .chan = 50, 
        .freq = 5250, 
        .flags = WIFI_WIDTH_160MHZ  | WIFI_OTHER_RESERVED
    },
    [52] = { 
        /* primary channel for AC80 58 */
        .chan = 52, 
        .freq = 5260, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40PLUS | WIFI_HT_HT80,
        .freq80 = 5290
    },
    [54] = { 
        /* Not typically exposed */
        .chan = 54, 
        .freq = 5270, 
        .flags = WIFI_WIDTH_40MHZ | WIFI_OTHER_RESERVED
    },
    [56] = { 
        .chan = 56, 
        .freq = 5280, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40MINUS | WIFI_HT_HT80,
        .freq80 = 5290
    },
    [58] = { 
        /* Not typically exposed */
        .chan = 58, 
        .freq = 5290, 
        .flags = WIFI_WIDTH_80MHZ | WIFI_OTHER_RESERVED
    },
    [60] = { 
        .chan = 60, 
        .freq = 5300, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40PLUS | WIFI_HT_HT80,
        .freq80 = 5290
    },
    [62] = { 
        /* Not typically exposed */
        .chan = 63, 
        .freq = 5310, 
        .flags = WIFI_WIDTH_40MHZ | WIFI_OTHER_RESERVED
    },
    [64] = { 
        .chan = 64, 
        .freq = 5320, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40MINUS | WIFI_HT_HT80,
        .freq80 = 5290
    },
    [100] = { 
        /* Control channel for AC80 106 and AC160 114 */
        .chan = 100, 
        .freq = 5500, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40PLUS | WIFI_HT_HT80 | WIFI_HT_HT160,
        .freq80 = 5530,
        .freq160 = 5570
    },
    [102] = { 
        /* Not typically exposed */
        .chan = 102, 
        .freq = 5510, 
        .flags = WIFI_WIDTH_40MHZ | WIFI_OTHER_RESERVED
    },
    [104] = { 
        .chan = 104, 
        .freq = 5520,
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40MINUS | WIFI_HT_HT80,
        .freq80 = 5530,
    },
    [106] = { 
        /* Not typically exposed */
        .chan = 106, 
        .freq = 5530, 
        .flags = WIFI_WIDTH_80MHZ | WIFI_OTHER_RESERVED
    },
    [108] = { 
        .chan = 108, 
        .freq = 5540, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40PLUS | WIFI_HT_HT80,
        .freq80 = 5530,
    },
    [110] = { 
        /* Not typically exposed */
        .chan = 110, 
        .freq = 5550, 
        .flags = WIFI_WIDTH_40MHZ | WIFI_OTHER_RESERVED
    },
    [112] = { 
        .chan = 112, 
        .freq = 5560, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40MINUS | WIFI_HT_HT80,
        .freq80 = 5530,
    },
    [114] = { 
        /* Not typically exposed */
        .chan = 114, 
        .freq = 5570, 
        .flags = WIFI_WIDTH_160MHZ | WIFI_OTHER_RESERVED
    },
    [116] = { 
        /* Control for AC80 122 */
        .chan = 116, 
        .freq = 5580, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40PLUS | WIFI_HT_HT80,
        .freq80 = 5610
    },
    [118] = { 
        /* Not typically exposed */
        .chan = 118, 
        .freq = 5590, 
        .flags = WIFI_WIDTH_40MHZ | WIFI_OTHER_RESERVED
    },
    [120] = { 
        .chan = 120, 
        .freq = 5600, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40MINUS | WIFI_HT_HT80,
        .freq80 = 5610
    },
    [122] = { 
        /* Not typically exposed */
        .chan = 122, 
        .freq = 5610, 
        .flags = WIFI_WIDTH_80MHZ | WIFI_OTHER_RESERVED
    },
    [124] = { 
        .chan = 124, 
        .freq = 5620, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40PLUS | WIFI_HT_HT80,
        .freq80 = 5610
    },
    [126] = { 
        /* Not typically exposed */
        .chan = 126, 
        .freq = 5630, 
        .flags = WIFI_WIDTH_40MHZ | WIFI_OTHER_RESERVED
    },
    [128] = { 
        .chan = 128, 
        .freq = 5640, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40MINUS | WIFI_HT_HT80,
        .freq80 = 5610
    },
    [132] = { 
        /* Control for AC80 138 */
        .chan = 132, 
        .freq = 5660, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40PLUS | WIFI_HT_HT80,
        .freq80 = 5690,
    },
    [134] = { 
        /* Not typically exposed */
        .chan = 134, 
        .freq = 5670, 
        .flags = WIFI_WIDTH_40MHZ | WIFI_OTHER_RESERVED
    },
    [136] = { 
        .chan = 136, 
        .freq = 5680, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40MINUS | WIFI_HT_HT80,
        .freq80 = 5690,
    },
    [138] = { 
        /* Not typically exposed */
        .chan = 138, 
        .freq = 5690, 
        .flags = WIFI_WIDTH_80MHZ | WIFI_OTHER_RESERVED
    },
    [140] = { 
        .chan = 140, 
        .freq = 5700, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40MINUS | WIFI_HT_HT80,
        .freq80 = 5690,
    },
    [142] = { 
        /* Not commonly exposed */
        .chan = 142, 
        .freq = 5710, 
        .flags = WIFI_WIDTH_40MHZ | WIFI_OTHER_RESERVED
    }, 
    [144] = { 
        .chan = 144, 
        .freq = 5720, 
        /* Probably can't do 40+ here */
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40MINUS | WIFI_HT_HT80,
        .freq80 = 5690,
    }, 
    [149] = { 
        /* Control channel for AC80 155 */
        .chan = 149, 
        .freq = 5745, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40PLUS | WIFI_HT_HT80,
        .freq80 = 5775
    },
    [151] = { 
        /* Not typically exposed */
        .chan = 151, 
        .freq = 5755, 
        .flags = WIFI_WIDTH_40MHZ | WIFI_OTHER_RESERVED
    },
    [153] = { 
        .chan = 153, 
        .freq = 5765, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40MINUS | WIFI_HT_HT80,
        .freq80 = 5775
    },
    [155] = { 
        /* Not typically exposed */
        .chan = 155, 
        .freq = 5775, 
        .flags = WIFI_WIDTH_80MHZ | WIFI_OTHER_RESERVED
    },
    [157] = { 
        .chan = 157, 
        .freq = 5785, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40PLUS | WIFI_HT_HT80,
        .freq80 = 5775
    },
    [159] = { 
        /* Not typically exposed */
        .chan = 159, 
        .freq = 5795, 
        .flags = WIFI_WIDTH_40MHZ | WIFI_OTHER_RESERVED
    },
    [161] = { 
        .chan = 161, 
        .freq = 5805, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40MINUS | WIFI_HT_HT80,
        .freq80 = 5775
    },
    [165] = { 
        .chan = 165, 
        .freq = 5825, 
        .flags = WIFI_WIDTH_20MHZ | WIFI_HT_HT40MINUS 
    },

    /* Do we support HT extension on any of these?  The only one that might 
     * is 192/196 */
    [183] = { .chan = 183, .freq = 4915, .flags = WIFI_WIDTH_10MHZ },
    [184] = { .chan = 184, .freq = 4920, .flags = WIFI_WIDTH_20MHZ },
    [185] = { .chan = 185, .freq = 4925, .flags = WIFI_WIDTH_10MHZ },
    [187] = { .chan = 187, .freq = 4935, .flags = WIFI_WIDTH_10MHZ },
    [188] = { .chan = 188, .freq = 4940, .flags = WIFI_WIDTH_20MHZ },
    [189] = { .chan = 189, .freq = 4945, .flags = WIFI_WIDTH_10MHZ },
    [192] = { .chan = 192, .freq = 4960, .flags = WIFI_WIDTH_20MHZ },
    [196] = { .chan = 196, .freq = 4980, .flags = WIFI_WIDTH_20MHZ },

    /* MUST UPDATE MAX_WIFI_HT_CHANNEL if this changes! */
};

