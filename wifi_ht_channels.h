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

#ifndef __WIFI_HT_CHANNELS_H__
#define __WIFI_HT_CHANNELS_H__

#define WIFI_WIDTH_MASK     (0x0000FFFF)
#define WIFI_WIDTH_5MHZ     (1 << 1)
#define WIFI_WIDTH_10MHZ    (1 << 2)
#define WIFI_WIDTH_15MHZ    (1 << 3)
#define WIFI_WIDTH_20MHZ    (1 << 4)
#define WIFI_WIDTH_40MHZ    (1 << 5)
#define WIFI_WIDTH_80MHZ    (1 << 6)
#define WIFI_WIDTH_160MHZ   (1 << 7)

#define WIFI_HT_MASK        (0x00FF0000)
#define WIFI_HT_NONE        (0)
#define WIFI_HT_HT40MINUS   (1 << 17)
#define WIFI_HT_HT40PLUS    (1 << 18)
#define WIFI_HT_HT80        (1 << 19)
#define WIFI_HT_HT160       (1 << 20)

#define WIFI_OTHER_MASK     (0xFF000000)
#define WIFI_OTHER_RESERVED (1 << 25)

typedef struct {
    unsigned int chan;
    double freq;
    unsigned int flags;
    double freq80;
    double freq160;
} wifi_channel;

#define MAX_WIFI_HT_CHANNEL     196

extern wifi_channel wifi_ht_channels[MAX_WIFI_HT_CHANNEL + 1];

#endif

