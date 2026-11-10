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

#ifndef __KCOMPAT_HOST_H__
#define __KCOMPAT_HOST_H__

/* Interface for the host program using kcompat, rather than for driver code */

/* Receives kernel log messages; level is the KERN_ level, 0 (emergency) to 7 (debug) */
typedef void (*kc_log_cb_t)(void *ctx, int level, const char *msg);
void kc_set_log_cb(kc_log_cb_t cb, void *ctx, int max_level);

/* Starts the jiffies ticker, timer thread and system workqueue; call once before use */
int kc_runtime_init(void);

#endif
