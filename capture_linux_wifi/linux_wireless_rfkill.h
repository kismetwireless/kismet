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

#ifndef __LINUX_RFKILL_H__
#define __LINUX_RFKILL_H__

#include "../config.h"

#ifdef HAVE_LINUX_WIRELESS

/* Fetch if rfkill is enabled on an interface 
 *
 * This uses the /sys filesystem to query mac80211 drivers to see if the rfkill
 * attributes are enabled.
 *
 * rfkill_type == 0 checks hard kill
 * rfkill_type == 1 checks soft kill
 *
 * Returns:
 * -1   Error, cannot determine rfkill status
 *  0   Rfkill not enabled
 *  1   Rfkill enabled
 */
#define LINUX_RFKILL_TYPE_HARD  0
#define LINUX_RFKILL_TYPE_SOFT  1
int linux_sys_get_rfkill(const char *interface, unsigned int rfkill_type);

/* Disable soft rfkill on an interface
 *
 * This uses the /sys filesystem to query mac80211 drivers and clear the rfkill
 *
 * This only disables softkill as we cannot alter hard kill from sw
 *
 * Returns:
 * -1   Error, cannot change rfkill
 *  0   Success
 */
int linux_sys_clear_rfkill(const char *interface);

#endif

#endif

