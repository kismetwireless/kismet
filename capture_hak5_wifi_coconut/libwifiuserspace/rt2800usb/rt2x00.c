/*
 * Copyright (C) 2010 Willow Garage <http://www.willowgarage.com>
 * Copyright (C) 2004 - 2010 Ivo van Doorn <IvDoorn@gmail.com>
 * <http://rt2x00.serialmonkey.com>
 *
 * GPL-2.0-or-later
 *
 * Userspace port (C) 2019 Hak5 Inc
 *
 */

/*
 * This is a user-space port of components of the rt2x00usb library,
 * implementing generic usb device routines.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "kernel/bits.h"
#include "kernel/endian.h"
#include "kernel/kernel.h"

#include "rt2800usb/rt2x00.h"
#include "rt2800usb/rt2x00usb.h"

