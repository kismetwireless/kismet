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

#include "../config.h"

#ifndef __TICC2531_H__
#define __TICC2531_H__

#define TICC2531_USB_VENDOR        0x0451 
#define TICC2531_USB_PRODUCT       0x16ae 

#define TICC2531_GET_IDENT 0xC0
#define TICC2531_SET_POWER 0xC5
#define TICC2531_GET_POWER 0xC6
#define TICC2531_SET_START 0xD0
#define TICC2531_SET_END   0xD1
#define TICC2531_SET_CHAN  0xD2 // 0x0d (idx 0) + data)0x00 (idx 1)
#define TICC2531_DIR_OUT   0x40
#define TICC2531_DIR_IN    0xC0
#define TICC2531_TIMEOUT   100 // 2500
#define TICC2531_DATA_TIMEOUT 200

#define TICC2531_POWER_RETRIES 10

#define TICC2531_DATA_EP 0x83

#define TICC2531 0x01

#endif


