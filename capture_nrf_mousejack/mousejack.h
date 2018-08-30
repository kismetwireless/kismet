/*
  Derived from the Bastille Mousejack python code.
  While Kismet is generally licensed under the GPL2 license, this binary is
  derived from GPL3 code from Bastille, and as such, is under that license.
   
  Copyright (C) 2016 Bastille Networks
  Copyright (C) 2018 Mike Kershaw / dragorn@kismetwireless.net


  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "../config.h"

#ifndef __MOUSEJACK_H__
#define __MOUSEJACK_H__

#define MOUSEJACK_USB_VENDOR        0x1915
#define MOUSEJACK_USB_PRODUCT       0x0102

/* Protocol constants for the mousejack firmware */
#define MOUSEJACK_TRANSMIT_PAYLOAD                0x04
#define MOUSEJACK_ENTER_SNIFFER_MODE              0x05
#define MOUSEJACK_ENTER_PROMISCUOUS_MODE          0x06
#define MOUSEJACK_ENTER_TONE_TEST_MODE            0x07
#define MOUSEJACK_TRANSMIT_ACK_PAYLOAD            0x08
#define MOUSEJACK_SET_CHANNEL                     0x09
#define MOUSEJACK_GET_CHANNEL                     0x0A
#define MOUSEJACK_ENABLE_LNA_PA                   0x0B
#define MOUSEJACK_TRANSMIT_PAYLOAD_GENERIC        0x0C
#define MOUSEJACK_ENTER_PROMISCUOUS_MODE_GENERIC  0x0D
#define MOUSEJACK_RECEIVE_PAYLOAD                 0x12

/* nRF registers */
#define MOUSEJACK_RF_CH                           0x05

/* Data rates */
#define MOUSEJACK_RF_RATE_250K                    0
#define MOUSEJACK_RF_RATE_1M                      1
#define MOUSEJACK_RF_RATE_2M                      2

/* Input endpoint */
#define MOUSEJACK_USB_ENDPOINT_IN                 0x81
#define MOUSEJACK_USB_ENDPOINT_OUT                0x01

#endif


