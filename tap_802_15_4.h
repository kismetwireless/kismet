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
#ifndef TAP_HEADER
#define TAP_HEADER
typedef struct {
    uint16_t type; //type identifier
    uint16_t length; // number of octets for type in value field (not including padding
    uint32_t value; // data for type
} tap_tlv;

typedef struct {
    uint8_t version; // currently zero
    uint8_t reserved; // must be zero
    uint16_t length; // total length of header and tlvs in octets, min 4 and must be multiple of 4
    tap_tlv tlv[3];//tap tlvs 3 fcs, signal, channel
    uint8_t payload[0];	        
    ////payload + fcs per fcs type
} _802_15_4_tap;
#endif
