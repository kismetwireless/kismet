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

#ifndef __PACKET_BTSCAN_H__
#define __PACKET_BTSCAN_H__

#include <config.h>

#include <string>

#include <packetchain.h>
#include <packetsource.h>
#include <macaddr.h>

// TODO - expand to include SDP scan data
class btscan_packinfo : public packet_component {
public:
	btscan_packinfo() {
		self_destruct = 1;
	};

	string bd_name;
	string bd_class;
	mac_addr bd_addr;
};

#endif
