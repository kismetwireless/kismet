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

#include "config.h"

#include <packetchain.h>
#include <packetsource.h>
#include <endian_magic.h>

#include "packet_dot15d4.h"

const char *dot15d4_type_str[] = {
	"802.15.4 Beacon",
	"802.15.4 Data",
	"802.15.4 Ack",
	"802.15.4 Command"
};

const char *dot15d4_cmd_subtype_str[] = {
	"802.15.4 Cmd Association Request",
	"802.15.4 Cmd Association Response",
	"802.15.4 Cmd Disassociation",
	"802.15.4 Cmd Data Request",
	"802.15.4 Cmd PAN ID Conflict",
	"802.15.4 Cmd Orphan Notification",
	"802.15.4 Cmd Beacon Request",
	"802.15.4 Cmd Coordinator Realign",
	"802.15.4 Cmd GTS Request"
};

const char *dot15d4_crypt_type_str[] = {
	"No encryption",
	"No encryption, 32-bit MIC",
	"No encryption, 64-bit MIC",
	"No encryption, 128-bit MIC",
	"Encrypted",
	"Encrypted, 32-bit MIC",
	"Encrypted, 64-bit MIC",
	"Encrypted, 128-bit MIC"
};

