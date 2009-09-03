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

#include <usb.h>
#include <pthread.h>

#include <packetchain.h>
#include <packetsource.h>

#include "packet_dot15d4.h"

int kis_dot15d4_dissector(CHAINCALL_PARMS) {
	if (in_pack->error)
		return 0;

	kis_datachunk *chunk =
		(kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_LINKFRAME));

	if (chunk == NULL)
		return 0;

	if (chunk->dlt != KDLT_IEEE802_15_4)
		return 0;

	if (chunk->length < 2) {
		_MSG("Short dot15d4 frame!", MSGFLAG_ERROR);
		return 0;
	}

	uint16_t fh;

	fh = (*((uint16_t *) chunk->data));

	printf("FH: %4.04x\n", fh);
	printf("  Frame Type    : %d\n", DOT154_FH_FRAMETYPE(fh));
	printf("  Frame Security: %d\n", DOT154_FH_SECURITY(fh));
	printf("  Frame DA Raw  : %u\n", (fh >> 10) & 0x2);
	printf("  Frame DA Mode : %u\n", DOT154_FH_DESTADDRMODE(fh));
	printf("  Frame SA Mode : %u\n", DOT154_FH_SRCADDRMODE(fh));
	printf("  Frame Version : %u\n", DOT154_FH_FRAMEVERSION(fh));

	return 1;
}

