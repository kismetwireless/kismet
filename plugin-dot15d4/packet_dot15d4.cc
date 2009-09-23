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

// From kismet_dot15d4
extern int pack_comp_dot15d4;

static int debugno = 0;

int kis_dot15d4_dissector(CHAINCALL_PARMS) {
	if (in_pack->error)
		return 0;

	kis_datachunk *chunk =
		(kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_LINKFRAME));

	if (chunk == NULL)
		return 0;

	if (chunk->dlt != KDLT_IEEE802_15_4)
		return 0;

	debugno++;

	if (chunk->length < 11) {
		_MSG("Short dot15d4 frame!", MSGFLAG_ERROR);
		in_pack->error = 1;
		return 0;
	}

	uint16_t fh;

	fh = kis_letoh16(*((uint16_t *) chunk->data));

	printf("Packet %d FH: %4.04x\n", debugno, fh);
	printf("  Frame Type    : %d\n", DOT154_FH_FRAMETYPE(fh));
	printf("  Frame Security: %d\n", DOT154_FH_SECURITY(fh));
	printf("  Frame SA Mode : %u\n", DOT154_FH_SRCADDRMODE(fh));
	printf("  Frame Version : %u\n", DOT154_FH_FRAMEVERSION(fh));

	uint8_t seqno;
	uint16_t pan, addr1, addr2;

	seqno = chunk->data[2];

	pan = kis_letoh16(*((uint16_t *) &(chunk->data[3])));
	addr1 = kis_letoh16(*((uint16_t *) &(chunk->data[5])));

	if (DOT154_FH_FRAMETYPE(fh) == 0x01)
		addr2 = kis_letoh16(*((uint16_t *) &(chunk->data[7])));
	else
		addr2 = 0xB00F;

	printf("       Sequence : %hu\n", seqno);
	printf("            PAN : %x\n", pan);
	printf("          Addr1 : %x\n", addr1);
	printf("          Addr2 : %x\n", addr2);

	return 1;
}

