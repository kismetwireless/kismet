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

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <algorithm>
#include <string>
#include <vector>
#include <map>

#include "globalregistry.h"
#include "packetchain.h"
#include "macaddr.h"
#include "packet_ieee80211.h"

kis_packet::kis_packet(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	error = 0;
	filtered = 0;

	// Stock and init the content vector
	content_vec.resize(MAX_PACKET_COMPONENTS, NULL);
	/*
	   for (unsigned int y = 0; y < MAX_PACKET_COMPONENTS; y++)
	   content_vec[y] = NULL;
	   */
}

kis_packet::~kis_packet() {
	// Delete everything we contain when we die.  I hope whomever put
	// it there expected this.
	for (unsigned int y = 0; y < MAX_PACKET_COMPONENTS; y++) {
		packet_component *pcm = content_vec[y];

		if (pcm == NULL)
			continue;

		// If it's marked for self-destruction, delete it.  Otherwise, 
		// someone else is responsible for removing it.
		if (pcm->self_destruct)
			delete pcm;

		content_vec[y] = NULL;
	}
}
   
void kis_packet::insert(const unsigned int index, packet_component *data) {
	if (index >= MAX_PACKET_COMPONENTS)
		return;
	if (content_vec[index] != NULL)
		fprintf(stderr, "DEBUG/WARNING: Leaking packet component %u/%s, inserting "
				"on top of existing\n", index,
				globalreg->packetchain->FetchPacketComponentName(index).c_str());
	content_vec[index] = data;
}

void *kis_packet::fetch(const unsigned int index) const {
	if (index >= MAX_PACKET_COMPONENTS)
		return NULL;

	return content_vec[index];
}

void kis_packet::erase(const unsigned int index) {
	if (index >= MAX_PACKET_COMPONENTS)
		return;

	// Delete it if we can - both from our array and from 
	// memory.  Whatever inserted it had better expect this
	// to happen or it will be very unhappy
	if (content_vec[index] != NULL) {
		if (content_vec[index]->self_destruct)
			delete content_vec[index];

		content_vec[index] = NULL;
	}
}

