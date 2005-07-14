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

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#ifdef HAVE_LINUX_WIRELESS
// Because some kernels include ethtool which breaks horribly...
// The stock ones don't but others seem to
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

#include <linux/wireless.h>
#endif

#include "util.h"
#include "packetsourcetracker.h"
#include "packetsource_wext.h"

#if (defined(HAVE_LIBPCAP) && defined(SYS_LINUX))

int PacketSource_Wext::FetchChannel() {
    char errstr[STATUS_MAX] = "";

    // Failure to fetch a channel isn't necessarily a fatal error
	// and if we blow up badly enough that we can't get channels, we'll
	// blow up definitively on something else soon enough
    if (Iwconfig_Get_Channel(interface.c_str(), errstr) < 0) {
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    return 1;
}

void PacketSource_Wext::FetchRadioData(kis_packet *in_packet) {
	// Build a signal layer record if we don't have one from the builtin headers.
	// These are less accurate.
	char errstr[STATUS_MAX] = "";
	int ret;
	
	kis_layer1_packinfo *radiodata = (kis_layer1_packinfo *) 
		in_packet->fetch(_PCM(PACK_COMP_RADIODATA));

	// We don't do anything if we have a signal layer from anywhere else
	if (radiodata == NULL)
		radiodata = new kis_layer1_packinfo;
	else
		return;

	// Fetch the signal levels if we know how and it hasn't been already.
	// Blow up if we can't, but do so sanely
	if ((ret = Iwconfig_Get_Levels(interface.c_str(), errstr,
								   &(radiodata->signal), &(radiodata->noise))) < 0) {
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		delete radiodata;
		return;
	}

	// Fetch the channel if we know how and it hasn't been filled in already
	radiodata->channel = FetchChannel();

	// Low accuracy
	radiodata->accuracy = 1;

	// If we didn't get anything good, destroy it
	if (radiodata->signal == 0 && radiodata->noise == 0 && radiodata->channel == 0) {
		delete radiodata;
		return;
	}

	in_packet->insert(_PCM(PACK_COMP_RADIODATA), radiodata);
}

/* *********************************************************** */
/* Packetsource registrant functions */

KisPacketSource *packetsource_wext_registrant(REGISTRANT_PARMS) {
	return new PacketSource_Wext(globalreg, in_name, in_device);
}

KisPacketSource *packetsource_wext_fcs_registrant(REGISTRANT_PARMS) {
	PacketSource_Wext *ret = new PacketSource_Wext(globalreg, in_name, in_device);
	ret->SetFCSBytes(4);
	return ret;
}

#endif

