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

#if defined(HAVE_LIBPCAP) && defined(SYS_DARWIN)

#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
extern "C" {
#include "apple80211.h"
}

#include "packetsource_darwin.h"

#include "packetsourcetracker.h"

/* From Macstumber rev-eng darwin headers */
WIErr wlc_ioctl(WirelessContextPtr ctx, int command, int bufsize, 
				void *buffer, int outsize,  void *out) {
	if (!buffer) 
		bufsize = 0;

	int *buf = (int *) malloc(bufsize+8);

	buf[0] = 3;
	buf[1] = command;

	if (bufsize && buffer) {
		memcpy(&buf[2], buffer, bufsize);
	}

	return WirelessPrivate(ctx, buf, bufsize+8, out, outsize);
}

int PacketSource_Darwin::OpenSource() {
	return PacketSource_Pcap::OpenSource();
}

int PacketSource_Darwin::AutotypeProbe(string in_device) {
	return 0;
}

int PacketSource_Darwin::RegisterSources(Packetsourcetracker *tracker) {
	tracker->RegisterPacketsource("darwin", this, 1, "IEEE80211b", 6);
	return 1;
}

PacketSource_Darwin::PacketSource_Darwin(GlobalRegistry *in_globalreg, 
										   string in_type, string in_name,
										   string in_dev): 
	PacketSource_Pcap(in_globalreg, in_type, in_name, in_dev) {

	fcsbytes = 4;
}

int PacketSource_Darwin::EnableMonitor() {
	return 1;
}

int PacketSource_Darwin::DisableMonitor() {
	return PACKSOURCE_UNMONITOR_RET_OKWITHWARN;
}

int PacketSource_Darwin::SetChannel(unsigned int in_ch) {
	WirelessContextPtr gWCtxt = NULL;

	if (WirelessAttach(&gWCtxt, 0) != 0) {
		_MSG("OSX Darwin adapter " + interface + " failed WirelessAttach(): Could "
			 "not set channel", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}
	wlc_ioctl(gWCtxt, 52, 0, NULL, 0, NULL); // Disassociate
	wlc_ioctl(gWCtxt, 30, 8, &in_ch, 0, NULL); // Set channel

	WirelessDetach(gWCtxt);

	return 0;
}

#endif 

