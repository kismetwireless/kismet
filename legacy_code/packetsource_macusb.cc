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

#include "packetsource_macusb.h"
#include "packetsourcetracker.h"

/*
int PacketSource_MacUSB::OpenSource() {
	return PacketSource_Pcap::OpenSource();
}
*/

int PacketSource_MacUSB::AutotypeProbe(string in_device) {
	if (in_device.substr(0, 3) == "tap") {
		type = "macusb";
		return 1;
	}

	return 0;
}

int PacketSource_MacUSB::RegisterSources(Packetsourcetracker *tracker) {
	tracker->RegisterPacketProto("macusb", this, "IEEE80211b", 0);
	tracker->RegisterPacketProto("macrtl8187", this, "IEEE80211b", 0);
	return 1;
}

PacketSource_MacUSB::PacketSource_MacUSB(GlobalRegistry *in_globalreg, 
										 string in_interface,
										 vector<opt_pair> *in_opts) :
	PacketSource_Pcap(in_globalreg, in_interface, in_opts) {

	// We override as DLT_IEEE802_11 by default
	override_dlt = KDLT_IEEE802_11;

	fcsbytes = 4;
}

#endif 

