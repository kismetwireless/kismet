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

#include "psutils.h"

#ifdef HAVE_LINUX_WIRELESS
// Some kernels include ethtool headers in wireless.h and seem to break
// terribly if these aren't defined
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

#include <asm/types.h>
#include <linux/if.h>
#include <linux/wireless.h>
#endif

#include "util.h"

#if (defined(HAVE_LIBPCAP) && defined(SYS_LINUX) && defined(HAVE_LINUX_WIRELESS))

#include "packetsourcetracker.h"
#include "packetsource_bcmon.h"

PacketSource_Bcmon::PacketSource_Bcmon(GlobalRegistry *in_globalreg, 
										   string in_interface,
										   vector<opt_pair> *in_opts) :
	PacketSource_Wext(in_globalreg, in_interface, in_opts) {

	SetFCSBytes(4);
}

int PacketSource_Bcmon::DatalinkType() {
	datalink_type = DLT_IEEE802_11_RADIO;
	return DLT_IEEE802_11_RADIO;
}

int PacketSource_Bcmon::RegisterSources(Packetsourcetracker *tracker) {
	tracker->RegisterPacketProto("bcmon", this, "IEEE80211b", 1);
	return 1;
}

int PacketSource_Bcmon::EnableMonitor() {
	return 1;
}

int PacketSource_Bcmon::DisableMonitor() {
	return 1;
}

int PacketSource_Bcmon::AutotypeProbe(string in_device) {
	return 0;
}

int PacketSource_Bcmon::OpenSource() {
	return PacketSource_Pcap::OpenSource();
}


#endif

