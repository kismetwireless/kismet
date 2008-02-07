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
#include <Carbon/Carbon.h>
#include "darwin_control_objc.h"
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

/* Iterate over the IO registry, look for a specific type of card
 * thanks to Kevin Finisterre */
int darwin_cardcheck(char *service) {
	mach_port_t masterPort;
	io_iterator_t iterator;
	io_object_t sdev;
	kern_return_t err;

	if (IOMasterPort(MACH_PORT_NULL, &masterPort) != KERN_SUCCESS) {
		return -1;
	}

	if (IORegistryCreateIterator(masterPort, kIOServicePlane,
								 kIORegistryIterateRecursively, &iterator) == 
		KERN_SUCCESS) {
		while ((sdev = IOIteratorNext(iterator))) {
			if (sdev != MACH_PORT_NULL) {
				io_name_t thisClassName;
				io_name_t name;

				err = IOObjectGetClass(sdev, thisClassName);
				err = IORegistryEntryGetName(sdev, name);

				if (IOObjectConformsTo(sdev, service)) {
					IOObjectRelease(iterator);
					return 0;
				}
			}
		}

		IOObjectRelease(iterator);
	}

	return 1;
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
										   string in_dev, string in_opts): 
	PacketSource_Pcap(in_globalreg, in_type, in_name, in_dev, in_opts) {

	fcsbytes = 4;
}

int PacketSource_Darwin::EnableMonitor() {
	char devname[16];
	int devnum;
	char errstr[1024];

	if (sscanf(interface.c_str(), "%16[^0-9]%d", devname, &devnum) != 2) {
		_MSG("OSX Darwin interface could not parse '" + interface + "' "
			 "into wlt# or en#, malformed interface name", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
	}

	if (darwin_cardcheck("AirPort_Brcm43xx") == 0 ||
			   darwin_cardcheck("AirPortPCI_MM") == 0) {
		if (darwin_bcom_testmonitor() < 0) {
			_MSG("Darwin source " + name + ": Looks like a broadcom card running "
				 "under Darwin and does not appear to have monitor mode enabled "
				 "in the kernel.  Kismet will attempt to enable monitor in "
				 "5 seconds.", MSGFLAG_INFO);
			sleep(5);
			if (darwin_bcom_enablemonitor() < 0) {
				_MSG("Darwin source " + name + ": Failed to enable monitor mode "
					 "for Darwin Broadcom", MSGFLAG_FATAL);
				globalreg->fatal_condition = 1;
				return -1;
			}
		} else {
			_MSG("Darwin source " + name + ": Looks like a Broadcom card "
				 "running under Darwin and already has monitor mode enabled",
				 MSGFLAG_INFO);
		}
	} else if (darwin_cardcheck("AirPort_Athr5424ab") == 0) {
		_MSG("Darwin source " + name + ": Looks like an Atheros card running "
			 "under Darwin.  Monitor mode assumed to be on by default in "
			 "these drivers.", MSGFLAG_INFO);
	} else {
		_MSG("Darwin source " + name + ": Didn't look like Broadcom or "
			 "Atheros under Darwin.  We'll treat it like an Atheros card and "
			 "hope for the best, however it may not work properly.", 
			 MSGFLAG_ERROR);
		sleep(2);
	}

	// Bring the control interface up and promisc
	snprintf(devname, 16, "en%d", devnum);

	Ifconfig_Delta_Flags(devname, errstr, (IFF_UP | IFF_PROMISC));

	if (Ifconfig_Delta_Flags(devname, errstr, (IFF_UP | IFF_PROMISC)) < 0) {
		_MSG("Darwin source " + name + ": Failed to set interface " +
			 string(devname) + " Up+Promisc: " + string(errstr),
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	snprintf(devname, 16, "wlt%d", devnum);

	interface = string(devname);

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

