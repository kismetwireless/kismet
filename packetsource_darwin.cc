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
#include "darwin_control_wrapper.h"
}

#include "packetsource_darwin.h"

#include "packetsourcetracker.h"

/* Iterate over the IO registry, look for a specific type of card
 * thanks to Kevin Finisterre */
int darwin_cardcheck(const char *service) {
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
	int r = PacketSource_Pcap::OpenSource();

	if (r < 0)
		return r;

	// Set the DLT in the order of what we want least, since the last one we
	// set will stick
	pcap_set_datalink(pd, DLT_IEEE802_11);
	pcap_set_datalink(pd, DLT_IEEE802_11_RADIO_AVS);
	pcap_set_datalink(pd, DLT_IEEE802_11_RADIO);
	// Hack to re-enable promisc mode since changing the DLT seems to make it
	// drop it on some bsd pcap implementations
	ioctl(pcap_get_selectable_fd(pd), BIOCPROMISC, NULL);
	// Hack to set the fd to IOIMMEDIATE, to solve problems with select() on bpf
	// devices on BSD
	int v = 1;
	ioctl(pcap_get_selectable_fd(pd), BIOCIMMEDIATE, &v);

	if (DatalinkType() < 0) {
		pcap_close(pd);
		return -1;
	}

	return 1;
}

int PacketSource_Darwin::AutotypeProbe(string in_device) {
	if (in_device.substr(0, 2) == "en" ||
		in_device.substr(0, 3) == "wlt") {
		type = "darwin";
		return 1;
	}

	return 0;
}

int PacketSource_Darwin::RegisterSources(Packetsourcetracker *tracker) {
	tracker->RegisterPacketProto("darwin", this, "IEEE80211b", 0);
	return 1;
}

PacketSource_Darwin::PacketSource_Darwin(GlobalRegistry *in_globalreg, 
										 string in_interface,
										 vector<opt_pair> *in_opts) :
	PacketSource_Pcap(in_globalreg, in_interface, in_opts) {

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

	cherror_pending = 0;

	control = darwin_allocate_interface(devname);
	
	if (darwin_get_corewifi(control)) {
		_MSG("Darwin source " + name + ": Looks like Snow Leopard (10.6) "
				"or newer is installed and CoreWireless knew what we were.",
				MSGFLAG_INFO);
	} else if (darwin_cardcheck("AirPort_Brcm43xx") == 0 ||
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

	/*
	snprintf(devname, 16, "wlt%d", devnum);

	interface = string(devname);
	*/

	return 1;
}

int PacketSource_Darwin::DisableMonitor() {
	darwin_free_interface(control);
	return PACKSOURCE_UNMONITOR_RET_OKWITHWARN;
}

vector<unsigned int> PacketSource_Darwin::FetchSupportedChannels(string in_interface) { 
        vector<unsigned int> ret;

	int *channels;

	int nch = darwin_get_channels(in_interface.c_str(), &channels);

	for (int x = 0; x < nch; x++) {
		ret.push_back(channels[x]);
	}

	free(channels);

        return ret;
}


int PacketSource_Darwin::SetChannel(unsigned int in_ch) {
	char err[1024];

	// If we're in pending error state, spin
	if (cherror_pending) {
		if (globalreg->timestamp.tv_sec - cherror_pending <= 2) {
			return 0;
		} else {
			cherror_pending = 0;
			// Set the DLT back to the original
    			pcap_set_datalink(pd, orig_dlt);
			paused = 0;
			_MSG("Resuming Darwin source " + name + "...", MSGFLAG_INFO);
		}
	}

	if (darwin_set_channel(in_ch, err, control) < 0) {
		_MSG("Darwin source " + name + ": Failed to set channel " +
		IntToString(in_ch) + ": " + string(err), MSGFLAG_ERROR);
		_MSG("Attempting to reset Darwin source " + name + ", will resume channel "
			"hopping once reset is complete.", MSGFLAG_ERROR);

		// Remember the DLT, set us back to 10meg, set our delay time, set us to paused
		// so that we don't process bogus packets
		orig_dlt = pcap_datalink(pd);
		darwin_disassociate(control);
		pcap_set_datalink(pd, DLT_EN10MB);
		cherror_pending = globalreg->timestamp.tv_sec;
		paused = 1;
	}

	return 0;
}

#endif 

