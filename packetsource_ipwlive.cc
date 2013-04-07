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
#include "packetsourcetracker.h"
#include "packetsource_ipwlive.h"

#if (defined(HAVE_LIBPCAP) && defined(SYS_LINUX) && defined(HAVE_LINUX_WIRELESS))

int PacketSource_Ipwlive::AutotypeProbe(string in_device) {
	return 0;
}

int PacketSource_Ipwlive::RegisterSources(Packetsourcetracker *tracker) {
	tracker->RegisterPacketProto("ipwlivetap", this, "na", 0);
	return 1;
}

int PacketSource_Ipwlive::EnableMonitor() {
	char errstr[STATUS_MAX];

#if 0
	// Pull the hardware address from the device and use it to re-seed 
	// the UUID
	uint8_t hwnode[6];
	if (Ifconfig_Get_Hwaddr(interface.c_str(), errstr, hwnode) < 0) {
		_MSG(errstr, MSGFLAG_ERROR);
		_MSG("Failed to fetch interface hardware flags for '" + interface + ", "
			 "this will probably fully fail in a moment when we try to configure "
			 "the interface, but we'll keep going.", MSGFLAG_ERROR);
	}
	src_uuid.GenerateTimeUUID(hwnode);
#endif

	char dynif[32];
	FILE *sysf;
	char path[1024];
	int ifflags;

	if (Ifconfig_Get_Flags(interface.c_str(), errstr, &ifflags) < 0) {
		_MSG(errstr, MSGFLAG_ERROR);
		_MSG("Failed to get interface flags for livetap control interface",
			 MSGFLAG_ERROR);
		return -1;
	}

	if ((ifflags & IFF_UP) == 0) {
		_MSG("The ipw control interface (" + interface + ") is not configured "
			 "as 'up'.  The ipwlivetap source reports traffic from a currently "
			 "running interface.  For pure rfmon, use ipwXXXX instead.",
			 MSGFLAG_ERROR);
		return -1;
	}

	// Use the .../net/foo/device symlink into .../bus/pci/drivers
	snprintf(path, 1024, "/sys/class/net/%s/device/rtap_iface", interface.c_str());

	// Open it in RO mode first and get the current state.  I'm not sure how
	// well frewind works on proc virtual files so we'll close it and re-open
	// to set modes, instead of opening it in mixed rw
	if ((sysf = fopen(path, "r")) == NULL) {
		_MSG("Failed to open ipw sysfs rtap control file.  Check that the "
			 "version of the ipw drivers you are using is current enough to "
			 "support livetap mode, and that your system has sysfs set up "
			 "properly", MSGFLAG_ERROR);
		return -1;
	}

	if (fgets(dynif, 32, sysf) == NULL) {
		_MSG("Failed to read from the ipw rtap control file.  Check that the "
			 "version of the ipw drivers you are using is current enough to "
			 "support livetap mode, and that your system has sysfs set up "
			 "properly", MSGFLAG_ERROR);
		fclose(sysf);
		return -1;
	}

	// We're done with the ro
	fclose(sysf);

	// If it's -1 we aren't turned on, so we'll initialize
	if (strncmp(dynif, "-1", 3) == 0) {
		if ((sysf = fopen(path, "w")) == NULL) {
			_MSG("Failed to open the ipw rtap control file for writing "
				 "(" + string(strerror(errno)) + ").  Check that Kismet has "
				 "the proper privilege levels (SUID or started as root) and "
				 "that you are running a version of the ipw drivers current "
				 "enough to support livetap mode.", MSGFLAG_ERROR);
			return -1;
		}

		fprintf(sysf, "1\n");
		fclose(sysf);

		// Now open it AGAIN for reading to get the interface out of it
		if ((sysf = fopen(path, "r")) == NULL) {
			_MSG("Failed to open ipw sysfs rtap control file.  Check that the "
				 "version of the ipw drivers you are using is current enough to "
				 "support livetap mode, and that your system has sysfs set up "
				 "properly", MSGFLAG_ERROR);
			return -1;
		}

		if (fgets(dynif, 32, sysf) == NULL) {
			_MSG("Failed to read from the ipw rtap control file.  Check that the "
				 "version of the ipw drivers you are using is current enough to "
				 "support livetap mode, and that your system has sysfs set up "
				 "properly", MSGFLAG_ERROR);
			fclose(sysf);
			return -1;
		}

		// We're done with the ro
		fclose(sysf);

		// Wait for things to settle if interfaces are getting renamed
		sleep(1);
	}

	// Sanity check the interface we were told to use.  A 0, 1, -1 probably
	// means a bad driver version or something
	if (strncmp(dynif, "-1", 3) == 0 || strncmp(dynif, "0", 2) == 0 ||
		strncmp(dynif, "1", 2) == 0) {
		_MSG("Got a nonsense interface from the ipw rtap control file.  This "
			 "probably means there is something unexpected happening with the "
			 "ipw drivers.  Check your system messages (dmesg)", MSGFLAG_ERROR);
		return -1;
	}

	// Bring up the dynamic interface
	if (Ifconfig_Delta_Flags(dynif, errstr, 
							 (IFF_UP | IFF_RUNNING | IFF_PROMISC)) < 0) {
		_MSG(errstr, MSGFLAG_ERROR);
		_MSG("Unable to set ipw livetap dynamic interface to 'up'",
			 MSGFLAG_ERROR);
		return -1;
	}

	interface = dynif;

	return 0;
}

int PacketSource_Ipwlive::DisableMonitor() {
	return PACKSOURCE_UNMONITOR_RET_SILENCE;
}

int PacketSource_Ipwlive::SetChannel(unsigned int in_ch) {
	return 1;
}

int PacketSource_Ipwlive::FetchChannel() {
	return 0;
}

#endif

