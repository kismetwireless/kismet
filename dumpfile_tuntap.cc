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

#ifdef SYS_LINUX

#include <errno.h>

#include "dumpfile_tuntap.h"
#include "ifcontrol.h"

int dumpfiletuntap_chain_hook(CHAINCALL_PARMS) {
	Dumpfile_Tuntap *auxptr = (Dumpfile_Tuntap *) auxdata;
	return auxptr->chain_handler(in_pack);
}

Dumpfile_Tuntap::Dumpfile_Tuntap() {
	fprintf(stderr, "FATAL OOPS: Dumpfile_Tuntap called with no globalreg\n");
	exit(1);
}

Dumpfile_Tuntap::Dumpfile_Tuntap(GlobalRegistry *in_globalreg) : 
	Dumpfile(in_globalreg) {
	char errstr[STATUS_MAX];
	globalreg = in_globalreg;

	tuntap_fd = -1;

	if (globalreg->sourcetracker == NULL) {
		fprintf(stderr, "FATAL OOPS:  Sourcetracker missing before "
				"Dumpfile_Tuntap\n");
		exit(1);
	}

	if (globalreg->kismet_config == NULL) {
		fprintf(stderr, "FATAL OOPS:  Config file missing before "
				"Dumpfile_Tuntap\n");
		exit(1);
	}

	if (globalreg->kismet_config->FetchOpt("tuntap_export") != "true") {
		return;
	}

	if ((fname = globalreg->kismet_config->FetchOpt("tuntap_device")) == "") {
		_MSG("No 'tuntap_device' specified in Kismet config file", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	if ((tuntap_fd = open("/dev/net/tun", O_RDWR)) < 0) {
		if (errno == EACCES) {
			snprintf(errstr, STATUS_MAX, "Unable to open the tun/tap control "
					 "file (/dev/net/tun), it could not be found.  Make sure that "
					 "you have tun/tap support compiled into your kernel, and if "
					 "it is a module, make sure the tun module is loaded.  The "
					 "exact error was: %s", strerror(errno));
		} else if (errno == ENOENT) {
			snprintf(errstr, STATUS_MAX, "Unable to open the tun/tap control "
					 "file (/dev/net/tun), write permission was denied.  Make "
					 "sure that you are running as a user which has permission "
					 "(typically only root) or that you modified permissions on "
					 "your /dev filesystem.  The exact error was: %s",
					 strerror(errno));
		} else {
			snprintf(errstr, STATUS_MAX, "Unable to open the tun/tap control "
					 "file (/dev/net/tun) for writing.  The exact error was: %s",
					 strerror(errno));
		}
		_MSG(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	// Create the tap interface
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = (IFF_TAP | IFF_NO_PI);
	strncpy(ifr.ifr_name, fname.c_str(), sizeof(ifr.ifr_name) - 1);
	if (ioctl(tuntap_fd, TUNSETIFF, (void *) &ifr) < 0) {
		snprintf(errstr, STATUS_MAX, "Unable to create the tun/tap interface: %s",
				 strerror(errno));
		_MSG(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	// Try to set the link type
	if (ioctl(tuntap_fd, TUNSETLINK, LNX_LINKTYPE_80211) < 0) {
		snprintf(errstr, STATUS_MAX, "Unable to set the tun/tap interface link "
				 "type.  While Kismet will be able to continue, unless the "
				 "program capturing packets is able to handle a broken link "
				 "type it will not work properly.  Make sure you have applied "
				 "the patches to set tun/tap link type.  Exact error was: %s",
				 strerror(errno));
		_MSG(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	// Bring up the interface
	if (Ifconfig_Delta_Flags(fname.c_str(), errstr, 
							 (IFF_UP | IFF_RUNNING | IFF_PROMISC)) < 0) {
		_MSG(errstr, MSGFLAG_FATAL);
		_MSG("Failed bringing virtual interface %s up", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	globalreg->packetchain->RegisterHandler(&dumpfiletuntap_chain_hook, this,
											CHAINPOS_LOGGING, -100);

	_MSG("Opened tun/tap replicator '" + fname + "'", MSGFLAG_INFO);
}

Dumpfile_Tuntap::~Dumpfile_Tuntap() {
	globalreg->packetchain->RemoveHandler(&dumpfiletuntap_chain_hook,
										  CHAINPOS_LOGGING);
	if (tuntap_fd >= 0) {
		close(tuntap_fd);
		tuntap_fd = -1;
		_MSG("Closed tun/tap virtual interface '" + fname + "'", MSGFLAG_INFO);
	}
}

int Dumpfile_Tuntap::Flush() {
	// Nothing to see here
	return 1;
}

int Dumpfile_Tuntap::chain_handler(kis_packet *in_pack) {
	if (tuntap_fd < 0)
		return 0;

	// Grab the mangled frame if we have it, then try to grab up the list of
	// data types and die if we can't get anything
	kis_datachunk *chunk = 
		(kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_MANGLEFRAME));

	if (chunk == NULL) {
		if ((chunk = 
			 (kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_80211FRAME))) == NULL) {
			if ((chunk = (kis_datachunk *) 
				 in_pack->fetch(_PCM(PACK_COMP_LINKFRAME))) == NULL) {
				return 0;
			}
		}
	}

	// May not be safe, do we need a ringbuffer?  Keep in mind of we have
	// hanging problems
	write(tuntap_fd, chunk->data, chunk->length);

	dumped_frames++;

	return 1;
}

#endif /* sys_linux */

