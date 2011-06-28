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

#include <errno.h>

#include "dumpfile_tuntap.h"
#include "ifcontrol.h"
#include "ipc_remote.h"

#ifndef SYS_CYGWIN

int dft_ipc_open(IPC_CMD_PARMS) {
	if (parent) {
		// If we're the parent, we use this as a signal that we've opened it
		// and we need to pull the file descriptor
		if (len < (int) sizeof(ipc_dft_open))
			return 0;

		globalreg->packetchain->RegisterHandler(&dumpfiletuntap_chain_hook, 
												(void *) auxptr,
												CHAINPOS_LOGGING, -100);
		globalreg->RegisterDumpFile((Dumpfile_Tuntap *) auxptr);

		return ((Dumpfile_Tuntap *) auxptr)->GetTapFd();
	} else {
		// If we're the child, we now know our tap device name from the 
		// config parser in the parent, record it and open
		// fname = string(((ipc_dft_open *) data)->tapdevice);
		ipc_dft_open *dfo = (ipc_dft_open *) data;
		((Dumpfile_Tuntap *) auxptr)->SetTapDevice(string((char *) dfo->tapdevice));
		((Dumpfile_Tuntap *) auxptr)->OpenTuntap();
		return 1;
	}
}

int dft_ipc_sync_complete(IPC_CMD_PARMS) {
	if (parent) return 0;

	((Dumpfile_Tuntap *) auxptr)->RegisterIPC();

	return 1;
}

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
	globalreg = in_globalreg;

	tuntap_fd = -1;

	type = "tuntap";

	// If we have a config, push it to the other side
	if (globalreg->kismet_config != NULL) {
		//if (globalreg->kismet_config->FetchOpt("tuntap_export") != "true") {
		if (globalreg->kismet_config->FetchOptBoolean("tuntap_export", 0) != 1) {
			return;
		}

		if ((fname = globalreg->kismet_config->FetchOpt("tuntap_device")) == "") {
			_MSG("No 'tuntap_device' specified in Kismet config file", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return;
		}
	}

	// Register the IPC channel
	if (globalreg->rootipc != NULL) {
		ipc_sync_id =
			globalreg->rootipc->RegisterIPCCmd(&dft_ipc_sync_complete, NULL,
											   this, "SYNCCOMPLETE");
		ipc_trigger_id =
			globalreg->rootipc->RegisterIPCCmd(&dft_ipc_open, NULL, 
											   this, "TUNTAP_TRIGGER");

	}
}

void Dumpfile_Tuntap::RegisterIPC() {
	if (globalreg->rootipc != NULL) {
		ipc_trigger_id =
			globalreg->rootipc->RegisterIPCCmd(&dft_ipc_open, NULL, 
											   this, "TUNTAP_TRIGGER");
	}
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

int Dumpfile_Tuntap::OpenTuntap() {
	// Open the tuntap device and optionally send it over IPC if we're running
	// split-priv
	char errstr[STATUS_MAX];

	if (fname == "")
		return -1;

	// fprintf(stderr, "debug- opentuntap %d\n", getpid());

	// If we have a file name, and we have IPC, assume we need to send it 
	// to the other side of the IPC
	if (globalreg->rootipc != NULL &&
		globalreg->rootipc->FetchSpawnPid() > 0) {
		// fprintf(stderr, "debug- opentuntap rootipc %d\n", getpid());
		if (globalreg->rootipc->FetchRootIPCSynced() <0 ) {
			_MSG("tun/tap driver needs root privileges to create the virtual "
				 "interface, but the root control process doesn't appear to be "
				 "running, tun/tap will not be configured.", MSGFLAG_ERROR);
			return -1;
		}

		ipc_packet *ipc =
			(ipc_packet *) malloc(sizeof(ipc_packet) +
								  sizeof(ipc_dft_open));
		ipc_dft_open *dfto = (ipc_dft_open *) ipc->data;

		ipc->data_len = sizeof(ipc_dft_open);
		ipc->ipc_ack = 0;
		ipc->ipc_cmdnum = ipc_trigger_id;

		snprintf((char *) dfto->tapdevice, 32, "%s", fname.c_str());

		globalreg->rootipc->SendIPC(ipc);

		return 1;
	}

	// fprintf(stderr, "debug- not opentuntap rootipc\n");

#ifdef SYS_LINUX
	// Linux has dynamic tun-tap, so we allocate our device that way
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
		return -1;
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
		return -1;
	}

	// Try to set the link type
	if (ioctl(tuntap_fd, TUNSETLINK, LNX_LINKTYPE_80211) < 0) {
		snprintf(errstr, STATUS_MAX, "Unable to set the tun/tap interface link "
				 "type.  While Kismet will be able to continue, unless the "
				 "program capturing packets is able to handle a broken link "
				 "type it will not work properly.  Make sure you have applied "
				 "the patches to set tun/tap link type.  Exact error was: %s",
				 strerror(errno));
		_MSG(errstr, MSGFLAG_ERROR);
		// globalreg->fatal_condition = 1;
		sleep(1);
		return -1;
	}

	if (ioctl(tuntap_fd, TUNSETNOCSUM, 1) < 0) {
		_MSG("Unable to disable checksumming on tun/tap interface " + fname + ": " +
			 string(strerror(errno)), MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}
#endif

	// Bring up the interface
	if (Ifconfig_Delta_Flags(fname.c_str(), errstr, 
							 (IFF_UP | IFF_RUNNING | IFF_PROMISC)) < 0) {
		_MSG(errstr, MSGFLAG_FATAL);
		_MSG("Failed bringing virtual interface " + fname + " up", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

#ifndef SYS_LINUX
	// Non-linux systems have fixed tun devices, so we open that
	if ((tuntap_fd = open(string("/dev/" + fname).c_str(), O_RDWR)) < 0) {
		_MSG("Unable to open tun/tap interface " + fname + ": " +
			 string(strerror(errno)), MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

#endif

	_MSG("Opened tun/tap replicator '" + fname + "'", MSGFLAG_INFO);
	// printf("debug - %d opened tun/tap replicator\n", getpid());

	if (globalreg->rootipc != NULL) {
		// printf("debug - %d - calling senddescriptor\n", getpid());
		if (globalreg->rootipc->SendDescriptor(tuntap_fd) < 0) {
			_MSG("tuntap failed to send tap descriptor over IPC", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
		}

		ipc_packet *ipc =
			(ipc_packet *) malloc(sizeof(ipc_packet) +
								  sizeof(ipc_dft_open));
		ipc_dft_open *dfto = (ipc_dft_open *) ipc->data;

		ipc->data_len = sizeof(ipc_dft_open);
		ipc->ipc_ack = 0;
		ipc->ipc_cmdnum = ipc_trigger_id;

		dfto->tapdevice[0] = 0;

		// printf("debug - %d queueing senddescriptor trigger command\n", getpid());
		globalreg->rootipc->SendIPC(ipc);
	} else {
		// Otherwise we're running with no privsep so register ourselves
		globalreg->packetchain->RegisterHandler(&dumpfiletuntap_chain_hook, this,
												CHAINPOS_LOGGING, -100);
		globalreg->RegisterDumpFile(this);
	}

	return 0;
}

int Dumpfile_Tuntap::GetTapFd() {
	// Get the descriptor form the root IPC
	if (globalreg->rootipc == NULL)
		return -1;

	tuntap_fd = globalreg->rootipc->ReceiveDescriptor();

	return tuntap_fd;
}

int Dumpfile_Tuntap::Flush() {
	// Nothing to see here
	return 0;
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
			 (kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_DECAP))) == NULL) {
			if ((chunk = (kis_datachunk *) 
				 in_pack->fetch(_PCM(PACK_COMP_LINKFRAME))) == NULL) {
				return 0;
			}
		}
	}

	// May not be safe, do we need a ringbuffer?  Keep in mind of we have
	// hanging problems
	if (write(tuntap_fd, chunk->data, chunk->length) <= 0)
		return 0;

	dumped_frames++;

	return 1;
}

#endif

