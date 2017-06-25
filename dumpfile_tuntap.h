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

#ifndef __DUMPFILE_TUNTAP_H__
#define __DUMPFILE_TUNTAP_H__

/* 
 * TUN/TAP dumpfile module
 *
 * This writes 802.11 frames to the userspace end of a tun/tap virtual network
 * device.  Any other packet capture device can attach to this interface then
 * and get a runtime packet stream from Kismet, which is really cool.  This is
 * much less fragile than the named pipe output, because Kismet doesn't care
 * what is listening to the interface or when.
 *
 * This currently only works on Linux, but should be portable to any system 
 * which supports the tun/tap interface model (BSD and OSX should).
 *
 * To work fully on Linux it needs a patch which will, with luck, be mainlained
 * eventually.  Without the patch, the tap device will always be a en10mb link
 * type, which will confuse pcap and anything sniffing since it's not en10mb
 * frames.  Any listening device SHOULD be able to retranslate to a different
 * link type, but the kernel patch solves this problem fully.
 *
 * This is a bizzare not-quite-normal dumpfile module.  It doesn't parse the
 * normal dumptypes string, and it has to be started before the root privdrop.
 * It's closer to a dumpfile than anything else though, and the flush/close/
 * track system isn't worth duplicating.
 */

#include "config.h"

#include <string>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

/* Linux system includes */
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include "globalregistry.h"
#include "configfile.h"
#include "messagebus.h"
#include "packetchain.h"
#include "dumpfile.h"

#ifdef SYS_LINUX 
#include <linux/if_tun.h>

// Linux IEEE80211 link typ to set
#define LNX_LINKTYPE_80211		801
// If the system headers don't have the TUNSETLINK ioctl, define it here,
// and we'll figure it out at runtime
#ifndef TUNSETLINK
#define TUNSETLINK				_IOW('T', 205, int)
#endif

#endif

struct ipc_dft_open {
	uint8_t tapdevice[32];
};

// Hook for grabbing packets
int dumpfiletuntap_chain_hook(CHAINCALL_PARMS);

// Pcap-based packet writer
class Dumpfile_Tuntap : public Dumpfile {
public:
	Dumpfile_Tuntap();
	Dumpfile_Tuntap(GlobalRegistry *in_globalreg);
	virtual ~Dumpfile_Tuntap();

	virtual int OpenTuntap();
	virtual int GetTapFd();
	virtual void SetTapDevice(string in_dev) { fname = in_dev; }

	virtual void RegisterIPC();

	virtual int chain_handler(kis_packet *in_pack);
	virtual int Flush();
protected:
	int tuntap_fd;
	int ipc_sync_id, ipc_trigger_id;
};

#endif /* __dump... */
	
