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

#ifndef __PACKETSOURCE_LINUXBT_H__
#define __PACKETSOURCE_LINUXBT_H__

#include <config.h>

#ifdef SYS_LINUX

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#include <fcntl.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <netinet/in.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <pthread.h>

#include <string>

#include <packetsource.h>
#include <macaddr.h>

#define USE_PACKETSOURCE_LINUXBT

#define KIS_LINUXBT_NAME_MAX	16
#define KIS_LINUXBT_CLASS_MAX	9

class PacketSource_LinuxBT : public KisPacketSource {
public:
	PacketSource_LinuxBT() {
		fprintf(stderr, "FATAL OOPS: Packetsource_Raven()\n");
		exit(1);
	}

	PacketSource_LinuxBT(GlobalRegistry *in_globalreg) :
		KisPacketSource(in_globalreg) {

	}

	virtual KisPacketSource *CreateSource(GlobalRegistry *in_globalreg,
										  string in_interface,
										  vector<opt_pair> *in_opts) {
		return new PacketSource_LinuxBT(in_globalreg, in_interface, in_opts);
	}

	virtual int AutotypeProbe(string in_device);

	virtual int RegisterSources(Packetsourcetracker *tracker) {
		// Use a channel list we assign in the main loader to a single channel,
		// we're also not hoppable in the Kismet sense
		tracker->RegisterPacketProto("btscan", this, "LINUXBTSCAN", 0);
		return 1;
	}

	PacketSource_LinuxBT(GlobalRegistry *in_globalreg, string in_interface,
						 vector<opt_pair> *in_opts);

	virtual ~PacketSource_LinuxBT();

	virtual int ParseOptions(vector<opt_pair> *in_opts);

	virtual int OpenSource();
	virtual int CloseSource();

	// We're not, since we're a fake scanning device
	virtual int FetchChannelCapable() { return 0; }
	virtual int EnableMonitor() { return 1; }
	virtual int DisableMonitor() { return 1; }

	virtual int FetchChannel() { return -1; }
	virtual int FetchChannelMod() { return -1; }

	// We don't
	virtual int SetChannel(unsigned int in_ch) { return 0; };

	// We use a fake FD like the raven (plugin-dot15d4) does
	virtual int FetchDescriptor();
	virtual int Poll();

	struct linuxbt_pkt {
		string bd_name;
		string bd_class;
		mac_addr bd_addr;
	};

protected:
	virtual void FetchRadioData(kis_packet *in_packet) { };

	int linuxbt_packet_id;

	// We spawn a thread to control scanning since the HCI calls are blocking
	// and take a long time.  We pass packets via locking like we do on raven,
	// if we have a dozen devices in a scan we'll lock and kick them out
	int thread_active;

	pthread_t cap_thread;
	pthread_mutex_t packet_lock, device_lock;

	int hci_dev_id, hci_dev;
	// Delay between scans (seconds)
	int bt_scan_delay;
	// Time for each scan (unknown - seconds?)
	int bt_scan_time;

	// FD pipes
	int fake_fd[2];

	// Packet storage, locked with packet_lock
	vector<struct linuxbt_pkt *> packet_queue;

	// Pending packet, locked with packet_lock
	int pending_packet;

	// Error from thread
	string thread_error;

	friend void *linuxbt_cap_thread(void *);
};
#endif

#endif
