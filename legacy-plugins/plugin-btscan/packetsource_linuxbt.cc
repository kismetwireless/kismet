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

#include <vector>

#include <util.h>
#include <messagebus.h>
#include <packet.h>
#include <packetchain.h>
#include <packetsource.h>
#include <packetsourcetracker.h>
#include <timetracker.h>
#include <configfile.h>
#include <plugintracker.h>
#include <globalregistry.h>
#include <dumpfile.h>
#include <pcap.h>

#include "packetsource_linuxbt.h"
#include "packet_btscan.h"

PacketSource_LinuxBT::PacketSource_LinuxBT(GlobalRegistry *in_globalreg, 
										   string in_interface,
										   vector<opt_pair> *in_opts) : 
	KisPacketSource(in_globalreg, in_interface, in_opts) {

	thread_active = 0;
	hci_dev_id = -1;
	hci_dev = -1;

	fake_fd[0] = -1;
	fake_fd[1] = -1;

	pending_packet = 0;

	bt_scan_delay = 1;
	bt_scan_time = 4;

	linuxbt_packet_id = globalreg->packetchain->RegisterPacketComponent("BTSCAN");

	ParseOptions(in_opts);
}

PacketSource_LinuxBT::~PacketSource_LinuxBT() {
	CloseSource();
}
	

int PacketSource_LinuxBT::ParseOptions(vector<opt_pair> *in_opts) {
	KisPacketSource::ParseOptions(in_opts);

	if (FetchOpt("scandelay", in_opts) != "") {
		if (sscanf(FetchOpt("scandelay", in_opts).c_str(), "%d", &bt_scan_delay) != 1) {
			_MSG("BTSCAN device " + interface + " invalid scandelay= option, expected "
				 "number in seconds.", MSGFLAG_ERROR);
			return -1;
		}

		_MSG("BTSCAN device " + interface + " delaying " + IntToString(bt_scan_delay) + 
			 " seconds between initiating scans.", MSGFLAG_INFO);
	}

	return 1;
}

int PacketSource_LinuxBT::AutotypeProbe(string in_device) {
	if (hci_devid(in_device.c_str()) >= 0) {
		type = "BTSCAN";
		return 1;
	}

	return 0;
}

// Capture thread to fake async io
void *linuxbt_cap_thread(void *arg) {
	PacketSource_LinuxBT *linuxbt = (PacketSource_LinuxBT *) arg;

	/* Clear the thread sigmask so we don't catch sigterm weirdly */
	sigset_t sset;
	sigfillset(&sset);
	pthread_sigmask(SIG_BLOCK, &sset, NULL);

	char hci_name[KIS_LINUXBT_NAME_MAX];
	char hci_class[KIS_LINUXBT_CLASS_MAX];
	inquiry_info *hci_inq = NULL;
	int hci_num_dev = 0;

	// printf("debug - cap thread\n");

	while (linuxbt->thread_active > 0) {
		// printf("debug - thread active, top of loop\n");

		// Lock the device, do a blocking read of info, then sleep (if any)
		// printf("debug - locking device lock\n");
		pthread_mutex_lock(&(linuxbt->device_lock));

		if ((hci_num_dev = hci_inquiry(linuxbt->hci_dev_id, linuxbt->bt_scan_time,
									   100, NULL, &hci_inq, 0)) <= 0) {
			// printf("debug - hci inq failed out\n");
			pthread_mutex_unlock(&(linuxbt->device_lock));
			sleep(linuxbt->bt_scan_delay);
			continue;
		}

		for (int x = 0; x < hci_num_dev; x++) {
			memset(hci_name, 0, KIS_LINUXBT_NAME_MAX);

			if ((hci_read_remote_name(linuxbt->hci_dev, &(hci_inq + x)->bdaddr,
									  KIS_LINUXBT_NAME_MAX, hci_name, 250000)) < 0) {
				// printf("debug - hci read remote failed out\n");
				continue;
			}

			// Lock the queue, throw away if we have more than 100 records pending in
			// the queue that haven't been handled, and raise the FD high if we need
			// to, to get Poll() to start paying attention to us

			pthread_mutex_lock(&(linuxbt->packet_lock));

			if (linuxbt->packet_queue.size() > 100) {
				pthread_mutex_unlock(&(linuxbt->packet_lock));
				continue;
			}

			struct PacketSource_LinuxBT::linuxbt_pkt *rpkt = 
				new PacketSource_LinuxBT::linuxbt_pkt;
			char classbuf[8];
			uint8_t swapmac[6];

			for (unsigned int s = 0; s < 6; s++) {
				swapmac[s] = (hci_inq + x)->bdaddr.b[5 - s];
			}

			rpkt->bd_name = string(hci_name);
			rpkt->bd_addr = mac_addr(swapmac, 6);
			snprintf(classbuf, 6, "%2.2x%2.2x%2.2x",
					 (hci_inq + x)->dev_class[2],
					 (hci_inq + x)->dev_class[1],
					 (hci_inq + x)->dev_class[0]);
			rpkt->bd_class = "0x" + string(classbuf);

			linuxbt->packet_queue.push_back(rpkt);

			if (linuxbt->pending_packet == 0) {
				linuxbt->pending_packet = 1;
				write(linuxbt->fake_fd[1], rpkt, 1);
			}

			pthread_mutex_unlock(&(linuxbt->packet_lock));
		}

		sleep(linuxbt->bt_scan_delay);

		// printf("debug - unlocking device lock\n");
		pthread_mutex_unlock(&(linuxbt->device_lock));
	}

	linuxbt->thread_active = -1;
	close(linuxbt->fake_fd[1]);
	linuxbt->fake_fd[1] = -1;
	pthread_exit((void *) 0);
}

int PacketSource_LinuxBT::OpenSource() {
	if ((hci_dev_id = hci_devid(interface.c_str())) < 0) {
		_MSG("Linux BTSCAN '" + name + "' failed to open device '" + interface + "': " +
			 "Invalid bluetooth device", MSGFLAG_ERROR);
		return 0;
	} 

	if ((hci_dev = hci_open_dev(hci_dev_id)) < 0) {
		_MSG("Linux BTSCAN '" + name + "' failed to open device '" + interface + "': " +
			 string(strerror(errno)), MSGFLAG_ERROR);
		return 0;
	}

	/* Initialize the pipe, mutex, and reading thread */
	if (pipe(fake_fd) < 0) {
		_MSG("Linux BTSCAN '" + name + "' failed to make a pipe() (this is really "
			 "weird): " + string(strerror(errno)), MSGFLAG_ERROR);
		hci_dev_id = -1;
		return 0;
	}

	if (pthread_mutex_init(&packet_lock, NULL) < 0 ||
		pthread_mutex_init(&device_lock, NULL) < 0) {
		_MSG("Linux BTSCAN '" + name + "' failed to initialize pthread mutex: " +
			 string(strerror(errno)), MSGFLAG_ERROR);
		hci_dev_id = -1;
		return 0;
	}

	/* Launch a capture thread */
	thread_active = 1;
	pthread_create(&cap_thread, NULL, linuxbt_cap_thread, this);

	return 1;
}

int PacketSource_LinuxBT::CloseSource() {
	void *ret;

	if (thread_active > 0) {
		// Tell the thread to die
		thread_active = 0;

		// Kill it
		// printf("debug - thread cancel\n");
		pthread_cancel(cap_thread);

		// Grab it back
		// printf("debug - thread join\n");
		pthread_join(cap_thread, &ret);

		// Kill the mutexes
		pthread_mutex_destroy(&device_lock);
		pthread_mutex_destroy(&packet_lock);
	}

	if (hci_dev >= 0)
		hci_close_dev(hci_dev);

	hci_dev = -1;

	if (fake_fd[0] >= 0) {
		close(fake_fd[0]);
		fake_fd[0] = -1;
	}

	if (fake_fd[1] >= 0) {
		close(fake_fd[1]);
		fake_fd[1] = -1;
	}

	// printf("debug - done closing source\n");

	return 1;
}

int PacketSource_LinuxBT::FetchDescriptor() {
	// This is as good a place as any to catch a failure
	if (thread_active < 0) {
		_MSG("Linux BTSCAN '" + name + "' capture thread failed: " +
			 thread_error, MSGFLAG_INFO);
		CloseSource();
		return -1;
	}

	return fake_fd[0];
}

int PacketSource_LinuxBT::Poll() {
	char rx;

	// Consume the junk byte we used to raise the FD high
	read(fake_fd[0], &rx, 1);

	pthread_mutex_lock(&packet_lock);

	pending_packet = 0;

	for (unsigned int x = 0; x < packet_queue.size(); x++) {
		kis_packet *newpack = globalreg->packetchain->GeneratePacket();

		newpack->ts.tv_sec = globalreg->timestamp.tv_sec;
		newpack->ts.tv_usec = globalreg->timestamp.tv_usec;

		btscan_packinfo *pi = new btscan_packinfo;

		pi->bd_name = packet_queue[x]->bd_name;
		pi->bd_class = packet_queue[x]->bd_class;
		pi->bd_addr = packet_queue[x]->bd_addr;

		newpack->insert(linuxbt_packet_id, pi);

		// printf("debug - got BT device %s %s %s\n", pi->bd_addr.Mac2String().c_str(), pi->bd_name.c_str(), pi->bd_class.c_str());

		num_packets++;

		kis_ref_capsource *csrc_ref = new kis_ref_capsource;
		csrc_ref->ref_source = this;
		newpack->insert(_PCM(PACK_COMP_KISCAPSRC), csrc_ref);

		globalreg->packetchain->ProcessPacket(newpack);

		// Delete the packet queue
		delete packet_queue[x];
	}

	// Flush the queue
	packet_queue.clear();

	// printf("debug - packet queue cleared %d\n", packet_queue.size());

	pthread_mutex_unlock(&packet_lock);

	return 1;
}

#endif

