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

#include "packetsource_raven.h"
#include "packet_dot15d4.h"

PacketSource_Raven::PacketSource_Raven(GlobalRegistry *in_globalreg, string in_interface,
									   vector<opt_pair> *in_opts) : 
	KisPacketSource(in_globalreg, in_interface, in_opts) {

	thread_active = 0;
	devhdl = NULL;

	fake_fd[0] = -1;
	fake_fd[1] = -1;

	pending_packet = 0;

	d154_packet_id = globalreg->packetchain->RegisterPacketComponent("IEEE802_15_4");

	ParseOptions(in_opts);
}

PacketSource_Raven::~PacketSource_Raven() {
	CloseSource();
}
	

int PacketSource_Raven::ParseOptions(vector<opt_pair> *in_opts) {
	KisPacketSource::ParseOptions(in_opts);

	if (FetchOpt("device", in_opts) != "") {
		usb_dev = FetchOpt("usbdev", in_opts);
		_MSG("RAVEN 802.15.4 using USB device '" + usb_dev + "'", MSGFLAG_INFO);
	} else {
		_MSG("RAVEN 802.15.4 using first USB device that looks like an ATAVRRZUSB",
			 MSGFLAG_INFO);
	}

	return 1;
}

int PacketSource_Raven::AutotypeProbe(string in_device) {
	// Shortcut like we do on airport
	if (in_device == "raven") {
		type = "raven";
		return 1;
	}

	return 0;
}

// Capture thread to fake async io
void *raven_cap_thread(void *arg) {
	PacketSource_Raven *raven = (PacketSource_Raven *) arg;
	int len = 0;
	char *pkt;

	// printf("debug - cap thread\n");

	while (raven->thread_active > 0) {
		pkt = new char[2048];

		// Do a timered read since we need to catch when the thread is scheduled
		// to die.  This uses more CPU.  That's unfortunate.
		pthread_mutex_lock(&(raven->device_lock));
		if ((len = usb_bulk_read(raven->devhdl, 0x81, pkt, 2048, 1000)) < 0) {
			if (errno != EAGAIN) {
				raven->thread_error = string(usb_strerror());
				pthread_mutex_unlock(&(raven->device_lock));
				break;
			} else {
				len = 0;
			}
		}
		pthread_mutex_unlock(&(raven->device_lock));

		if (len == 0) {
			delete[] pkt;
			continue;
		}

		// printf("debug - thread got packet len %d\n", len);

		// Lock the packet queue, throw away when there are more than 20 in the queue
		// that haven't been handled, raise the file descriptor hot if we need to
		pthread_mutex_lock(&(raven->packet_lock));

		if (raven->packet_queue.size() > 20) {
			// printf("debug - thread packet queue to big\n");
			delete[] pkt;
			pthread_mutex_unlock(&(raven->packet_lock));
			continue;
		}

		struct PacketSource_Raven::raven_pkt *rpkt = new PacketSource_Raven::raven_pkt;
		rpkt->data = pkt;
		rpkt->len = len;
		rpkt->channel = raven->last_channel;

		raven->packet_queue.push_back(rpkt);
		if (raven->pending_packet == 0) {
			// printf("debug - writing to fakefd\n");
			raven->pending_packet = 1;
			write(raven->fake_fd[1], pkt, 1);
		}

		pthread_mutex_unlock(&(raven->packet_lock));
	}

	raven->thread_active = -1;
	close(raven->fake_fd[1]);
	raven->fake_fd[1] = -1;
	pthread_exit((void *) 0);
}

int PacketSource_Raven::OpenSource() {
	struct usb_bus *bus = NULL;
	struct usb_device *dev = NULL;
	// Linux uses numbers, others might use strings
	int dev_cmp_id, dev_bus_id, found = 0;

	usb_init();
	usb_find_busses();
	usb_find_devices();

	if (sscanf(usb_dev.c_str(), "%d", &dev_cmp_id) != 1)
		dev_cmp_id = -1;

	for (bus = usb_busses; bus; bus = bus->next) {
		for (dev = bus->devices; dev; dev = dev->next) {
			if (dev->descriptor.idVendor != 0x03EB ||
				dev->descriptor.idProduct != 0x210A)
				continue;

			// Match first if we don't care
			if (usb_dev == "") {
				found = 1;
				break;
			}

			// Match string if we can
			if (string(dev->filename) == usb_dev) {
				found = 1;
				break;
			}

			// Match int if it looks like a number (ie, linux id)
			if (sscanf(dev->filename, "%d", &dev_bus_id) == 1) {
				if (dev_cmp_id == dev_bus_id) {
					found = 1;
					break;
				}
			}
		}

		if (found)
			break;
	}

	if (found == 0) {
		if (usb_dev == "") {
			_MSG("RAVEN 802.15.4 unable to find any device which looked like an "
				 "ATAVRRZUSB", MSGFLAG_ERROR);
			return 0;
		} else {
			_MSG("RAVEN 802.15.4 '" + name + "' unable to find device '" + 
				 usb_dev + "'.  The USB device id changes each time the device is "
				 "added or removed.  Most times it will work better to let Kismet "
				 "find the device automatically.", MSGFLAG_ERROR);
			return 0;
		}
	}

	if (usb_dev == "")
		usb_dev = string(dev->filename);

	if ((devhdl = usb_open(dev)) == NULL) {
		_MSG("RAVEN 802.15.4 '" + name + "' failed to open device '" + usb_dev + "': " +
			 string(strerror(errno)), MSGFLAG_ERROR);
		return 0;
	}

	/*
	if (usb_detatch_kernel_driver_np(devhdl, 0) < 0) {
	}
	*/

	usb_set_configuration(devhdl, 1);

	if (usb_claim_interface(devhdl, 0) < 0) {
		_MSG("RAVEN 802.15.4 '" + name + "' failed to claim interface '" + usb_dev + 
			 "': " + string(usb_strerror()), MSGFLAG_ERROR);
		return 0;
	}

	/* Initialize the device, may fail if the device is already initialized, we
	 * don't really care if that happens */
	char init_cmd[1];
	init_cmd[0] = 0x09;
	usb_bulk_write(devhdl, 0x02, init_cmd, 1, 10);
	usb_bulk_read(devhdl, 0x84, init_cmd, 1, 10);

	/* Initialize the pipe, mutex, and reading thread */
	if (pipe(fake_fd) < 0) {
		_MSG("RAVEN 802.15.4 '" + name + "' failed to make a pipe() (this is really "
			 "weird): " + string(strerror(errno)), MSGFLAG_ERROR);
		usb_close(devhdl);
		devhdl = NULL;
		return 0;
	}

	if (pthread_mutex_init(&packet_lock, NULL) < 0 ||
		pthread_mutex_init(&device_lock, NULL) < 0) {
		_MSG("RAVEN 802.15.4 '" + name + "' failed to initialize pthread mutex: " +
			 string(strerror(errno)), MSGFLAG_ERROR);
		usb_close(devhdl);
		devhdl = NULL;
		return 0;
	}

	/* Launch a capture thread */
	thread_active = 1;
	pthread_create(&cap_thread, NULL, raven_cap_thread, this);

	return 1;
}

int PacketSource_Raven::CloseSource() {
	void *ret;

	if (thread_active > 0) {
		// Tell the thread to die
		thread_active = 0;

		// Grab it back
		pthread_join(cap_thread, &ret);

		// Kill the mutexes
		pthread_mutex_destroy(&device_lock);
		pthread_mutex_destroy(&packet_lock);
	}

	// Close the USB dev
	if (devhdl) {
		usb_close(devhdl);
		devhdl = NULL;
	}

	if (fake_fd[0] >= 0) {
		close(fake_fd[0]);
		fake_fd[0] = -1;
	}

	if (fake_fd[1] >= 0) {
		close(fake_fd[1]);
		fake_fd[1] = -1;
	}

	return 1;
}

int PacketSource_Raven::SetChannel(unsigned int in_ch) {
	char data[2];
	int ret;

	if (in_ch < 11 || in_ch > 26)
		return -1;

	if (thread_active <= 0 || devhdl == NULL)
		return 0;

	data[0] = 0x07;
	data[1] = 0x00;

	if ((ret = usb_bulk_write(devhdl, 0x02, data, 2, 10)) < 0) {
		_MSG("RAVEN 802.15.4 '" + name + "' failed to write channel control: " +
			 string(usb_strerror()), MSGFLAG_ERROR);
		return -1;
	}

	data[0] = 0x08;
	data[1] = (in_ch & 0xFF);

	if ((ret = usb_bulk_write(devhdl, 0x02, data, 2, 10)) < 0) {
		_MSG("RAVEN 802.15.4 '" + name + "' failed to write channel control: " +
			 string(usb_strerror()), MSGFLAG_ERROR);
		return -1;
	}

	usb_bulk_read(devhdl, 0x84, data, 1, 10);

	last_channel = in_ch;

	return 1;
}

int PacketSource_Raven::FetchDescriptor() {
	// This is as good a place as any to catch a failure
	if (thread_active < 0) {
		_MSG("RAVEN 802.15.4 '" + name + "' capture thread failed: " +
			 thread_error, MSGFLAG_INFO);
		CloseSource();
		return -1;
	}

	return fake_fd[0];
}

int PacketSource_Raven::Poll() {
	char rx;

	// Consume the junk byte we used to raise the FD high
	read(fake_fd[0], &rx, 1);

	pthread_mutex_lock(&packet_lock);

	pending_packet = 0;

	for (unsigned int x = 0; x < packet_queue.size(); x++) {
		kis_packet *newpack = globalreg->packetchain->GeneratePacket();

		newpack->ts.tv_sec = globalreg->timestamp.tv_sec;
		newpack->ts.tv_usec = globalreg->timestamp.tv_usec;

		if (packet_queue[x]->len <= 9) {
			delete[] packet_queue[x]->data;
			continue;
		}

		kis_datachunk *rawchunk = new kis_datachunk;

		// Offset by the 9 bytes of junk at the beginning
		rawchunk->length = packet_queue[x]->len - 9;
		// Copy the packet w/out the crap from the raven (interpret RSSI later)
		rawchunk->data = new uint8_t[rawchunk->length];
		memcpy(rawchunk->data, packet_queue[x]->data + 9, rawchunk->length);
		rawchunk->source_id = source_id;

		rawchunk->dlt = KDLT_IEEE802_15_4;

		newpack->insert(_PCM(PACK_COMP_LINKFRAME), rawchunk);

		// printf("debug - Got packet chan %d len=%d\n", packet_queue[x]->channel, packet_queue[x]->len);

		num_packets++;

		globalreg->packetchain->ProcessPacket(newpack);

		// Delete the temp struct and data
		delete packet_queue[x]->data;
		delete packet_queue[x];
	}

	// Flush the queue
	packet_queue.clear();

	// printf("debug - packet queue cleared %d\n", packet_queue.size());

	pthread_mutex_unlock(&packet_lock);

	return 1;
}

#endif

