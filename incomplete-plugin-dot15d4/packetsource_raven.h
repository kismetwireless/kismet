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

#ifndef __PACKETSOURCE_RAVEN_H__
#define __PACKETSOURCE_RAVEN_H__

#include "config.h"

#ifdef SYS_LINUX

#include <usb.h>
#include <pthread.h>

#include <packetsource.h>

#define USE_PACKETSOURCE_RAVEN

class PacketSource_Raven : public KisPacketSource {
public:
	PacketSource_Raven() {
		fprintf(stderr, "FATAL OOPS: Packetsource_Raven()\n");
		exit(1);
	}

	PacketSource_Raven(GlobalRegistry *in_globalreg) :
		KisPacketSource(in_globalreg) {

	}

	virtual KisPacketSource *CreateSource(GlobalRegistry *in_globalreg,
										  string in_interface,
										  vector<opt_pair> *in_opts) {
		return new PacketSource_Raven(in_globalreg, in_interface, in_opts);
	}

	virtual int AutotypeProbe(string in_device);

	virtual int RegisterSources(Packetsourcetracker *tracker) {
		tracker->RegisterPacketProto("raven", this, "IEEE802154", 0);
		return 1;
	}

	PacketSource_Raven(GlobalRegistry *in_globalreg, string in_interface,
					   vector<opt_pair> *in_opts);

	virtual ~PacketSource_Raven();

	virtual int ParseOptions(vector<opt_pair> *in_opts);

	virtual int OpenSource();
	virtual int CloseSource();

	virtual int FetchChannelCapable() { return 1; }
	virtual int EnableMonitor() { return 1; }
	virtual int DisableMonitor() { return 1; }

	// We seem to crash the default & killerbee firmwares if we hop more rapidly
	// than 3 times a second, throttle us.
	virtual int FetchChannelMaxVelocity() { return 3; }

	virtual int SetChannel(unsigned int in_ch);

	virtual int FetchDescriptor();
	virtual int Poll();

	struct raven_pkt {
		char *data;
		int len;
		int channel;
	};

protected:
	virtual void FetchRadioData(kis_packet *in_packet) { };

	int d154_packet_id;

	int thread_active;

	/* Screw libusb and their crappy IO options - libusb 0.12 API, no
	 * async IO ...  libusb 1.x, async io can't be used in plugins and contaminates
	 * all of the select loop code which makes it impossible to use in plugins */
	pthread_t cap_thread;
	pthread_mutex_t packet_lock, device_lock;

	// Named USB interface
	string usb_dev;

	struct usb_dev_handle *devhdl;

	// FD pipes
	int fake_fd[2];

	// Packet storage, locked with packet_lock
	vector<struct raven_pkt *> packet_queue;

	// Pending packet, locked with packet_lock
	int pending_packet;

	// Error from thread
	string thread_error;

	friend void *raven_cap_thread(void *);
};

#endif

#endif

