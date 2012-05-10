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

#ifndef __PACKETSOURCE_SERIALDEV_H__
#define __PACKETSOURCE_SERIALDEV_H__

#include "config.h"

#include <usb.h>
#include <pthread.h>

#include <packetsource.h>
#include <serialclient.h>

#define USE_PACKETSOURCE_SERIALDEV

// All commands are 3 bytes
#define SERIALDEV_CMD_OPEN		((uint8_t *) "zb\x01")
#define SERIALDEV_CMD_CLOSE		((uint8_t *) "zb\x02")
// u8 setchan u8 channel, base 1
#define SERIALDEV_CMD_SETCHAN	((uint8_t *) "zb\x04")
#define SERIALDEV_CMD_ED		((uint8_t *) "zb\x05")
#define SERIALDEV_CMD_CCA		((uint8_t *) "zb\x06")
// u8 setstate u8 state
#define SERIALDEV_CMD_SETSTATE	((uint8_t *) "zb\x07")
#define SERIALDEV_CMD_XMITDATA	((uint8_t *) "zb\x09")
#define SERIALDEV_CMD_RECV		((uint8_t *) "zb\x0b")

#define SERIALDEV_CMD_LEDTEST	((uint8_t *) "zb\xF0")
#define SERIALDEV_CMD_GETNAME	((uint8_t *) "zb\xF1");
// u8 sethwchan u8 lowerchannels u8 upperchannels u8 rate-per-sec u8 trafficdelay
#define SERIALDEV_CMD_SETHWCHAN	((uint8_t *) "zb\xF2")

#define SERIALDEV_STATUS_SUCCESS	0
#define SERIALDEV_STATUS_RX_ON		1
#define SERIALDEV_STATUS_TX_ON		2
#define SERIALDEV_STATUS_TRX_OFF	3
#define SERIALDEV_STATUS_IDLE		4
#define SERIALDEV_STATUS_BUSY		5
#define SERIALDEV_STATUS_BUSY_RX	6
#define SERIALDEV_STATUS_BUSY_TX	7
#define SERIALDEV_STATUS_ERR		8

// u8 id u8 status
#define SERIALDEV_RESP_OPEN			0x81
// u8 id u8 status
#define SERIALDEV_RESP_CLOSE		0x82
// u8 id u8 status
#define SERIALDEV_RESP_SETCHAN		0x84
// u8 id u8 status u8 level
#define SERIALDEV_RESP_ED			0x85
// u8 id u8 status
#define SERIALDEV_RESP_CCA			0x86
// u8 id u8 status
#define SERIALDEV_RESP_SETSTATE		0x87
// u8 id u8 status
#define SERIALDEV_RESP_XMITDATA		0x89
// u8 id u8 lq u8 len u8 data[]
#define SERIALDEV_RESP_RECVBLOCK	0x8b
// u8 id u8 c
#define SERIALDEV_RESP_RECVSTREAM	0x8c

// u8 id u8 len u8 data[]
#define SERIALDEV_RESP_GETNAME		0xd1
#define SERIALDEV_RESP_SETHWCHAN	0xd2
// u8 id u8 lq u8 chan u8 len u8 data[]
#define SERIALDEV_RESP_RECVBLOCKHW	0xc2

#define SERIALDEV_MODE_IDLE			0x00
#define SERIALDEV_MODE_RX			0x02
#define SERIALDEV_MODE_TX			0x03
// HW channel-control assisted rx
#define SERIALDEV_MODE_HWRX			0xF0

#define D15D4_MAX_MTU			127

class PacketSource_Serialdev;

class d15d4_serialdev_helper : public ClientFramework {
public:
	d15d4_serialdev_helper() { fprintf(stderr, "FATAL OOPS: serialdev_helper\n"); exit(1); }
	d15d4_serialdev_helper(GlobalRegistry *in_globalreg);
	virtual ~d15d4_serialdev_helper();

	int OpenSerialDev(string in_dev);

	virtual int MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
		return netclient->MergeSet(in_max_fd, out_rset, out_wset);
	}

	virtual int Poll(fd_set& in_rset, fd_set& in_wset) {
		return netclient->Poll(in_rset, in_wset);
	}

	virtual int ParseData();
	virtual int Shutdown();
	virtual int Reconnect();

	virtual void AddPacketsource(PacketSource_Serialdev *in_src) {
		packetsource = in_src;
	}

	virtual int SendCommand(uint8_t *command, unsigned int in_len, uint8_t *in_data);

protected:
	SerialClient *sercli;
	PacketSource_Serialdev *packetsource;

	string device;

	// Asynch states of current ID, length, etc
	int state, s_id, s_len, s_rlen, s_status, s_level;

	// States:
	// 1 - 'z'
	// 2 - 'b'
	// 3 - id
	// 4 - id subhandler

	// Data (packets are small). 
	uint8_t pkt_data[D15D4_MAX_MTU];
};

class PacketSource_Serialdev : public KisPacketSource {
public:
	PacketSource_Serialdev() {
		fprintf(stderr, "FATAL OOPS: Packetsource_Serialdev()\n");
		exit(1);
	}

	PacketSource_Serialdev(GlobalRegistry *in_globalreg) :
		KisPacketSource(in_globalreg) {

	}

	virtual KisPacketSource *CreateSource(GlobalRegistry *in_globalreg,
										  string in_interface,
										  vector<opt_pair> *in_opts) {
		return new PacketSource_Serialdev(in_globalreg, in_interface, in_opts);
	}

	virtual int AutotypeProbe(string in_device);

	virtual int RegisterSources(Packetsourcetracker *tracker) {
		tracker->RegisterPacketProto("d15d4serial", this, "IEEE802154", 0);
		return 1;
	}

	PacketSource_Serialdev(GlobalRegistry *in_globalreg, string in_interface,
						   vector<opt_pair> *in_opts);

	virtual ~PacketSource_Serialdev();

	virtual int ParseOptions(vector<opt_pair> *in_opts);

	virtual int OpenSource();
	virtual int CloseSource();

	virtual int FetchChannelCapable() { return 1; }
	virtual int EnableMonitor() { return 1; }
	virtual int DisableMonitor() { return 1; }

	// Throttle us to something sane
	virtual int FetchChannelMaxVelocity() { return 3; }

	virtual int SetChannel(unsigned int in_ch);

	virtual int FetchDescriptor();
	virtual int Poll();

	// This is stupid but i'm tired
	struct serial_pkt {
		uint8_t *data;
		unsigned int len; 
		struct timeval ts;
		unsigned int channel;
		unsigned int sig_lq;
	};

protected:
	virtual void FetchRadioData(kis_packet *in_packet) { };

	virtual void QueuePacket(unsigned int in_len, uint8_t *in_data, 
							 unsigned int in_sig);

	int d154_packet_id;

	// Serial port to use
	string serialport;

	int fake_fd[2];

	vector<struct serial_pkt *> packet_queue;

	int pending_packet;

	d15d4_serialdev_helper *helper;

	friend class d15d4_serialdev_helper;
};

#endif
