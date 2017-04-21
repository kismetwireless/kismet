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

#ifndef __SPECTOOLCLIENT_H__
#define __SPECTOOLCLIENT_H__

#include "config.h"

#include "clinetframework.h"
#include "tcpclient.h"
#include "kis_netframe.h"
#include "packetchain.h"

#define WISPY_NET_FRAME_DEVICE		0x00
#define WISPY_NET_FRAME_SWEEP		0x01
#define WISPY_NET_FRAME_COMMAND		0x02
#define WISPY_NET_FRAME_MESSAGE		0x03

#define WISPY_NET_SENTINEL			0xDECAFBAD

#define WISPY_NET_PROTO_VERSION		0x01

#define WISPY_NET_DEFAULT_PORT		30569

typedef struct _wispy_fr_header {
	uint32_t sentinel;
	uint16_t frame_len;
	uint8_t proto_version;
	uint8_t block_type;
	uint8_t num_blocks;
	uint8_t data[0];
} __attribute__ ((packed)) wispy_fr_header;
/* Size of a container header */
#define wispy_fr_header_size()		(sizeof(wispy_fr_header))

#define WISPY_NET_SWEEPTYPE_CUR		0x01
#define WISPY_NET_SWEEPTYPE_AVG		0x02
#define WISPY_NET_SWEEPTYPE_PEAK	0x03

typedef struct _wispy_fr_sweep {
	uint16_t frame_len;
	uint32_t device_id;
	uint8_t sweep_type;
	uint32_t start_sec;
	uint32_t start_usec;
	uint8_t sample_data[0];
} __attribute__ ((packed)) wispy_fr_sweep;
/* Size of a sweep of N samples */
#define wispy_fr_sweep_size(x)		(sizeof(wispy_fr_sweep) + (x))

#define WISPY_NET_DEVTYPE_USB1		0x01
#define WISPY_NET_DEVTYPE_USB2		0x02
#define WISPY_NET_DEVTYPE_LASTDEV	0xFF

#define WISPY_NET_DEVFLAG_NONE		0x00
#define WISPY_NET_DEVFLAG_VARSWEEP	0x01
#define WISPY_NET_DEVFLAG_LOCKED	0x02

typedef struct _wispy_fr_device {
	uint16_t frame_len;
	uint8_t device_version;
	uint16_t device_flags;
	uint32_t device_id;
	uint8_t device_name_len;
	uint8_t device_name[256];

	uint32_t amp_offset_mdbm;
	uint32_t amp_res_mdbm;
	uint16_t rssi_max;

	uint32_t def_start_khz;
	uint32_t def_res_hz;
	uint16_t def_num_samples;

	uint32_t start_khz;
	uint32_t res_hz;
	uint16_t num_samples;
} __attribute__ ((packed)) wispy_fr_device;
/* Size of a device frame of N sample definitions */
#define wispy_fr_device_size()		(sizeof(wispy_fr_device))

#define WISPY_NET_TXTTYPE_INFO		0x00
#define WISPY_NET_TXTTYPE_ERROR		0x01
#define WISPY_NET_TXTTYPE_FATAL		0x02
typedef struct _wispy_fr_txtmessage {
	uint16_t frame_len;
	uint8_t message_type;
	uint16_t message_len;
	uint8_t message[0];
} __attribute__ ((packed)) wispy_fr_txtmessage;
/* Size of a text message of N characters */
#define wispy_fr_txtmessage_size(x)	(sizeof(wispy_fr_txtmessage) + (x))

#define WISPY_NET_COMMAND_NULL			0x00
#define WISPY_NET_COMMAND_ENABLEDEV		0x01
#define WISPY_NET_COMMAND_DISABLEDEV	0x02
#define WISPY_NET_COMMAND_SETSCAN		0x03
#define WISPY_NET_COMMAND_LOCK			0x04
#define WISPY_NET_COMMAND_UNLOCK		0x05
typedef struct _wispy_fr_command {
	uint16_t frame_len;
	uint8_t command_id;
	uint16_t command_len;
	uint8_t command_data[0];
} __attribute__ ((packed)) wispy_fr_command;
#define wispy_fr_command_size(x)	(sizeof(wispy_fr_command) + (x))

typedef struct _wispy_fr_command_enabledev {
	uint32_t device_id;
} __attribute__ ((packed)) wispy_fr_command_enabledev;
#define wispy_fr_command_enabledev_size(x)	(sizeof(wispy_fr_command_enabledev))

typedef struct _wispy_fr_broadcast {
	uint32_t sentinel;
	uint8_t version;
	uint16_t server_port;
} __attribute__ ((packed)) wispy_fr_broadcast;

#define spectool_net_state_setup			0
#define spectool_net_state_configured 		1

class SpectoolsClient : public ClientFramework {
public:
	SpectoolsClient() {
		fprintf(stderr, "FATAL OOPS:  spectoolsclient called without globalreg\n");
		exit(1);
	}

	SpectoolsClient(GlobalRegistry *in_globalreg);
	virtual ~SpectoolsClient();

	virtual int ParseData();

	virtual int Shutdown();

	struct spectool_dev {
		int dev_version;
		int dev_flags;
		unsigned int dev_id;

		string dev_name;

		int amp_offset_mdbm;
		int amp_res_mdbm;
		int rssi_max;

		int start_khz;
		int res_hz;
		unsigned int num_samples;
	};

	virtual int Reconnect();

	virtual int FetchPacketCompId() { return packet_comp_id; }

	virtual void ConnectCB(int status);

protected:
	TcpClient *tcpcli;

	char host[MAXHOSTNAMELEN];
	int port;

	int state;

	int recon_timer_id;

	int spec_proto_id;

	int packet_comp_id;

	int last_disconnect;

	vector<spectool_dev *> device_vec;
};

class kis_spectrum_data : public packet_component {
public:
	vector<int> rssi_vec;
	string dev_name;
	struct timeval start_tm;
	int start_khz;
	int res_hz;
	int amp_offset_mdbm;
	int amp_res_mdbm;
	int rssi_max;
	// dBm = (RSSI * (Amp_Res_mdBm / 1000)) + (Amp_Offset_mdBm / 1000)
	
	kis_spectrum_data() {
		self_destruct = 1;
		start_khz = 0;
		res_hz = 0;
	}

	~kis_spectrum_data() { }
};

#endif

