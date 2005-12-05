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

#ifndef __KISDRONEFRAME_H__
#define __KISDRONEFRAME_H__

#include "config.h"

#include <string>

#include "util.h"
#include "globalregistry.h"
#include "messagebus.h"
#include "netframework.h"
#include "packetchain.h"

// Network stream protocol used for Drones.
// Designed to be future-proof so that drone and server versions will be able
// to co-mingle, instead of breaking all the users every time we find a field
// we have to add.
//
// Future-proofing is accomplished via nested bitfields for each component and
// subcomponent.
//
// uint16 is preferred over uint8 to prevent gaps in the struct packs

// Forward prototype
class KisDroneFramework;

#define KIS_DRONE_VERSION		1

#define DRONEBIT(n)     (1 << n)

// Messagebus subscriber to pass data to the client
class KisDroneframe_MessageClient : public MessageClient {
public:
    KisDroneframe_MessageClient(GlobalRegistry *in_globalreg, void *in_aux) :
		MessageClient(in_globalreg, in_aux) { };
    void ProcessMessage(string in_msg, int in_flags);
};

// Timer events
int kisdrone_time_hook(TIMEEVENT_PARMS);

// Chain hook
int kisdrone_chain_hook(CHAINCALL_PARMS);

// Drone protocol
const uint32_t DroneSentinel = 0xDEADBEEF;

// Drone commands that determine the type of packet this is
#define DRONE_CMDNUM_NULL			0
#define DRONE_CMDNUM_HELO			1
#define DRONE_CMDNUM_STRING			2
#define DRONE_CMDNUM_CAPPACKET		3
#define DRONE_CMDNUM_CHANNELSET		4

// Packet header stuck on the beginning of everything
typedef struct drone_packet {
	uint32_t sentinel __attribute__ ((packed));
	uint32_t drone_cmdnum __attribute__ ((packed));
	uint32_t data_len __attribute__ ((packed));
	uint8_t data[0];
} __attribute__ ((packed));

// Basic hello packet
typedef struct drone_helo_packet {
	// Increment when we break the protocol in big ways
	uint32_t drone_version __attribute__ ((packed));
	// Version string of the kismet server hosting this
	uint8_t kismet_version[32] __attribute__ ((packed));
	// Arbitrary name of the drone/server hosting this
	uint8_t host_name[32] __attribute__ ((packed));
} __attribute__ ((packed));

// String packet for text
typedef struct drone_string_packet {
	uint32_t msg_flags __attribute__ ((packed));
	uint32_t msg_len __attribute__ ((packed));
	char msg[0];
} __attribute__ ((packed));

// Channel set command packet
typedef struct drone_channelset_packet {
	uint16_t channel_hop __attribute__ ((packed));
	uint16_t num_channels __attribute__ ((packed));
	// size = 2 * num_channels
	uint16_t channels[0];
} __attribute__ ((packed));

// Size-neutral container for doubles
typedef struct drone_trans_double {
	uint32_t mantissal __attribute__ ((packed));
	uint32_t mantissah __attribute__ ((packed));
	uint16_t exponent __attribute__ ((packed));
	uint16_t sign __attribute__ ((packed));
} __attribute__ ((packed));

#define DRONE_CONV_DOUBLE(x, y)		\
	({ \
	 ieee_double_t *locfl = (ieee_double_t *) &(x); \
	 (y)->mantissal = kis_hton32(locfl->mantissal); \
	 (y)->mantissah = kis_hton32(locfl->mantissah); \
	 (y)->exponent = kis_hton16(locfl->exponent); \
	 (y)->sign = kis_hton16(locfl->sign); \
	 })

#define DOUBLE_CONV_DRONE(x, y)		\
	({ \
	 ieee_double_t *locfl = (ieee_double_t *) &(x); \
	 (locfl)->mantissal = kis_ntoh32((y)->mantissal); \
	 (locfl)->mantissah = kis_ntoh32((y)->mantissah); \
	 (locfl)->exponent = kis_ntoh16((y)->exponent); \
	 (locfl)->sign = kis_ntoh16((y)->sign); \
	})

// Bitmap fields for radio headers
#define DRONE_RADIO_ACCURACY		0
#define DRONE_RADIO_CHANNEL			1
#define DRONE_RADIO_SIGNAL			2
#define DRONE_RADIO_NOISE			3
#define DRONE_RADIO_CARRIER			4
#define DRONE_RADIO_ENCODING		5
#define DRONE_RADIO_DATARATE		6

// Radiotap-style header of radio data
typedef struct drone_capture_sub_radio {
	uint16_t radio_hdr_len __attribute__ ((packed));
	uint32_t radio_content_bitmap __attribute__ ((packed));

	uint16_t radio_accuracy __attribute__ ((packed));
	uint16_t radio_channel __attribute__ ((packed));
	int16_t radio_signal __attribute__ ((packed));
	int16_t radio_noise __attribute__ ((packed));
	uint32_t radio_carrier __attribute__ ((packed));
	uint32_t radio_encoding __attribute__ ((packed));
	uint32_t radio_datarate __attribute__ ((packed));
} __attribute__ ((packed));

// Bitmap fields for gps headers
#define DRONE_GPS_FIX				0
#define DRONE_GPS_LAT				1
#define DRONE_GPS_LON				2
#define DRONE_GPS_ALT				3
#define DRONE_GPS_SPD				4
#define DRONE_GPS_HEADING			5

// Radiotap-style header of GPS data
typedef struct drone_capture_sub_gps {
	uint16_t gps_hdr_len __attribute__ ((packed));
	uint32_t gps_content_bitmap __attribute__ ((packed));

	uint16_t gps_fix __attribute__ ((packed));
	drone_trans_double gps_lat __attribute__ ((packed));
	drone_trans_double gps_lon __attribute__ ((packed));
	drone_trans_double gps_alt __attribute__ ((packed));
	drone_trans_double gps_spd __attribute__ ((packed));
	drone_trans_double gps_heading __attribute__ ((packed));
} __attribute__ ((packed));

// Bitmap fields for eitht11 subs
#define DRONE_EIGHT11_PACKLEN		0
#define DRONE_EIGHT11_TVSEC			1
#define DRONE_EIGHT11_TVUSEC		2

// Capture data in ieee80211 format
typedef struct drone_capture_sub_80211 {
	uint16_t eight11_hdr_len __attribute__ ((packed));
	uint32_t eight11_content_bitmap __attribute__ ((packed));
	uint16_t packet_len __attribute__ ((packed));
	uint64_t tv_sec __attribute__ ((packed));
	uint64_t tv_usec __attribute__ ((packed));
	uint8_t packdata[0]; // Alias to the trailing packet data
} __attribute__ ((packed));

#define DRONE_CONTENT_RADIO			0
#define DRONE_CONTENT_GPS			1
#define DRONE_CONTENT_IEEEPACKET	31
// Capture packet made of multiple other sub components
// content[0] format:
//   Bitmap
//   Packet offset
//   --- Content ---
//   Radio header
//   GPS header
//   ---
//   Eight11 header
//   Raw packet data
typedef struct drone_capture_packet {
	uint32_t cap_content_bitmap __attribute__ ((packed));
	uint32_t cap_packet_offset __attribute__ ((packed));
	// This will be filled with a subset of (radio|gps|packet) based
	// on the content bitmap
	uint8_t content[0];
} __attribute__ ((packed));

// Callbacks
#define DRONE_CMD_PARMS GlobalRegistry *globalreg, const drone_packet *data, \
	const void *auxptr
typedef int (*DroneCmdCallback)(DRONE_CMD_PARMS);

int dronecmd_channelset_hook(DRONE_CMD_PARMS);

// Drone framework for sending data
class KisDroneFramework : public ServerFramework {
public:
    KisDroneFramework();
    KisDroneFramework(GlobalRegistry *in_globalreg);
    virtual ~KisDroneFramework();

	// Activate the setup
	int Activate();
 
    virtual int Accept(int in_fd);
    virtual int ParseData(int in_fd);
    virtual int KillConnection(int in_fd);

	// Handle a buffer drain on a client
	virtual int BufferDrained(int in_fd);

	// Usage
	static void Usage(char *name);

	// Add a command
	virtual int RegisterDroneCmd(uint32_t in_cmdid, DroneCmdCallback in_callback, 
								 void *in_aux);
	virtual int RemoveDroneCmd(uint32_t in_cmdid);

	// Send text down the connection
	virtual int SendText(int in_cl, string in_text, int flags);
	virtual int SendAllText(string in_text, int flags);

	// Chain handler
	virtual int chain_handler(kis_packet *in_pack);

	// Timer handler
	virtual int time_handler();

	// Send a frame
	virtual int SendPacket(int in_cl, drone_packet *in_pack);
	virtual int SendAllPacket(drone_packet *in_pack);

	virtual int channel_handler(const drone_packet *in_pack);

	typedef struct drone_cmd_rec {
		void *auxptr;
		DroneCmdCallback callback;
	};

protected:
    // Messagebus client
    KisDroneframe_MessageClient *kisdrone_msgcli;

	// Server type (0 = tcp...)
	int server_type;

	int eventid;

	map<unsigned int, drone_cmd_rec *> drone_cmd_map;

	friend int drone_die_callback(DRONE_CMD_PARMS);

};

#endif

