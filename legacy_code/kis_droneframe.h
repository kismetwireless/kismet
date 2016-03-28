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
#include "packetsourcetracker.h"

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
	virtual ~KisDroneframe_MessageClient() { }
    void ProcessMessage(string in_msg, int in_flags);
};

// Drone protocol
const uint32_t DroneSentinel = 0xDEADBEEF;

// Drone commands that determine the type of packet this is
#define DRONE_CMDNUM_NULL			0
#define DRONE_CMDNUM_HELO			1
#define DRONE_CMDNUM_STRING			2
#define DRONE_CMDNUM_CAPPACKET		3
#define DRONE_CMDNUM_CHANNELSET		4
#define DRONE_CMDNUM_SOURCE			5
#define DRONE_CMDNUM_REPORT			6

// Size-neutral container for a uuid
struct drone_trans_uuid {
	uint32_t time_low;
	uint16_t time_mid;
	uint16_t time_hi;
	uint16_t clock_seq;
	uint8_t node[6];
} __attribute__((__packed__));

#define DRONE_CONV_UUID(x, y)	\
	({ \
	 (y)->time_low = kis_hton32(*((x).time_low)); \
	 (y)->time_mid = kis_hton16(*((x).time_mid)); \
	 (y)->time_hi = kis_hton16(*((x).time_hi)); \
	 (y)->clock_seq = kis_hton16(*((x).clock_seq)); \
	 memcpy((y)->node, (x).node, 6); \
	 })

#define UUID_CONV_DRONE(x, y)	\
	({ \
	 (y).GenerateStoredUUID(kis_ntoh32((x)->time_low), \
							kis_ntoh16((x)->time_mid), \
							kis_ntoh16((x)->time_hi), \
							kis_ntoh16((x)->clock_seq), \
							(x)->node); \
	 })

// Size-neutral container for doubles
struct drone_trans_double {
	uint32_t mantissal;
	uint32_t mantissah;
	uint16_t exponent;
	uint16_t sign;
} __attribute__((__packed__));

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

// Packet header stuck on the beginning of everything
struct drone_packet {
	uint32_t sentinel;
	uint32_t drone_cmdnum;
	uint32_t data_len;
	uint8_t data[0];
} __attribute__((__packed__));

// Basic hello packet
struct drone_helo_packet {
	// Increment when we break the protocol in big ways
	uint32_t drone_version;
	// Version string of the kismet server hosting this
	uint8_t kismet_version[32];
	// Arbitrary name of the drone/server hosting this
	uint8_t host_name[32];
} __attribute__((__packed__));

// String packet for text
struct drone_string_packet {
	uint32_t msg_flags;
	uint32_t msg_len;
	char msg[0];
} __attribute__((__packed__));

// Channel set command packet (one channel sets chan, multiple sets vector)
// OR if it comes FROM the drone, it indicates the current set of channels used
// and the state of channel hopping.  How a set command is treated depends on
// the commands set.
#define DRONE_CHANNELSET_UUID			0
#define DRONE_CHANNELSET_CMD			1
#define DRONE_CHANNELSET_CURCH			2
#define DRONE_CHANNELSET_HOP			3
#define DRONE_CHANNELSET_NUMCH			4
#define DRONE_CHANNELSET_CHANNELS		5
#define DRONE_CHANNELSET_CHANNELSDWELL	6
#define DRONE_CHANNELSET_HOPRATE		7
#define DRONE_CHANNELSET_HOPDWELL		8

// Commands for the channelset command
#define DRONE_CHS_CMD_NONE			0
#define DRONE_CHS_CMD_SETHOP		1
#define DRONE_CHS_CMD_SETVEC		2
#define DRONE_CHS_CMD_SETCUR		3
#define DRONE_CHS_CMD_SETHOPDWELL	4
struct drone_channelset_packet {
	uint16_t channelset_hdr_len;
	uint32_t channelset_content_bitmap;

	drone_trans_uuid uuid;
	uint16_t command;
	uint16_t cur_channel;
	uint16_t channel_hop;
	uint16_t num_channels;

	/* Updated, breaks unreleased compat */
	struct chandata_t {
		union {
			struct {
				// Highest bit (1 << 15) == 0 if channel
				uint16_t channel;
				uint16_t dwell;
			} chan_t;

			struct {
				// Highest bit (1 << 15) == 1 if range
				uint16_t start;
				uint16_t end;
				uint16_t width;
				uint16_t iter;
			} range_t;
		} u;
	} chandata[IPC_SOURCE_MAX_CHANS];

	/*
	uint16_t channels[IPC_SOURCE_MAX_CHANS];
	uint16_t channels_dwell[IPC_SOURCE_MAX_CHANS];
	*/

	uint16_t channel_rate;
	uint16_t channel_dwell;
} __attribute__((__packed__));

// Source record
#define DRONE_SRC_UUID				0
#define DRONE_SRC_INVALID			1
#define DRONE_SRC_NAMESTR			2
#define DRONE_SRC_INTSTR			3
#define DRONE_SRC_TYPESTR			4
#define DRONE_SRC_CHANHOP			5
#define DRONE_SRC_CHANNELDWELL		6
#define DRONE_SRC_CHANNELRATE		7
struct drone_source_packet {
	uint16_t source_hdr_len;
	uint32_t source_content_bitmap;
	drone_trans_uuid uuid;
	// Kill this source, the rest of the data is empty
	uint16_t invalidate;
	// Null-terminated strings
	uint8_t name_str[16];
	uint8_t interface_str[16];
	uint8_t type_str[16];
	uint8_t channel_hop;
	uint16_t channel_dwell;
	uint16_t channel_rate;
} __attribute__((__packed__));

// Source report record
#define DRONE_REPORT_UUID			0
#define DRONE_REPORT_FLAGS			1
#define DRONE_REPORT_HOP_TM_SEC		2
#define DRONE_REPORT_HOP_TM_USEC	3
struct drone_report_packet {
	uint16_t report_hdr_len;
	uint32_t report_content_bitmap;
	drone_trans_uuid uuid;
	uint8_t flags;
	uint32_t hop_tm_sec;
	uint32_t hop_tm_usec;
} __attribute__((__packed__));
#define DRONE_REPORT_FLAG_NONE		0
#define DRONE_REPORT_FLAG_ERROR		128

// Bitmap fields for radio headers
#define DRONE_RADIO_ACCURACY		0
#define DRONE_RADIO_FREQ_MHZ		1
#define DRONE_RADIO_SIGNAL_DBM		2
#define DRONE_RADIO_NOISE_DBM		3
#define DRONE_RADIO_CARRIER			4
#define DRONE_RADIO_ENCODING		5
#define DRONE_RADIO_DATARATE		6
#define DRONE_RADIO_SIGNAL_RSSI		7
#define DRONE_RADIO_NOISE_RSSI		8

// Radiotap-style header of radio data
struct drone_capture_sub_radio {
	uint16_t radio_hdr_len;
	uint32_t radio_content_bitmap;

	uint16_t radio_accuracy;
	uint16_t radio_freq_mhz;
	int16_t radio_signal_dbm;
	int16_t radio_noise_dbm;
	uint32_t radio_carrier;
	uint32_t radio_encoding;
	uint32_t radio_datarate;
	int16_t radio_signal_rssi;
	int16_t radio_noise_rssi;
} __attribute__((__packed__));

// Bitmap fields for gps headers
#define DRONE_GPS_FIX				0
#define DRONE_GPS_LAT				1
#define DRONE_GPS_LON				2
#define DRONE_GPS_ALT				3
#define DRONE_GPS_SPD				4
#define DRONE_GPS_HEADING			5

// Radiotap-style header of GPS data
struct drone_capture_sub_gps {
	uint16_t gps_hdr_len;
	uint32_t gps_content_bitmap;

	uint16_t gps_fix;
	drone_trans_double gps_lat;
	drone_trans_double gps_lon;
	drone_trans_double gps_alt;
	drone_trans_double gps_spd;
	drone_trans_double gps_heading;
} __attribute__((__packed__));

// Bitmap fields for eitht11 subs
#define DRONE_DATA_UUID			0
#define DRONE_DATA_PACKLEN		1
#define DRONE_DATA_TVSEC		2
#define DRONE_DATA_TVUSEC		3
#define DRONE_DATA_DLT			4

// Capture data 
struct drone_capture_sub_data {
	uint16_t data_hdr_len;
	uint32_t data_content_bitmap;
	drone_trans_uuid uuid;
	uint16_t packet_len;
	uint64_t tv_sec;
	uint64_t tv_usec;
	uint32_t dlt;
	uint8_t packdata[0]; // Alias to the trailing packet data
} __attribute__((__packed__));

#define DRONE_CONTENT_RADIO			0
#define DRONE_CONTENT_GPS			1
#define DRONE_CONTENT_FCS			2
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
struct drone_capture_packet {
	uint32_t cap_content_bitmap;
	uint32_t cap_packet_offset;
	// This will be filled with a subset of (radio|gps|packet) based
	// on the content bitmap
	uint8_t content[0];
} __attribute__((__packed__));

// Callbacks
#define DRONE_CMD_PARMS GlobalRegistry *globalreg, const drone_packet *data, \
	const void *auxptr
typedef int (*DroneCmdCallback)(DRONE_CMD_PARMS);

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

	// AddSource handler...
	virtual void sourceact_handler(pst_packetsource *src, int action, int flags);

	// Send a frame
	virtual int SendPacket(int in_cl, drone_packet *in_pack);
	virtual int SendAllPacket(drone_packet *in_pack);

	// Send a source record
	virtual int SendSource(int in_cl, pst_packetsource *in_int, int invalid);
	virtual int SendAllSource(pst_packetsource *in_int, int invalid);

	// Send a source report
	virtual int SendSourceReport(int in_cl, pst_packetsource *in_int);
	virtual int SendAllSourceReport(pst_packetsource *in_int);

	// Send a channel record
	virtual int SendChannels(int in_cl, pst_packetsource *in_int);
	virtual int SendAllChannels(pst_packetsource *in_int);

	virtual int channel_handler(const drone_packet *in_pack);

	struct drone_cmd_rec {
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
};

#endif

