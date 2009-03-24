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

#ifndef __KIS_PKTPROTO_H__
#define __KIS_PKTPROTO_H__

#include "config.h"

#include "util.h"
#include "netframework.h"
#include "ipc_remote.h"

// Packet control IPC protocol
// Elements requested from the parent should include the ID they'll
// be referred to in the return frames

// Parent->Child - Add a packet source 
// SOURCEADD
// sourceline - standard config file source line
// type - our dervied type from the server, easier than trying to figure out
//  autotype on the IPC
// channel source data - everything we parsed from the server and derived for
//  channel sharing
// Channel source data may be reset once we have parsed more about this source,
//  by sending a channelset
struct ipc_source_add {
	uint16_t source_id;

	char type[64];
	char sourceline[1024];

	uint16_t channel_id;

	uint32_t channel;

	int32_t channel_hop;
	int32_t channel_dwell;
	int32_t channel_rate;

	int32_t channel_position;
};

// Parent->Child - Push a channel list, we assume we'll never
// need to set more than 256 channels in this rev, expandable
// if we need to in the future.
// An existing channel set may be re-used by sending this packet
// a second time with the same chanset id
// SOURCEADDCHAN
// chanset_hop_offset allows hopping multiple channels at a time to force
// mixing on iterative lists (cur chan + hop offset = next chan)
// dwell list should be populated with dwelling points equivalent to the
// channel set
#define IPC_SOURCE_MAX_CHANS		256
struct ipc_source_add_chanlist {
	uint16_t chanset_id;
	uint16_t num_channels;
	struct chandata_t {
		union {
			struct {
				// Highest bit (1<<15) == 0 if channel
				uint16_t channel;
				uint16_t dwell;
			} chan_t;

			struct {
				// Highest bit (1<<15) == 1 if range
				uint16_t start;
				uint16_t end;
				uint16_t width;
				uint16_t iter;
			} range_t;
		} u;
	} chandata[IPC_SOURCE_MAX_CHANS];

	/*
	uint32_t chan_list[IPC_SOURCE_MAX_CHANS];
	uint8_t chan_dwell_list[IPC_SOURCE_MAX_CHANS];
	*/
};

// Parent->Child - Set a channel set or specific channel
// SOURCESETCHAN
// chanset_id = 0 && hop = 0 implies lock to channel
//
// Used to lock/unlock hopping or change channel sets runtime, also to modify
// hop/dwell status
struct ipc_source_chanset {
	uint16_t source_id;
	uint16_t chanset_id;
	uint32_t channel;
	int32_t channel_hop;
	int32_t channel_dwell;
	int32_t channel_rate;
	int32_t channel_split;
	uint16_t channel_pos;
};

// Parent->Child - Start/Stop a source
// SOURCERUN
struct ipc_source_run {
	uint16_t source_id;
	uint8_t start;
};

// Child->Parent - Report a frame
// SOURCEFRAME
struct ipc_source_packet {
	uint16_t source_id;
	uint32_t tv_sec;
	uint32_t tv_usec;
	uint32_t dlt;
	uint32_t pkt_len;
	uint8_t data[0];
};

// Child-Parent - Report source state.  Sent once per second on
// non-hopping sources, once per hop cycle complete on hopping
// sources, or in the event of an error.  msgbus link will carry 
// the data regarding the error until we need more detailed
// per-source failure state info
// SOURCESTATE
struct ipc_source_report {
	uint16_t source_id;
	uint16_t chanset_id;
	uint32_t capabilities;
	uint8_t flags;
	uint32_t hop_tm_sec;
	uint32_t hop_tm_usec;
	uint32_t last_channel;
};

#define IPC_SRCREP_FLAG_NONE		0
#define IPC_SRCREP_FLAG_RUNNING		1
#define IPC_SRCREP_FLAG_ERROR		128

// Child-Parent - Report channel timings
struct ipc_source_chanreport {
	uint16_t num_channels;
	uint32_t channels[IPC_SOURCE_MAX_CHANS];
	uint16_t channels_time[IPC_SOURCE_MAX_CHANS];
};

// Parent-Child - Remove packet source
struct ipc_source_remove {
	uint16_t source_id;
};


#endif

