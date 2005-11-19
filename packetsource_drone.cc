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

#include <string>
#include <sstream>

#include "endian_magic.h"
#include "packet.h"
#include "packetsource.h"
#include "packetchain.h"
#include "gpscore.h"
#include "kis_droneframe.h"
#include "clinetframework.h"
#include "tcpclient.h"
#include "packetsourcetracker.h"
#include "packetsource_drone.h"

int droneclienttimer_hook(TIMEEVENT_PARMS) {
	return ((DroneClientFrame *) parm)->time_handler();
}

DroneClientFrame::DroneClientFrame() {
	fprintf(stderr, "FATAL OOPS:  DroneClientFrame called without globalreg\n");
	exit(1);
}

DroneClientFrame::DroneClientFrame(GlobalRegistry *in_globalreg) :
	ClientFramework(in_globalreg) {
	// Not much to do here, the real magic happens in OpenConnection(..)
	globalreg = in_globalreg;

	if (globalreg->packetchain == NULL) {
		fprintf(stderr, "FATAL OOPS: DroneClientFrame called before packetchain\n");
		exit(1);
	}

	if (globalreg->timetracker == NULL) {
		fprintf(stderr, "FATAL OOPS: DroneClientFrame called before timetracker\n");
		exit(1);
	}

	netclient = NULL;
	tcpcli = NULL;
	packetsource = NULL;

	reconnect = 0;

	cli_type = -1;

	timerid = 
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1,
											  &droneclienttimer_hook, (void *) this);

	last_disconnect = 0;

	globalreg->RegisterPollableSubsys(this);
}

DroneClientFrame::~DroneClientFrame() {
	if (netclient != NULL) {
		netclient->KillConnection();
	}

	if (timerid >= 0 && globalreg != NULL) {
		globalreg->timetracker->RemoveTimer(timerid);
	}
}

void DroneClientFrame::SetPacketsource(void *in_src) {
	packetsource = in_src;
}

int DroneClientFrame::OpenConnection(string in_conparm, int in_recon) {
	char cli_proto[11];
	ostringstream osstr;

	if (sscanf(in_conparm.c_str(), "%10[^:]://%128[^:]:%d",
			   cli_proto, cli_host, &cli_port) != 3) {
		_MSG("Drone client unable to parse remote server info from '" + 
			 in_conparm + "', expected proto://host:port", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	if (strncasecmp(cli_proto, "tcp", 10) == 0) {
		tcpcli = new TcpClient(globalreg);
		netclient = tcpcli;

		RegisterNetworkClient(tcpcli);
		tcpcli->RegisterClientFramework(this);

		cli_type = 0;
	} else {
		_MSG("Invalid protocol '" + string(cli_proto) + "' for drone connection",
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	reconnect = in_recon;

	if (netclient->Connect(cli_host, cli_port) < 0) {
		if (reconnect == 0) {
			osstr << "Kismet drone initial connection to " << cli_host << ":" <<
				cli_port << " failed (" << strerror(errno) << ") and reconnection "
				"not enabled";
			_MSG(osstr.str(), MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
		} else {
			osstr << "Could not create initial connection to the Kismet drone "
				"server at " << cli_host << ":" << cli_port << " (" <<
				strerror(errno) << "), will attempt to reconnect in 5 seconds";
			_MSG(osstr.str(), MSGFLAG_ERROR);
		}

		last_disconnect = time(0);
		return 0;
	}

	return 1;
}

int DroneClientFrame::time_handler() {
	if (last_disconnect != 0) {
		if (time(0) - last_disconnect > 5) {
			Reconnect();
		}
	}

	return 1;
}

int DroneClientFrame::Reconnect() {
	ostringstream osstr;

	if (tcpcli == NULL)
		return 0;

	tcpcli->KillConnection();

	if (cli_type == 0) {
		if (netclient->Connect(cli_host, cli_port) < 0) {
			osstr << "Could not reconnect to Kismet drone server at " <<
				cli_host << ":" << cli_port << " (" << strerror(errno) << "), "
				"will attempt to recconect in 5 seconds";
			_MSG(osstr.str(), MSGFLAG_ERROR);
			last_disconnect = time(0);
			return 0;
		}

		osstr << "Reconnected to Kismet drone server at " << cli_host << ":" <<
			cli_port;
		_MSG(osstr.str(), MSGFLAG_INFO);

		last_disconnect = 0;

		return 1;
	}

	return 0;
}

int DroneClientFrame::KillConnection() {
	if (tcpcli != NULL)
		tcpcli->KillConnection();

	return 1;
}

int DroneClientFrame::Shutdown() {
	if (tcpcli != NULL) {
		tcpcli->FlushRings();
		tcpcli->KillConnection();
	}

	return 1;
}

int DroneClientFrame::Poll(fd_set &in_rset, fd_set& in_wset) {
	int ret = netclient->Poll(in_rset, in_wset);

	if (ret < 0) {
		if (reconnect) {
			_MSG("Kismet drone client failed to poll data from the "
				 "TCP connection.  Will attempt to reconnect in 5 seconds",
				 MSGFLAG_ERROR);
			last_disconnect = time(0);
			KillConnection();
			return 0;
		} else {
			_MSG("Kismet drone client failed to poll data from the "
				 "TCP connection.  This error is fatal because "
				 "drone reconnecting is not enabled", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return -1;
		}
	}

	return ret;
}

int DroneClientFrame::ParseData() {
	int len, rlen;
	uint8_t *buf;
	ostringstream osstr;

	if (netclient == NULL)
		return 0;

	if (netclient->Valid() == 0)
		return 0;

	len = netclient->FetchReadLen();
	buf = new uint8_t[len + 1];

	if (netclient->ReadData(buf, len, &rlen) < 0) {
		if (reconnect) {
			_MSG("Kismet drone client failed to read data from the "
				 "TCP connection.  Will attempt to reconnect in 5 seconds",
				 MSGFLAG_ERROR);
			last_disconnect = time(0);
			KillConnection();
			delete[] buf;
			return 0;
		} else {
			_MSG("Kismet drone client failed to read data from the "
				 "TCP connection.  This error is fatal because "
				 "drone reconnecting is not enabled", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			delete[] buf;
			return -1;
		}
	}

	if (rlen < (int) sizeof(drone_packet)) {
		delete[] buf;
		return 0;
	}

	drone_packet *dpkt = (drone_packet *) buf;

	if (kis_ntoh32(dpkt->sentinel) != DroneSentinel) {
		if (reconnect) {
			_MSG("Kismet drone client failed to find the sentinel "
				 "value in a packet header, dropping connection.  Will "
				 "attempt to reconnect in 5 seconds", MSGFLAG_ERROR);
			last_disconnect = time(0);
			KillConnection();
			delete[] buf;
			return 0;
		} else {
			_MSG("Kismet drone client failed to find the sentinel "
				 "value in a packet header.  This error is fatal because "
				 "drone reconnecting is not enabled", MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			delete[] buf;
			return -1;
		}
	}

	unsigned int dplen = kis_ntoh32(dpkt->data_len);

	// Check for incomplete packets
	if (rlen < (int) (dplen + sizeof(drone_packet))) {
		delete[] buf;
		return 0;
	}

	unsigned int dcid = kis_ntoh32(dpkt->drone_cmdnum);

	// Handle the packet types
	if (dcid == DRONE_CMDNUM_NULL) {
		// Nothing special to do here
	} else if (dcid == DRONE_CMDNUM_HELO) {
		drone_helo_packet *hpkt = (drone_helo_packet *) dpkt->data;
		if (kis_ntoh32(hpkt->drone_version) != KIS_DRONE_VERSION) {
			osstr << "Kismet drone client got remote protocol "
				"version " << kis_ntoh32(hpkt->drone_version) << " but uses "
				"version " << KIS_DRONE_VERSION << ".  All features or "
				"components may not be available";
			_MSG(osstr.str(), MSGFLAG_INFO);
		} else {
			osstr << "Kismet drone client connected to remote server "
				"using protocol version " << kis_ntoh32(hpkt->drone_version);
			_MSG(osstr.str(), MSGFLAG_INFO);
		}
	} else if (dcid == DRONE_CMDNUM_STRING) {
		drone_string_packet *spkt = (drone_string_packet *) dpkt->data;
		string msg = string("DRONE - ");
		uint32_t len = kis_ntoh32(spkt->msg_len);
		// Don't trust us to have a final terminator, copy manually
		for (unsigned int x = 0; x < len; x++) {
			msg += spkt->msg[x];
		}
		// Inject it into the messagebus w/ the normal 
		_MSG(msg, kis_ntoh32(spkt->msg_flags));
	} else if (dcid == DRONE_CMDNUM_CAPPACKET) {
		drone_capture_packet *dcpkt = (drone_capture_packet *) dpkt->data;
		uint32_t poffst = 0;

		kis_packet *newpack = globalreg->packetchain->GeneratePacket();
		
		if ((dcpkt->cap_content_bitmap & DRONEBIT(DRONE_CONTENT_RADIO))) {
			drone_capture_sub_radio *dsr = 
				(drone_capture_sub_radio *) &(dcpkt->content[poffst]);

			uint16_t sublen = kis_ntoh16(dsr->radio_hdr_len);

			// Make sure our subframe is contained within the larger frame
			if (poffst + sublen > dplen) {
				_MSG("Kismet drone client got a subframe with a length "
					 "greater than the total packet length.  This "
					 "corruption may be accidental or malicious.",
					 MSGFLAG_ERROR);
				globalreg->packetchain->DestroyPacket(newpack);
				delete[] buf;
				return 0;
			}

			kis_layer1_packinfo *radio = new kis_layer1_packinfo;

			uint16_t rofft = 0;

			// Extract the components as long as theres space... in theory it
			// should be an error condition if it's not filled in, but
			// if we just handle it properly...
			if ((dsr->radio_content_bitmap & DRONEBIT(DRONE_RADIO_ACCURACY)) &&
				(rofft + 2 <= sublen)) {
				radio->accuracy = kis_ntoh16(dsr->radio_accuracy);
				rofft += 2;
			}
			if ((dsr->radio_content_bitmap & DRONEBIT(DRONE_RADIO_CHANNEL)) &&
				(rofft + 2 <= sublen)) {
				radio->channel = kis_ntoh16(dsr->radio_channel);
				rofft += 2;
			}
			if ((dsr->radio_content_bitmap & DRONEBIT(DRONE_RADIO_SIGNAL)) &&
				(rofft + 2 <= sublen)) {
				radio->signal = (int16_t) kis_ntoh16(dsr->radio_signal);
				rofft += 2;
			}
			if ((dsr->radio_content_bitmap & DRONEBIT(DRONE_RADIO_NOISE)) &&
				(rofft + 2 <= sublen)) {
				radio->noise = (int16_t) kis_ntoh16(dsr->radio_noise);
				rofft += 2;
			}
			if ((dsr->radio_content_bitmap & DRONEBIT(DRONE_RADIO_CARRIER)) &&
				(rofft + 4 <= sublen)) {
				radio->carrier = (phy_carrier_type) kis_ntoh32(dsr->radio_carrier);
				rofft += 4;
			}
			if ((dsr->radio_content_bitmap & DRONEBIT(DRONE_RADIO_ENCODING)) &&
				(rofft + 4 <= sublen)) {
				radio->encoding = (phy_encoding_type) kis_ntoh32(dsr->radio_encoding);
				rofft += 4;
			}
			if ((dsr->radio_content_bitmap & DRONEBIT(DRONE_RADIO_DATARATE)) &&
				(rofft + 4 <= sublen)) {
				radio->datarate = kis_ntoh32(dsr->radio_datarate);
				rofft += 4;
			}

			newpack->insert(_PCM(PACK_COMP_RADIODATA), radio);

			// Jump to the end of this packet
			poffst += sublen;
		}

		if ((dcpkt->cap_content_bitmap & DRONEBIT(DRONE_CONTENT_GPS))) {
			drone_capture_sub_gps *dsg = 
				(drone_capture_sub_gps *) &(dcpkt->content[poffst]);

			uint16_t sublen = kis_ntoh16(dsg->gps_hdr_len);

			// Make sure our subframe is contained within the larger frame
			if (poffst + sublen > dplen) {
				_MSG("Kismet drone client got a subframe with a length "
					 "greater than the total packet length.  This "
					 "corruption may be accidental or malicious.",
					 MSGFLAG_ERROR);
				delete[] buf;
				globalreg->packetchain->DestroyPacket(newpack);
				return 0;
			}

			kis_gps_packinfo *gpsinfo = new kis_gps_packinfo;

			uint16_t rofft = 0;

			if ((dsg->gps_content_bitmap & DRONEBIT(DRONE_GPS_FIX)) &&
				(rofft + 2 <= sublen)) {
				gpsinfo->gps_fix = kis_ntoh16(dsg->gps_fix);
				rofft += 2;
			}
			if ((dsg->gps_content_bitmap & DRONEBIT(DRONE_GPS_LAT)) &&
				(rofft + sizeof(drone_trans_double) <= sublen)) {
				DOUBLE_CONV_DRONE(gpsinfo->lat, &(dsg->gps_lat));
				rofft += sizeof(drone_trans_double);
			}
			if ((dsg->gps_content_bitmap & DRONEBIT(DRONE_GPS_LON)) &&
				(rofft + sizeof(drone_trans_double) <= sublen)) {
				DOUBLE_CONV_DRONE(gpsinfo->lon, &(dsg->gps_lon));
				rofft += sizeof(drone_trans_double);
			}
			if ((dsg->gps_content_bitmap & DRONEBIT(DRONE_GPS_ALT)) &&
				(rofft + sizeof(drone_trans_double) <= sublen)) {
				DOUBLE_CONV_DRONE(gpsinfo->alt, &(dsg->gps_alt));
				rofft += sizeof(drone_trans_double);
			}
			if ((dsg->gps_content_bitmap & DRONEBIT(DRONE_GPS_SPD)) &&
				(rofft + sizeof(drone_trans_double) <= sublen)) {
				DOUBLE_CONV_DRONE(gpsinfo->spd, &(dsg->gps_spd));
				rofft += sizeof(drone_trans_double);
			}
			if ((dsg->gps_content_bitmap & DRONEBIT(DRONE_GPS_HEADING)) &&
				(rofft + sizeof(drone_trans_double) <= sublen)) {
				DOUBLE_CONV_DRONE(gpsinfo->heading, &(dsg->gps_heading));
				rofft += sizeof(drone_trans_double);
			}

			newpack->insert(_PCM(PACK_COMP_GPS), gpsinfo);

			// Jump to the end of this packet
			poffst += sublen;
		}

		if (dcpkt->cap_content_bitmap & DRONEBIT(DRONE_CONTENT_IEEEPACKET)) {
			// Jump to thend of the capframe
			poffst = kis_ntoh32(dcpkt->cap_packet_offset);

			drone_capture_sub_80211 *ds11 = 
				(drone_capture_sub_80211 *) &(dcpkt->content[poffst]);

			uint16_t sublen = kis_ntoh16(ds11->eight11_hdr_len);

			// Make sure our subframe is contained within the larger frame
			if (poffst + sublen > dplen) {
				_MSG("Kismet drone client got a subframe with a length "
					 "greater than the total packet length.  This "
					 "corruption may be accidental or malicious.",
					 MSGFLAG_ERROR);
				delete[] buf;
				globalreg->packetchain->DestroyPacket(newpack);
				return 0;
			}

			kis_datachunk *chunk = new kis_datachunk;

			uint16_t rofft = 0;

			if ((ds11->eight11_content_bitmap & DRONEBIT(DRONE_EIGHT11_PACKLEN)) &&
				(rofft + 2 <= sublen)) {
				chunk->length = kismin(kis_ntoh16(ds11->packet_len),
									   (uint32_t) MAX_PACKET_LEN);
				rofft += 2;
			}
			if ((ds11->eight11_content_bitmap & DRONEBIT(DRONE_EIGHT11_TVSEC)) &&
				(rofft + 8 <= sublen)) {
				newpack->ts.tv_sec = kis_ntoh64(ds11->tv_sec);
				rofft += 8;
			}
			if ((ds11->eight11_content_bitmap & DRONEBIT(DRONE_EIGHT11_TVUSEC)) &&
				(rofft + 8 <= sublen)) {
				newpack->ts.tv_usec = kis_ntoh64(ds11->tv_usec);
				rofft += 8;
			}

			// Fill in the rest of the chunk if it makes sense to
			if (chunk->length == 0) {
				delete chunk;
			} else {
				if (poffst + sublen + chunk->length > dplen) {
					_MSG("Kismet drone client got a 80211 frame with a length "
						 "greater than the total packet length.  This "
						 "corruption may be accidental or malicious.",
						 MSGFLAG_ERROR);
					delete[] buf;
					delete chunk;
					globalreg->packetchain->DestroyPacket(newpack);
					return 0;
				}

				chunk->data = new uint8_t[chunk->length];
				uint8_t *rawdat = (uint8_t *) ds11;
				memcpy(chunk->data, &(rawdat[sublen]), chunk->length);

				newpack->insert(_PCM(PACK_COMP_LINKFRAME), chunk);
			}
		}

		if (packetsource != NULL) {
			kis_ref_capsource *csrc_ref = new kis_ref_capsource;
			csrc_ref->ref_source = (KisPacketSource *) packetsource;
			newpack->insert(_PCM(PACK_COMP_KISCAPSRC), csrc_ref);
		}

		globalreg->packetchain->ProcessPacket(newpack);
	}
	
	netclient->MarkRead(dplen + sizeof(drone_packet));

	delete[] buf;

	return 1;
}

PacketSource_Drone::~PacketSource_Drone() {
	if (droneframe != NULL) {
		droneframe->Shutdown();
		delete droneframe;
	}
}

int PacketSource_Drone::OpenSource() {
	if (droneframe == NULL)
		droneframe = new DroneClientFrame(globalreg);

	// Look for the reconnect parm
	for (unsigned int x = 0; x < optargs.size(); x++) {
		if (optargs[x] == "reconnect") {
			reconnect = 1;
		} else if (optargs[x] == "noreconnect") {
			reconnect = 0;
		}
	}

	droneframe->SetPacketsource((void *) this);

	if (droneframe->OpenConnection(interface, reconnect) < 0 ||
		globalreg->fatal_condition) {
		_MSG("Packetsource drone (" + name + ") failed to create drone "
			 "framework and open connection", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	return 1;
}

int PacketSource_Drone::CloseSource() {
	if (droneframe == NULL)
		return 0;

	droneframe->Shutdown();
	delete droneframe;
	droneframe = NULL;

	return 1;
}

void PacketSource_Drone::FetchRadioData(kis_packet *in_packet) {
	// Nothing to do here
	return;
}

int PacketSource_Drone::FetchDescriptor() {
	// Nothing to do here, the pollable droneclientframe handles it
	return -1;
}

int PacketSource_Drone::Poll() {
	// Nothing to do here, we should never even be called.   Pollable
	// droneclientframe handles it
	return 0;
}

int PacketSource_Drone::FetchChannel() {
	// Nope
	return 0;
}

KisPacketSource *packetsource_drone_registrant(REGISTRANT_PARMS) {
	PacketSource_Drone *ret =
		new PacketSource_Drone(globalreg, in_meta, in_name, in_device);
	return ret;
}

int unmonitor_drone(MONITOR_PARMS) {
	return 0;
}

