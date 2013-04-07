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
#include "phy_80211.h"

int droneclienttimer_hook(TIMEEVENT_PARMS) {
	return ((DroneClientFrame *) auxptr)->time_handler();
}

void droneclient_pst_sourceact_hook(SOURCEACT_PARMS) {
	((DroneClientFrame *) auxptr)->SourceActionHandler(src, action, flags);
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

	if (globalreg->sourcetracker == NULL) {
		fprintf(stderr, "FATAL OOPS:  DroneClientFrame called before sourcetracker\n");
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

	// Catch channel set stuff here
	globalreg->sourcetracker->RegisterSourceActCallback(&droneclient_pst_sourceact_hook,
														(void *) this);

	last_disconnect = 0;
	last_frame = 0;

	// globalreg->RegisterPollableSubsys(this);
}

DroneClientFrame::~DroneClientFrame() {
	if (netclient != NULL) {
		netclient->KillConnection();
	}

	if (timerid >= 0 && globalreg != NULL) {
		globalreg->timetracker->RemoveTimer(timerid);
	}

	globalreg->sourcetracker->RemoveSourceActCallback(&droneclient_pst_sourceact_hook);

	globalreg->RemovePollableSubsys(this);
}

void DroneClientFrame::SetPacketsource(void *in_src) {
	packetsource = in_src;
}

void dcf_connect_hook(GlobalRegistry *globalreg, int status, void *auxptr) {
	((DroneClientFrame *) auxptr)->ConnectCB(status);
}

void DroneClientFrame::ConnectCB(int status) {
	ostringstream osstr;

	// fprintf(stderr, "debug - dcf connectcb %u\n", status);

	if (status != 0) {
		if (reconnect == 0) {
			osstr << "Kismet drone connection to " << cli_host << ":" <<
				cli_port << " failed (" << strerror(errno) << ") and reconnection "
				"not enabled";
			_MSG(osstr.str(), MSGFLAG_PRINTERROR);
			return;
		} else {
			osstr << "Could not create connection to the Kismet drone "
				"server at " << cli_host << ":" << cli_port << " (" <<
				strerror(errno) << "), will attempt to reconnect in 5 seconds";
			_MSG(osstr.str(), MSGFLAG_PRINTERROR);
		}

		last_disconnect = globalreg->timestamp.tv_sec;
		last_frame = globalreg->timestamp.tv_sec;

		return;
	}

	last_disconnect = 0;
	last_frame = globalreg->timestamp.tv_sec;

	return;
}

int DroneClientFrame::OpenConnection(string in_conparm, int in_recon) {
	char cli_proto[11];
	ostringstream osstr;

	// fprintf(stderr, "debug - dcf openconnection\n");

	if (sscanf(in_conparm.c_str(), "%10[^:]://%128[^:]:%d",
			   cli_proto, cli_host, &cli_port) != 3) {
		_MSG("Drone client unable to parse remote server info from '" + 
			 in_conparm + "', expected proto://host:port", MSGFLAG_PRINTERROR);
		return -1;
	}

	if (strncasecmp(cli_proto, "tcp", 4) == 0) {
		tcpcli = new TcpClient(globalreg);
		netclient = tcpcli;

		RegisterNetworkClient(tcpcli);
		tcpcli->RegisterClientFramework(this);

		cli_type = 0;
	} else {
		_MSG("Invalid protocol '" + string(cli_proto) + "' for drone connection",
			 MSGFLAG_PRINTERROR);
		return -1;
	}

	last_frame = globalreg->timestamp.tv_sec;
	reconnect = in_recon;

	// Queue async reconnect
	netclient->Connect(cli_host, cli_port, dcf_connect_hook, this);

	return 1;
}

int DroneClientFrame::time_handler() {
	if (last_disconnect != 0) {
		if (globalreg->timestamp.tv_sec - last_disconnect > 5) {
			_MSG("Attempting to reconnect to Kismet drone server at " +
				 string(cli_host) + ":" + IntToString(cli_port), MSGFLAG_ERROR);
			last_frame = globalreg->timestamp.tv_sec;
			Reconnect();
		}
	}

	if (last_disconnect == 0) {
		if (globalreg->timestamp.tv_sec - last_frame > 20) {
			if (tcpcli->Valid() == 0) {
				_MSG("Unable to establish connection to Kismet drone server at " + 
					 string(cli_host) + ":" + IntToString(cli_port) + " in 20 seconds, "
					 "attempting to reconnect", MSGFLAG_ERROR);
				last_disconnect = 0;
				last_frame = globalreg->timestamp.tv_sec;
			} else {
				_MSG("No frames from Kismet drone server at " + string(cli_host) + 
					 ":" + IntToString(cli_port) + " in 20 seconds, reconnecting",
					 MSGFLAG_ERROR);
				last_disconnect = last_frame = globalreg->timestamp.tv_sec;
			}

			Reconnect();
		}
	}

	return 1;
}

void DroneClientFrame::SourceActionHandler(pst_packetsource *src, int action, 
										   int flags) {
	unsigned int cmd = DRONE_CHS_CMD_NONE;

	if (action == SOURCEACT_HOPENABLE || action == SOURCEACT_HOPDISABLE) {
		cmd = DRONE_CHS_CMD_SETHOP;
	} else if (action == SOURCEACT_CHVECTOR) {
		cmd = DRONE_CHS_CMD_SETVEC;
	} else if (action == SOURCEACT_CHHOPDWELL) {
		cmd = DRONE_CHS_CMD_SETHOPDWELL;
	}
}

int DroneClientFrame::Reconnect() {
	ostringstream osstr;

	if (tcpcli == NULL)
		return 0;

	tcpcli->KillConnection();

	if (cli_type == 0) {
		netclient->Connect(cli_host, cli_port, dcf_connect_hook, this);

		return 1;
	}

	return 0;
}

int DroneClientFrame::KillConnection() {
	ClientFramework::KillConnection();

	// last_disconnect = globalreg->timestamp.tv_sec;

	// Kill all our faked packet sources
	for (map<uuid, int>::iterator i = virtual_src_map.begin();
		 i != virtual_src_map.end(); ++i) {
		pst_packetsource *psrc = 
			globalreg->sourcetracker->FindLivePacketSourceUUID(i->first);
		KisPacketSource *src = psrc->strong_source;
		if (src != NULL) {
			globalreg->sourcetracker->RemoveLivePacketSource(src);
			delete src;
		}
	}

	virtual_src_map.erase(virtual_src_map.begin(), virtual_src_map.end());

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
	if (netclient == NULL)
		return 0;

	int ret = netclient->Poll(in_rset, in_wset);

	if (ret < 0) {
		KillConnection();
		last_disconnect = globalreg->timestamp.tv_sec;
	}

	return ret;
}

int DroneClientFrame::ParseData() {
	int len, rlen;
	uint8_t *buf;
	ostringstream osstr;
	unsigned int pos = 0;

	if (netclient == NULL)
		return 0;

	if (netclient->Valid() == 0)
		return 0;

	// Allocate a buffer
	len = netclient->FetchReadLen();
	buf = new uint8_t[len + 1];

	// Fetch all the data we have queued
	if (netclient->ReadData(buf, len, &rlen) < 0) {
		if (reconnect) {
			_MSG("Kismet drone client failed to read data from the "
				 "TCP connection.  Will attempt to reconnect in 5 seconds",
				 MSGFLAG_ERROR);

			KillConnection();
			last_disconnect = globalreg->timestamp.tv_sec;
			delete[] buf;
			return 0;
		} else {
			delete[] buf;
			_MSG("Kismet drone client failed to read data from the "
				 "TCP connection and reconnecting not enabled.", MSGFLAG_ERROR);
			return -1;
		}
	}

	// Bail if we're too small to hold even a packet header
	if ((unsigned int) rlen < sizeof(drone_packet)) {
		delete[] buf;
		return 0;
	}

	// Loop through
	while (rlen > (int) pos && (rlen - pos) >= (int) sizeof(drone_packet)) {
		drone_packet *dpkt = (drone_packet *) &(buf[pos]);

		if (kis_ntoh32(dpkt->sentinel) != DroneSentinel) {
			/*
			fprintf(stderr, "debug - pkt sentinel mismatch pos %u rlen %u\n", pos, rlen);
			for (unsigned int z = pos; z < rlen; z++)
				fprintf(stderr, "%02x ", buf[z]);
			fprintf(stderr, "\n");
			*/

			if (reconnect) {
				_MSG("Kismet drone client failed to find the sentinel "
					 "value in a packet header, dropping connection.  Will "
					 "attempt to reconnect in 5 seconds", MSGFLAG_ERROR);
				KillConnection();
				last_disconnect = globalreg->timestamp.tv_sec;
				delete[] buf;
				return 0;
			} else {
				delete[] buf;
				_MSG("Kismet drone client failed to find the sentinel "
					 "value in a packet header.  This error is fatal because "
					 "drone reconnecting is not enabled", MSGFLAG_ERROR);
				return -1;
			}
		}

		unsigned int dplen = kis_ntoh32(dpkt->data_len);

		// fprintf(stderr, "debug - dplen %u\n", dplen);

		// Check for incomplete packets
		if (rlen - (int) pos < (int) (dplen + sizeof(drone_packet))) {
			break;
		}

		netclient->MarkRead(dplen + sizeof(drone_packet));
		pos += dplen + sizeof(drone_packet);

		unsigned int dcid = kis_ntoh32(dpkt->drone_cmdnum);

		// Handle the packet types
		if (dcid == DRONE_CMDNUM_NULL) {
			// Nothing special to do here, treat it as an update packet
		} else if (dcid == DRONE_CMDNUM_HELO) {
			drone_helo_packet *hpkt = (drone_helo_packet *) dpkt->data;
			char rname[33];

			sscanf((char *) hpkt->host_name, "%32s", rname);
			remote_name = string(rname);

			if (kis_ntoh32(hpkt->drone_version) != KIS_DRONE_VERSION) {
				osstr << "Kismet drone client got remote protocol "
					"version " << kis_ntoh32(hpkt->drone_version) << " but uses "
					"version " << KIS_DRONE_VERSION << ".  All features or "
					"components may not be available";
				_MSG(osstr.str(), MSGFLAG_INFO);
			} else {
				osstr << "Kismet drone client connected to remote server "
					"\"" + remote_name + "\" using protocol version " << 
					kis_ntoh32(hpkt->drone_version);
				_MSG(osstr.str(), MSGFLAG_INFO);
			}
		} else if (dcid == DRONE_CMDNUM_STRING) {
			drone_string_packet *spkt = (drone_string_packet *) dpkt->data;
			string msg = string("DRONE(" + remote_name + ") - ");
			uint32_t len = kis_ntoh32(spkt->msg_len);
			// Don't trust us to have a final terminator, copy manually
			for (unsigned int x = 0; x < len; x++) {
				msg += spkt->msg[x];
			}
			// Inject it into the messagebus w/ the normal 
			_MSG(msg, kis_ntoh32(spkt->msg_flags));
		} else if (dcid == DRONE_CMDNUM_SOURCE) {
			drone_source_packet *spkt = (drone_source_packet *) dpkt->data;

			uint32_t sbm = kis_ntoh32(spkt->source_content_bitmap);
			uint16_t sourcelen = kis_ntoh16(spkt->source_hdr_len);
			uint16_t rofft = 0;

			// New source data we're making
			uuid new_uuid;
			string namestr, interfacestr, typestr;
			char strbuffer[17];
			int src_invalidated = 0;
			int channel_hop = -1, channel_dwell = -1, channel_rate = -1;
			// Ghetto method of tracking how many components we've filled in.
			// We should get a 8 to make a source.
			int comp_counter = 0;

			if ((sbm & DRONEBIT(DRONE_SRC_UUID)) &&
				(rofft + sizeof(drone_trans_uuid) <= sourcelen)) {

				UUID_CONV_DRONE(&(spkt->uuid), new_uuid);

				comp_counter++;

				rofft += sizeof(drone_trans_uuid);
			}

			if ((sbm & DRONEBIT(DRONE_SRC_INVALID)) &&
				(rofft + 2 <= sourcelen)) {
				src_invalidated = kis_ntoh16(spkt->invalidate);
				comp_counter++;
				rofft += 2;
			}

			if ((sbm & DRONEBIT(DRONE_SRC_NAMESTR)) && (rofft + 16 <= sourcelen)) {
				sscanf((const char *) spkt->name_str, "%16s", strbuffer);
				namestr = string(strbuffer);
				comp_counter++;
				rofft += 16;
			}

			if ((sbm & DRONEBIT(DRONE_SRC_INTSTR)) && (rofft + 16 <= sourcelen)) {
				sscanf((const char *) spkt->interface_str, "%16s", strbuffer);
				interfacestr = string(strbuffer);
				comp_counter++;
				rofft += 16;
			}

			if ((sbm & DRONEBIT(DRONE_SRC_TYPESTR)) && (rofft + 16 <= sourcelen)) {
				sscanf((const char *) spkt->type_str, "%16s", strbuffer);
				typestr = string(strbuffer);
				comp_counter++;
				rofft += 16;
			}

			if ((sbm & DRONEBIT(DRONE_SRC_CHANHOP)) &&
				 (rofft + 1 <= sourcelen)) {
				channel_hop = spkt->channel_hop;
				comp_counter++;
				rofft += 1;
			}

			if ((sbm & DRONEBIT(DRONE_SRC_CHANNELDWELL)) &&
				(rofft + 2 <= sourcelen)) {
				channel_dwell = kis_ntoh16(spkt->channel_dwell);
				comp_counter++;
				rofft += 2;
			}

			if ((sbm & DRONEBIT(DRONE_SRC_CHANNELRATE)) &&
				(rofft + 2 <= sourcelen)) {
				channel_rate = kis_ntoh16(spkt->channel_rate);
				comp_counter++;
				rofft += 2;
			}

			if (comp_counter >= 8 && src_invalidated == 0 && new_uuid.error == 0) {
				_MSG("Saw drone tunneled source " + new_uuid.UUID2String() + " name:" + 
					namestr + " intf:" + interfacestr, MSGFLAG_INFO);

				_MSG("Live-adding pseudo capsources from drones temporarily disabled "
					 "until rewrite.", MSGFLAG_INFO);
#if 0
				// Make sure the source doesn't exist in the real tracker
				pst_packetsource *rsrc = 
					globalreg->sourcetracker->FindLivePacketSourceUUID(new_uuid);

				if (rsrc == NULL) {
					ostringstream osstr;

					osstr << interfacestr << ":uuid=" << new_uuid.UUID2String();
					if (namestr != "")
						osstr << ",name=" << namestr;

					osstr << ",channellist=n/a";

					// Derive the rest of the source options
					if (channel_hop == 0)
						osstr << ",hop=false";

					if (channel_dwell > 0) {
						osstr << ",dwell=" << channel_dwell;
					} else if (channel_rate > 0) {
						osstr <<  ",velocity=" << channel_rate;
					}

					// Make the strong source with no options, we'll push them
					// via the sourcetracker registration
					PacketSource_DroneRemote *rem = 
						new PacketSource_DroneRemote(globalreg, interfacestr, NULL);

					rem->SetDroneFrame(this);

					if (globalreg->sourcetracker->AddLivePacketSource(
										osstr.str(), rem) < 0) {
						_MSG("Failed to add drone virtual source for remote "
							 "source " + interfacestr + " something went wrong.",
							 MSGFLAG_ERROR);
						delete rem;

						break;
					}

					rem->SetPST(
						globalreg->sourcetracker->FindLivePacketSourceUUID(new_uuid));

					virtual_src_map[new_uuid] = 1;
				}
			} else if (src_invalidated == 1 && new_uuid.error == 0) {
				pst_packetsource *rsrc = 
					globalreg->sourcetracker->FindLivePacketSourceUUID(new_uuid);

				// Make sure the source really exists, and make sure its one of our
				// virtual sources, because we don't let a drone try to cancel a
				// local real source
				if (rsrc != NULL && 
					virtual_src_map.find(new_uuid) != virtual_src_map.end()) {
					// We don't have to close anything since the virtual interfaces
					// are just nonsense

					_MSG("Removing capture source " + 
						 rsrc->strong_source->FetchName() + ", UUID " + 
						 new_uuid.UUID2String() + " from remote drone", 
						 MSGFLAG_INFO);

					globalreg->sourcetracker->RemovePacketSource(rsrc);
					virtual_src_map.erase(new_uuid);
				}
#endif
			}
		} else if (dcid == DRONE_CMDNUM_CAPPACKET) {
			// printf("debug - looks like cap packet\n");
			drone_capture_packet *dcpkt = (drone_capture_packet *) dpkt->data;
			uint32_t poffst = 0;

			kis_packet *newpack = globalreg->packetchain->GeneratePacket();

			uint32_t cbm = kis_ntoh32(dcpkt->cap_content_bitmap);

			if ((cbm & DRONEBIT(DRONE_CONTENT_RADIO))) {
				// printf("debug - cbm radio\n");
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
				uint32_t rcbm = kis_ntoh32(dsr->radio_content_bitmap);
				if ((rcbm & DRONEBIT(DRONE_RADIO_ACCURACY)) &&
					(rofft + 2 <= sublen)) {
					radio->accuracy = kis_ntoh16(dsr->radio_accuracy);
					rofft += 2;
				}
				if ((rcbm & DRONEBIT(DRONE_RADIO_FREQ_MHZ)) &&
					(rofft + 2 <= sublen)) {
					radio->freq_mhz = kis_ntoh16(dsr->radio_freq_mhz);
					rofft += 2;
				}
				if ((rcbm & DRONEBIT(DRONE_RADIO_SIGNAL_DBM)) &&
					(rofft + 2 <= sublen)) {
					radio->signal_dbm = (int16_t) kis_ntoh16(dsr->radio_signal_dbm);
					rofft += 2;
				}
				if ((rcbm & DRONEBIT(DRONE_RADIO_NOISE_DBM)) &&
					(rofft + 2 <= sublen)) {
					radio->noise_dbm = (int16_t) kis_ntoh16(dsr->radio_noise_dbm);
					rofft += 2;
				}
				if ((rcbm & DRONEBIT(DRONE_RADIO_CARRIER)) &&
					(rofft + 4 <= sublen)) {
					radio->carrier = 
						(phy_carrier_type) kis_ntoh32(dsr->radio_carrier);
					rofft += 4;
				}
				if ((rcbm & DRONEBIT(DRONE_RADIO_ENCODING)) &&
					(rofft + 4 <= sublen)) {
					radio->encoding = 
						(phy_encoding_type) kis_ntoh32(dsr->radio_encoding);
					rofft += 4;
				}
				if ((rcbm & DRONEBIT(DRONE_RADIO_DATARATE)) &&
					(rofft + 4 <= sublen)) {
					radio->datarate = kis_ntoh32(dsr->radio_datarate);
					rofft += 4;
				}
				if ((rcbm & DRONEBIT(DRONE_RADIO_SIGNAL_RSSI)) &&
					(rofft + 2 <= sublen)) {
					radio->signal_rssi = (int16_t) kis_ntoh16(dsr->radio_signal_rssi);
					rofft += 2;
				}
				if ((rcbm & DRONEBIT(DRONE_RADIO_NOISE_RSSI)) &&
					(rofft + 2 <= sublen)) {
					radio->noise_rssi = (int16_t) kis_ntoh16(dsr->radio_noise_rssi);
					rofft += 2;
				}

				newpack->insert(_PCM(PACK_COMP_RADIODATA), radio);

				// Jump to the end of this packet
				poffst += sublen;
			}

			if ((cbm & DRONEBIT(DRONE_CONTENT_GPS))) {
				// printf("debug - cbm gps\n");
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

				uint32_t gcbm = kis_ntoh32(dsg->gps_content_bitmap);
				if ((gcbm & DRONEBIT(DRONE_GPS_FIX)) &&
					(rofft + 2 <= sublen)) {
					gpsinfo->gps_fix = kis_ntoh16(dsg->gps_fix);
					rofft += 2;
				}
				if ((gcbm & DRONEBIT(DRONE_GPS_LAT)) &&
					(rofft + sizeof(drone_trans_double) <= sublen)) {
					DOUBLE_CONV_DRONE(gpsinfo->lat, &(dsg->gps_lat));
					rofft += sizeof(drone_trans_double);
				}
				if ((gcbm & DRONEBIT(DRONE_GPS_LON)) &&
					(rofft + sizeof(drone_trans_double) <= sublen)) {
					DOUBLE_CONV_DRONE(gpsinfo->lon, &(dsg->gps_lon));
					rofft += sizeof(drone_trans_double);
				}
				if ((gcbm & DRONEBIT(DRONE_GPS_ALT)) &&
					(rofft + sizeof(drone_trans_double) <= sublen)) {
					DOUBLE_CONV_DRONE(gpsinfo->alt, &(dsg->gps_alt));
					rofft += sizeof(drone_trans_double);
				}
				if ((gcbm & DRONEBIT(DRONE_GPS_SPD)) &&
					(rofft + sizeof(drone_trans_double) <= sublen)) {
					DOUBLE_CONV_DRONE(gpsinfo->spd, &(dsg->gps_spd));
					rofft += sizeof(drone_trans_double);
				}
				if ((gcbm & DRONEBIT(DRONE_GPS_HEADING)) &&
					(rofft + sizeof(drone_trans_double) <= sublen)) {
					DOUBLE_CONV_DRONE(gpsinfo->heading, &(dsg->gps_heading));
					rofft += sizeof(drone_trans_double);
				}

				newpack->insert(_PCM(PACK_COMP_GPS), gpsinfo);

				// Jump to the end of this packet
				poffst += sublen;
			}

			if ((cbm & DRONEBIT(DRONE_CONTENT_FCS))) {
				// printf("debug - cbm fcs\n");
				kis_packet_checksum *fcschunk = new kis_packet_checksum;

				fcschunk->set_data(&(dcpkt->content[poffst]), 4);

				fcschunk->checksum_valid = 1;

				newpack->insert(_PCM(PACK_COMP_CHECKSUM), fcschunk);

				// Jump to the end of this packet
				poffst += 4;
			}

			if ((cbm & DRONEBIT(DRONE_CONTENT_IEEEPACKET))) {
				// Jump to thend of the capframe
				poffst = kis_ntoh32(dcpkt->cap_packet_offset);

				// printf("debug - pofft %u\n", poffst);

				drone_capture_sub_data *ds11 = 
					(drone_capture_sub_data *) &(dcpkt->content[poffst]);

				uint16_t sublen = kis_ntoh16(ds11->data_hdr_len);
				// printf("debug - data hdr len %u\n", sublen);

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

				// Make a data chunk, assuming 802.11 if we don't have
				// a DLT, otherwise with the remote DLT
				kis_datachunk *chunk = new kis_datachunk;

				uuid new_uuid;

				uint16_t rofft = 0;
				uint32_t ecbm = kis_ntoh32(ds11->data_content_bitmap);

				if ((ecbm & DRONEBIT(DRONE_DATA_UUID)) &&
					(rofft + sizeof(drone_trans_uuid) <= sublen)) {
					UUID_CONV_DRONE(&(ds11->uuid), new_uuid);
					// printf("debug - data uuid %s\n", new_uuid.UUID2String().c_str());
					rofft += sizeof(drone_trans_uuid);
				}
				if ((ecbm & DRONEBIT(DRONE_DATA_PACKLEN)) &&
					(rofft + 2 <= sublen)) {
					chunk->length = kismin(kis_ntoh16(ds11->packet_len),
										   (uint32_t) MAX_PACKET_LEN);
					// printf("debug - data packlen %u offt %u\n", chunk->length, rofft);
					rofft += 2;
				}

				if ((ecbm & DRONEBIT(DRONE_DATA_TVSEC)) &&
					(rofft + 8 <= sublen)) {
					// printf("debug - data tvsec\n");
					newpack->ts.tv_sec = kis_ntoh64(ds11->tv_sec);
					rofft += 8;
				} else {
					newpack->ts.tv_sec = globalreg->timestamp.tv_sec;
				}

				if ((ecbm & DRONEBIT(DRONE_DATA_TVUSEC)) &&
					(rofft + 8 <= sublen)) {
					// printf("debug - data usec\n");
					newpack->ts.tv_usec = kis_ntoh64(ds11->tv_usec);
					rofft += 8;
				} else {
					newpack->ts.tv_usec = globalreg->timestamp.tv_usec;
				}

				if ((ecbm & DRONEBIT(DRONE_DATA_DLT)) &&
					(rofft + 4 <= sublen)) {
					chunk->dlt = kis_ntoh32(ds11->dlt);
					// printf("debug - dlt offt %u %u\n", rofft, chunk->dlt);
					rofft += 4;
				} else {
					chunk->dlt = KDLT_IEEE802_11;
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

				// Fill in the capture source if we can find it locally, and only
				// accept from sources we understand, otherwise it shows up as
				// from the drone itself, as long as we have a local source
				if (new_uuid.error == 0 && 
					virtual_src_map.find(new_uuid) != virtual_src_map.end()) {
					PacketSource_DroneRemote *rsrc = NULL;

					pst_packetsource *psrc =
						globalreg->sourcetracker->FindLivePacketSourceUUID(new_uuid);

					if (psrc != NULL && psrc->strong_source != NULL) {
						rsrc = (PacketSource_DroneRemote *) psrc->strong_source;
					
						// Safe because we only do it on our own virtuals
						rsrc->IncrementNumPackets();
						kis_ref_capsource *csrc_ref = new kis_ref_capsource;
						csrc_ref->ref_source = rsrc;
						newpack->insert(_PCM(PACK_COMP_KISCAPSRC), csrc_ref);
					}
				} else if (packetsource != NULL) {
					kis_ref_capsource *csrc_ref = new kis_ref_capsource;
					csrc_ref->ref_source = (KisPacketSource *) packetsource;
					newpack->insert(_PCM(PACK_COMP_KISCAPSRC), csrc_ref);
				}
			}

			last_frame = time(0);

			globalreg->packetchain->ProcessPacket(newpack);
		}
	}
	
	delete[] buf;

	return 1;
}

int DroneClientFrame::SendPacket(drone_packet *in_pack) {
	if (netclient->Valid() == 0 && last_disconnect != 0) {
		if (Reconnect() <= 0)
			return 0;
	}

	int nlen = kis_ntoh32(in_pack->data_len) + sizeof(drone_packet);

	if (netclient->WriteData((void *) in_pack, nlen) < 0 ||
		globalreg->fatal_condition) {
		last_disconnect = time(0);
		return -1;
	}

	return 1;
}

int DroneClientFrame::SendChannelData(pst_packetsource *in_src, unsigned int in_cmd) {
	drone_packet *dpkt = 
		(drone_packet *) malloc(sizeof(uint8_t) * 
								(sizeof(drone_packet) + 
								 sizeof(drone_channelset_packet)));
	memset(dpkt, 0, sizeof(uint8_t) * (sizeof(drone_packet) + 
									   sizeof(drone_channelset_packet)));

	dpkt->sentinel = kis_hton32(DroneSentinel);
	dpkt->drone_cmdnum = kis_hton32(DRONE_CMDNUM_CHANNELSET);
	dpkt->data_len = kis_hton32(sizeof(drone_channelset_packet));

	drone_channelset_packet *cpkt = (drone_channelset_packet *) dpkt->data;

	cpkt->channelset_hdr_len = kis_hton16(sizeof(drone_channelset_packet));
	cpkt->channelset_content_bitmap =
		kis_hton32(DRONEBIT(DRONE_CHANNELSET_UUID) |
				   DRONEBIT(DRONE_CHANNELSET_CMD) |
				   DRONEBIT(DRONE_CHANNELSET_CURCH) |
				   DRONEBIT(DRONE_CHANNELSET_HOP) |
				   DRONEBIT(DRONE_CHANNELSET_NUMCH) |
				   DRONEBIT(DRONE_CHANNELSET_CHANNELS) |
				   DRONEBIT(DRONE_CHANNELSET_CHANNELSDWELL) |
				   DRONEBIT(DRONE_CHANNELSET_HOPRATE) |
				   DRONEBIT(DRONE_CHANNELSET_HOPDWELL));

	DRONE_CONV_UUID(in_src->strong_source->FetchUUID(), &(cpkt->uuid));

	cpkt->command = kis_ntoh16(in_cmd);

	if (in_cmd == DRONE_CHS_CMD_SETHOP) {
		cpkt->cur_channel = kis_hton16(in_src->channel);
		cpkt->channel_hop = kis_hton16(in_src->channel_hop);
	} else if (in_cmd == DRONE_CHS_CMD_SETVEC) {
		pst_channellist *chl = 
			globalreg->sourcetracker->FetchSourceChannelList(in_src);
		if (chl == NULL) {
			cpkt->num_channels = 0;
		} else {
			cpkt->num_channels = kis_hton16(chl->channel_vec.size());
			for (unsigned int c = 0; 
				 c < kismin(chl->channel_vec.size(), IPC_SOURCE_MAX_CHANS); c++) {
				if (chl->channel_vec[c].range == 0) {
					cpkt->chandata[c].u.chan_t.channel =
						kis_hton16(chl->channel_vec[c].u.chan_t.channel);
					cpkt->chandata[c].u.chan_t.dwell =
						kis_hton16(chl->channel_vec[c].u.chan_t.channel);
				} else {
					cpkt->chandata[c].u.range_t.start =
						kis_hton16(chl->channel_vec[c].u.range_t.start | (1 << 15));
					cpkt->chandata[c].u.range_t.end =
						kis_hton16(chl->channel_vec[c].u.range_t.end);
					cpkt->chandata[c].u.range_t.width =
						kis_hton16(chl->channel_vec[c].u.range_t.width);
					cpkt->chandata[c].u.range_t.iter =
						kis_hton16(chl->channel_vec[c].u.range_t.iter);
				}

				/*
				cpkt->channels[c] = kis_hton16(chl->channel_vec[c].channel);
				cpkt->channels_dwell[c] = kis_hton16(chl->channel_vec[c].dwell);
				*/
			}
		}
	} else if (in_cmd == DRONE_CHS_CMD_SETHOPDWELL) {
		cpkt->channel_rate = kis_hton16(in_src->channel_rate);
		cpkt->channel_dwell = kis_hton16(in_src->channel_dwell);
	}

	int ret = 0;

	ret = SendPacket(dpkt);

	free(dpkt);

	return ret;
}

PacketSource_Drone::PacketSource_Drone(GlobalRegistry *in_globalreg, 
									   string in_interface,
									   vector<opt_pair> *in_opts) :
	KisPacketSource(in_globalreg, in_interface, in_opts) { 

	droneframe = NULL;
	reconnect = 1;

	// The master source isn't channel capable
	channel_capable = 0;

	// Automatically reconnect
	reconnect = 1;

	// Look for the host and port
	if (FetchOpt("host", in_opts) == "" || FetchOpt("port", in_opts) == "") {
		_MSG("Drone source missing 'host' or 'port' option.  Kismet now uses the "
			 "'host' and 'port' source options to configure remote Drones (for example "
			 "ncsource=drone:host=127.0.0.1,port=2502,reconnect=true)", MSGFLAG_ERROR);
		error = 1;
		return;
	}

	connecturl = "tcp://" + FetchOpt("host", in_opts) + ":" + 
		FetchOpt("port", in_opts);

	// Look for the reconnect parm
	// if (FetchOpt("reconnect", in_opts) != "" &&
	// 	StrLower(FetchOpt("reconnect", in_opts)) != "true") {
	if (FetchOptBoolean("reconnect", in_opts, 1)) {
		reconnect = 0;
		_MSG("Disabling reconnection on drone source '" + name + "' '" + 
			 interface + "'.  If the connection fails this source will remain "
			 "inactive.", MSGFLAG_INFO);
	}
}

int PacketSource_Drone::RegisterSources(Packetsourcetracker *tracker) {
	// Register the pcapfile source based off ourselves, nonroot, nonchildcontrol
	tracker->RegisterPacketProto("drone", this, "n/a", 0);
	return 1;
}

PacketSource_Drone::~PacketSource_Drone() {
	if (droneframe != NULL) {
		droneframe->Shutdown();
		delete droneframe;
	}
}

int PacketSource_Drone::OpenSource() {
	if (error) {
		_MSG("packetsource drone (" + name + ") failed to initialize "
			 "drone framework and open connection, check previous errors "
			 "for why.", MSGFLAG_PRINTERROR);
		return -1;
	}

	if (droneframe == NULL)
		droneframe = new DroneClientFrame(globalreg);

	droneframe->SetPacketsource((void *) this);

	if (droneframe->OpenConnection(connecturl, reconnect) < 0 ||
		globalreg->fatal_condition) {
		_MSG("Packetsource drone (" + name + ") failed to create drone "
			 "framework and open connection", MSGFLAG_PRINTERROR);
		error = 1;
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

PacketSource_DroneRemote::~PacketSource_DroneRemote() {
	// nothing right now
}

int PacketSource_DroneRemote::RegisterSources(Packetsourcetracker *tracker) {
	// Nothing to do here, since we don't have any types per se that belong
	// to us
	return 1;
}

int PacketSource_DroneRemote::SetChannel(unsigned int in_ch) {
	if (droneframe == NULL)
		return 0;

	if (droneframe->Valid() == 0)
		return 0;

	// Toss the error, we always "succeed"
	droneframe->SendChannelData(pstsource, DRONE_CHS_CMD_SETCUR);

	return 1;
}

int PacketSource_DroneRemote::FetchChannel() {
	return 0;
}

