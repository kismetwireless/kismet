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
#include <serialclient.h>

#include "packetsource_serialdev.h"
#include "packet_dot15d4.h"

d15d4_serialdev_helper::d15d4_serialdev_helper(GlobalRegistry *in_globalreg) : 
	ClientFramework(in_globalreg) {

	sercli = NULL;
	netclient = NULL;
}

int d15d4_serialdev_helper::OpenSerialDev(string in_dev) {
	sercli = new SerialClient(globalreg);
	netclient = sercli;

	device = in_dev;

	// fprintf(stderr, "debug - serialdev helper for %s\n", in_dev.c_str());

	RegisterNetworkClient(sercli);
	sercli->RegisterClientFramework(this);

	return Reconnect();
}

d15d4_serialdev_helper::~d15d4_serialdev_helper() {
	globalreg->RemovePollableSubsys(this);
}

int d15d4_serialdev_helper::Shutdown() {
	if (sercli != NULL) {
		sercli->FlushRings();
		sercli->KillConnection();
	}

	return 1;
}

int d15d4_serialdev_helper::Reconnect() {
	if (sercli->Connect(device.c_str(), 0, NULL, NULL) < 0) {
		_MSG("d15d4 serialdev: could not open serial port " + string(device),
			 MSGFLAG_ERROR);
		return 0;
	}

	struct termios options;

	sercli->GetOptions(&options);

	options.c_cflag     |= (CLOCAL | CREAD);
	options.c_lflag     &= ~(ICANON | ECHO | ECHOE | ISIG);
	options.c_oflag     &= ~OPOST;

	cfsetispeed(&options, B115200);
	cfsetospeed(&options, B115200);

	sercli->SetOptions(TCSANOW, &options);

	sercli->FlushSerial(TCIFLUSH);

	// sercli->SetBaud(B115200);
	
	state = 1;
	s_id = s_len = s_rlen = s_status = s_level = -1;

	return 1;
}

int d15d4_serialdev_helper::SendCommand(uint8_t *command, unsigned int in_len, 
								  uint8_t *in_data) {
	if (sercli == NULL)
		return 0;

	uint8_t *cmd = new uint8_t[3 + in_len];

	memcpy(cmd, command, 3);

	if (in_len != 0)
		memcpy(cmd + 3, in_data, in_len);

	return sercli->WriteData(cmd, in_len + 3);
}

int d15d4_serialdev_helper::ParseData() {
	int len, rlen;
	char *buf;

	if (netclient == NULL)
		return 0;

	if (netclient->Valid() == 0)
		return 0;

	len = netclient->FetchReadLen();
	buf = new char[len + 1];

	if (netclient->ReadData(buf, len, &rlen) < 0) {
		_MSG("d15d4 serialdev failed to get data from the serial port",
			 MSGFLAG_ERROR);
		return -1;
	}

	netclient->MarkRead(rlen);

	// fprintf(stderr, "debug - got %d in read state %d\n", rlen, state);

	buf[len] = '\0';

	// State inherited from previous read incase we get a partial
	for (unsigned int b = 0; b < rlen; b++) {
		// fprintf(stderr, "debug - %d of %d state %d %x %c\n", b, rlen, state, buf[b], buf[b]);
		if (state == 1) {
			if (buf[b] == 'z') {
				// fprintf(stderr, "debug - serialdev going to stage 2\n");
				state = 2;
			} else if (buf[b] == 0) {
				// fprintf(stderr, "debug - serialdev resetting to stage 1\n");
				// We reset to 1
				state = 1;
			} else {
				_MSG("d15d4 serialdev got unexpected character " + 
					 HexIntToString(buf[b] & 0xFF), MSGFLAG_ERROR);
				state = 1;
			}

			continue;
		} else if (state == 2) {
			if (buf[b] == 'b') {
				// fprintf(stderr, "debug - serialdev going to stage 3\n");
				s_id = -1;
				s_len = -1;
				s_rlen = 0;
				s_status = -1;
				s_level = -1;
				state = 3;
			} else if (buf[b] == 0) {
				// fprintf(stderr, "debug - serialdev resetting from 2 to 1\n");
				state = 1;
			} else {
				_MSG("d15d4 serialdev got unexpected character " + 
					 HexIntToString(buf[b] & 0xFF) + " in state 2", MSGFLAG_ERROR);
				state = 1;
			}

			continue;
		} else if (state == 3) {
			// Get the ID and go to state 4, data/length
			s_id = buf[b] & 0xff;
			// fprintf(stderr, "debug - serialdev got id %x going to stage 4\n", s_id);
			state = 4;

			continue;
		} else if (state == 4) {
			if (s_id == SERIALDEV_RESP_ED) {
				// fprintf(stderr, "debug - serialdev ED %d %d\n", s_status, s_level);
				// ID STATUS LEVEL
				if (s_status < 0) {
					s_status = buf[b] & 0xff;
				} else if (s_level < 0) {
					s_level = buf[b] & 0xff;
					state = 1;
					// fprintf(stderr, "debug - serialdev ED %d %d\n", s_status, s_level);
					// fprintf(stderr, "debug - got ed, going to 1\n");
				}
			} else if (s_id == SERIALDEV_RESP_RECVBLOCK) {
				// fprintf(stderr, "debug - serialdev BLOCK %d %d\n", s_level, s_len);

				// ID LQ LEN buf[]
				if (s_level < 0) {
					// fprintf(stderr, "debug - getting level\n");
					s_level = buf[b] & 0xff;
				} else if (s_len < 0) {
					// fprintf(stderr, "debug - getting len\n");
					s_len = buf[b] & 0xff;
					s_rlen = 0;

					if (s_len > D15D4_MAX_MTU)
						_MSG("d15d4 serialdev got invalid length in d15d4 chunk",
							 MSGFLAG_ERROR);
				} else {
					if (s_rlen < D15D4_MAX_MTU)
						pkt_data[s_rlen] = buf[b] & 0xff;

					s_rlen++;

					if (s_rlen >= s_len) {
						state = 1;

						fprintf(stderr, "debug - serialdev got a packet len %d  ", s_len);
						for (unsigned int zz = 0; zz < s_rlen; zz++) {
							fprintf(stderr, "%02x ", pkt_data[zz]);
						}
						fprintf(stderr, "\n");

						packetsource->QueuePacket(s_len, pkt_data, s_level);
					}
				}
			} else {
				// fprintf(stderr, "debug - serialdev generic id %x status %d\n", s_id, s_status);
				if (s_status < 0)
					s_status = buf[b] & 0xff;

				// fprintf(stderr, "debug - %x got status %x going to state 1\n", s_id, s_status);

				state = 1;
			}

			continue;
		}
	}

	delete[] buf;

	return 1;
}

PacketSource_Serialdev::PacketSource_Serialdev(GlobalRegistry *in_globalreg, 
											   string in_interface,
											   vector<opt_pair> *in_opts) : 
	KisPacketSource(in_globalreg, in_interface, in_opts) {

	fake_fd[0] = -1;
	fake_fd[1] = -1;

	d154_packet_id = globalreg->packetchain->RegisterPacketComponent("IEEE802_15_4");

	serialport = "/dev/ttyUSB1";

	helper = new d15d4_serialdev_helper(globalreg);
	helper->AddPacketsource(this);

	ParseOptions(in_opts);
}

PacketSource_Serialdev::~PacketSource_Serialdev() {
	CloseSource();
	if (helper != NULL) {
		helper->Shutdown();
		delete helper;
	}
}
	

int PacketSource_Serialdev::ParseOptions(vector<opt_pair> *in_opts) {

	KisPacketSource::ParseOptions(in_opts);

	fprintf(stderr, "debug - serialdev parseoptions\n");

	if (FetchOpt("device", in_opts) != "") {
		serialport = FetchOpt("device", in_opts);
	}

	_MSG("Serialdev 802.15.4 using device '" + serialport + "'", MSGFLAG_INFO);

	return 1;
}

int PacketSource_Serialdev::AutotypeProbe(string in_device) {
	// Shortcut like we do on airport
	if (in_device == "d15d4serial") {
		type = "d15d4serial";
		return 1;
	}

	return 0;
}

int PacketSource_Serialdev::OpenSource() {
	int ret;

	fprintf(stderr, "debug - serialdev open helper %p device %s\n", helper, serialport.c_str());
	ret =  helper->OpenSerialDev(serialport);
	fprintf(stderr, "debug - serialdev open ret %d\n", ret);

	if (ret < 0)
		return ret;

	if (pipe(fake_fd) < 0) {
		_MSG("Serialdev 802.15.4 '" + name + "' failed to make a pipe() (this is "
			 "really weird): " + string(strerror(errno)), MSGFLAG_ERROR);
		return 0;
	}

	uint8_t cbuf[1];

	// Send close, then re-open
	helper->SendCommand(SERIALDEV_CMD_CLOSE, 0, NULL);
	helper->SendCommand(SERIALDEV_CMD_OPEN, 0, NULL);
	// cbuf[0] = 1;
	// helper->SendCommand(SERIALDEV_CMD_SETCHAN, 1, cbuf);
	cbuf[0] = SERIALDEV_MODE_RX;
	helper->SendCommand(SERIALDEV_CMD_SETSTATE, 1, cbuf);

	pending_packet = 0;

	return ret;
}

int PacketSource_Serialdev::CloseSource() {
	if (fake_fd[0] >= 0) {
		close(fake_fd[0]);
		fake_fd[0] = -1;
	}

	if (fake_fd[1] >= 0) {
		close(fake_fd[1]);
		fake_fd[1] = -1;
	}

	if (helper != NULL) {
		helper->Shutdown();
	}

	return 1;
}

int PacketSource_Serialdev::SetChannel(unsigned int in_ch) {
	uint8_t cbuf[1];

	// fprintf(stderr, "debug - set channel %u\n", in_ch);

	if (helper == NULL)
		return 0;

	cbuf[0] = (uint8_t) in_ch - 10;
	helper->SendCommand(SERIALDEV_CMD_SETCHAN, 1, cbuf);

	last_channel = in_ch;

	return 1;
}

int PacketSource_Serialdev::FetchDescriptor() {
	return fake_fd[0];
}

int PacketSource_Serialdev::Poll() {
	char rx;

	// Consume the junk byte we used to raise the FD high
	read(fake_fd[0], &rx, 1);

	pending_packet = 0;

	for (unsigned int x = 0; x < packet_queue.size(); x++) {
		kis_packet *newpack = globalreg->packetchain->GeneratePacket();

		newpack->ts.tv_sec = packet_queue[x]->ts.tv_sec;
		newpack->ts.tv_usec = packet_queue[x]->ts.tv_usec;

		kis_datachunk *rawchunk = new kis_datachunk;

		rawchunk->length = packet_queue[x]->len;
		// Allocated during addpacket, freed during packet destruction, so 
		// we just copy the ptr here
		rawchunk->data = packet_queue[x]->data;

		rawchunk->source_id = source_id;
		rawchunk->dlt = KDLT_IEEE802_15_4;

		newpack->insert(_PCM(PACK_COMP_LINKFRAME), rawchunk);

		printf("debug - Got packet chan %d len=%d\n", packet_queue[x]->channel, packet_queue[x]->len);

		// Flag the header
		kis_ref_capsource *csrc_ref = new kis_ref_capsource;
		csrc_ref->ref_source = this;
		newpack->insert(_PCM(PACK_COMP_KISCAPSRC), csrc_ref);

		num_packets++;

		globalreg->packetchain->ProcessPacket(newpack);

		// Delete the temp struct, NOT the data
		delete packet_queue[x];
	}

	// Flush the queue
	packet_queue.clear();

	// printf("debug - packet queue cleared %d\n", packet_queue.size());

	return 1;
}

void PacketSource_Serialdev::QueuePacket(unsigned int in_len, uint8_t *in_data,
										 unsigned int in_sig) {
	if (packet_queue.size() > 20) {
		_MSG("d15d4_serialdev packet queue > 20 packets w/out pickup, something "
			 "is acting weird", MSGFLAG_ERROR);
		return;
	}

	struct PacketSource_Serialdev::serial_pkt *rpkt = 
		new PacketSource_Serialdev::serial_pkt;

	rpkt->sig_lq = in_sig;
	rpkt->len = in_len;
	rpkt->data = new uint8_t[in_len];

	rpkt->ts.tv_sec = globalreg->timestamp.tv_sec;
	rpkt->ts.tv_usec = globalreg->timestamp.tv_usec;

	rpkt->channel = last_channel;

	memcpy(rpkt->data, in_data, in_len);

	packet_queue.push_back(rpkt);

	if (pending_packet == 0) {
		pending_packet = 1;
		write(fake_fd[1], in_data, 1);
	}
}


