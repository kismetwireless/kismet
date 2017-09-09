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

#include <sstream>
#include <iomanip>

#include "configfile.h"
#include "clinetframework.h"
#include "tcpclient.h"
#include "kis_netframe.h"
#include "packetchain.h"
#include "spectool_netclient.h"
#include "endian_magic.h"

enum SPECTRUM_fields {
	SPEC_devname, SPEC_amp_offset_mdbm, SPEC_amp_res_mdbm, SPEC_rssi_max,
	SPEC_start_khz, SPEC_res_hz, SPEC_num_samples, SPEC_samples,
	SPEC_maxfield
};

const char *SPECTRUM_fields_text[] = {
	"devname", "amp_offset_mdbm", "amp_res_mdbm", "rssi_max",
	"start_khz", "res_hz", "num_samples", "samples",
	NULL
};

void Protocol_SPECTRUM_enable(PROTO_ENABLE_PARMS) {
	return;
}

int Protocol_SPECTRUM(PROTO_PARMS) {
	kis_spectrum_data *spec = (kis_spectrum_data *) data;
	ostringstream osstr;

	cache->Filled(field_vec->size());

	for (unsigned int x = 0; x < field_vec->size(); x++) {
		unsigned int fnum = (*field_vec)[x];
		if (fnum >= SPEC_maxfield) {
			out_string += "Unknown field requested";
			return -1;
		}

		osstr.str("");

		if (cache->Filled(fnum)) {
			out_string += cache->GetCache(fnum) + " ";
			continue;
		}

		switch (fnum) {
			case SPEC_devname:
				cache->Cache(fnum, "\001" + spec->dev_name + "\001");
				break;

			case SPEC_amp_offset_mdbm:
				osstr << spec->amp_offset_mdbm;
				cache->Cache(fnum, osstr.str());
				break;

			case SPEC_amp_res_mdbm:
				osstr << spec->amp_res_mdbm;
				cache->Cache(fnum, osstr.str());
				break;

			case SPEC_rssi_max:
				osstr << spec->rssi_max;
				cache->Cache(fnum, osstr.str());
				break;

			case SPEC_start_khz:
				osstr << spec->start_khz;
				cache->Cache(fnum, osstr.str());
				break;

			case SPEC_res_hz:
				osstr << spec->res_hz;
				cache->Cache(fnum, osstr.str());
				break;

			case SPEC_num_samples:
				osstr << spec->rssi_vec.size();
				cache->Cache(fnum, osstr.str());
				break;

			case SPEC_samples:
				for (unsigned int s = 0; s < spec->rssi_vec.size(); s++) {
					osstr << spec->rssi_vec[s];
					if (s != spec->rssi_vec.size() - 1)
						osstr << ":";
				}
				cache->Cache(fnum, osstr.str());
				break;
		}

		out_string += cache->GetCache(fnum) + " ";
	}

	return 1;
}

int stc_recontimer(TIMEEVENT_PARMS) {
	((SpectoolsClient *) auxptr)->Reconnect();

	return 1;
}

void stc_connect_hook(GlobalRegistry *globalreg, int status, void *auxptr) {
	((SpectoolsClient *) auxptr)->ConnectCB(status);
}

void SpectoolsClient::ConnectCB(int status) {
	if (status == 0) {
		_MSG("Using Spectools server on " + string(host) + ":" + IntToString(port),
			 MSGFLAG_INFO);
		last_disconnect = 0;
	} else {
		_MSG("Could not connect to the spectools server " + string(host) + ":" +
			 IntToString(port), MSGFLAG_ERROR);
		last_disconnect = globalreg->timestamp.tv_sec;
	}
}

SpectoolsClient::SpectoolsClient(GlobalRegistry *in_globalreg) :
	ClientFramework(in_globalreg) {
	globalreg = in_globalreg;
	tcpcli = new TcpClient(globalreg);
	netclient = tcpcli;

	RegisterNetworkClient(tcpcli);
	tcpcli->RegisterClientFramework(this);

	if (globalreg->packetchain == NULL) {
		fprintf(stderr, "FATAL OOPS:  Spectoolsclient called before packetchain\n");
		exit(1);
	}

	if (globalreg->kismet_config == NULL) {
		fprintf(stderr, "FATAL OOPS:  Spectoolsclient called before kismet_config\n");
		exit(1);
	}

	if (globalreg->kisnetserver == NULL) {
		fprintf(stderr, "FATAL OOPS:  Spectoolsclient called before kisnetserver\n");
		exit(1);
	}

	last_disconnect = 0;

	// Packetchain spectrum data
	packet_comp_id = 
		globalreg->packetchain->RegisterPacketComponent("SPECTRUM");

	// *SPECTRUM protocol
	spec_proto_id =
		globalreg->kisnetserver->RegisterProtocol("SPECTRUM", 0, 1,
												  SPECTRUM_fields_text,
												  &Protocol_SPECTRUM,
												  &Protocol_SPECTRUM_enable,
												  this);

	if (globalreg->kismet_config->FetchOpt("spectools") == "") {
		_MSG("No spectools= line in config file, will not try to use spectools "
			 "for spectrum data", MSGFLAG_INFO);
		return;
	}

	char temphost[129];
	if (sscanf(globalreg->kismet_config->FetchOpt("spectools").c_str(),
			   "tcp://%128[^:]:%d", temphost, &port) != 2) {
		_MSG("Invalid spectools in config file, expected tcp://host:port, will "
			 "not be able to use spectools", MSGFLAG_ERROR);
		return;
	}

	// Reconnect timer
	recon_timer_id = 
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 30,
											  NULL, 1, &stc_recontimer, this);

	snprintf(host, MAXHOSTNAMELEN, "%s", temphost);

	tcpcli->Connect(host, port, stc_connect_hook, this);
}

SpectoolsClient::~SpectoolsClient() {
	if (recon_timer_id >= 0 && globalreg != NULL)
		globalreg->timetracker->RemoveTimer(recon_timer_id);

	globalreg->kisnetserver->RemoveProtocol(spec_proto_id);

	globalreg->RemovePollableSubsys(this);

	KillConnection();
}

int SpectoolsClient::Shutdown() {
	if (tcpcli != NULL) {
		tcpcli->FlushRings();
		tcpcli->KillConnection();
	}

	return 1;
}

int SpectoolsClient::Reconnect() {
	if (tcpcli != NULL && tcpcli->Valid() == 0 && last_disconnect != 0) {
		tcpcli->KillConnection();
		tcpcli->Connect(host, port, stc_connect_hook, this);
	}

	return 1;
}

int SpectoolsClient::ParseData() {
	int len, rlen;
	uint8_t *buf;
	int pos = 0;

	len = netclient->FetchReadLen();

	if ((unsigned int) len < sizeof(wispy_fr_header))
		return 0;

	buf = new uint8_t[len + 1];

	if (netclient->ReadData(buf, len, &rlen) < 0) {
		_MSG("Failed to fetch spectool data from client connection", 
			 MSGFLAG_ERROR);
		KillConnection();
		delete[] buf;
		return -1;
	}

	if ((unsigned int) rlen < wispy_fr_header_size()) {
		delete[] buf;
		return 0;
	}

	while ((rlen - pos) >= (int) wispy_fr_header_size()) {
		wispy_fr_header *whdr = (wispy_fr_header *) &(buf[pos]);

		if (kis_ntoh32(whdr->sentinel) != WISPY_NET_SENTINEL) {
			_MSG("Failed to find sentinel in spectool data stream, dropping "
				 "connection", MSGFLAG_ERROR);
			KillConnection();
			delete[] buf;
			return -1;
		}

		// Total sizeof frame including this header
		unsigned int wlen = kis_ntoh16(whdr->frame_len);

		// If we didn't peek a whole frame, go away
		if (rlen - (int) pos < (int) wlen) {
			delete[] buf;
			return 0;
		}

		netclient->MarkRead(wlen);
		pos += wlen;

		if (whdr->block_type == WISPY_NET_FRAME_DEVICE) {
			wispy_fr_device *dev;
			spectool_dev *localdev = NULL;

			for (unsigned int x = 0; x < whdr->num_blocks; x++) {
				if (wlen - wispy_fr_header_size() <
					wispy_fr_device_size() * (x + 1)) {
					delete[] buf;
					return -1;
				}

				dev = (wispy_fr_device *) &(whdr->data[wispy_fr_device_size() * x]);

				if (dev->device_version == WISPY_NET_DEVTYPE_LASTDEV) {
					state = spectool_net_state_configured;
					return 1;
				}

				for (unsigned int y = 0; y < device_vec.size(); y++) {
					if (device_vec[y]->dev_id == kis_ntoh32(dev->device_id)) {
						localdev = device_vec[x];
						break;
					}
				}

				if (localdev == NULL) {
					localdev = new spectool_dev;
					device_vec.push_back(localdev);
				}

				localdev->dev_version = dev->device_version;
				localdev->dev_flags = kis_ntoh16(dev->device_flags);
				localdev->dev_id = kis_ntoh32(dev->device_id);

				localdev->dev_name = string((char *) dev->device_name, 
											dev->device_name_len);

				localdev->amp_offset_mdbm = kis_ntoh32(dev->amp_offset_mdbm) * -1;
				localdev->amp_res_mdbm = kis_ntoh32(dev->amp_res_mdbm);
				localdev->rssi_max = kis_ntoh16(dev->rssi_max);

				localdev->start_khz = kis_ntoh32(dev->start_khz);
				localdev->res_hz = kis_ntoh32(dev->res_hz);
				localdev->num_samples = kis_ntoh16(dev->num_samples);

				// Enable it on the server
				wispy_fr_header *ehdr;
				wispy_fr_command *ecmd;
				wispy_fr_command_enabledev *edcmd;

				int sz = 
					wispy_fr_header_size() + 
					wispy_fr_command_size(wispy_fr_command_enabledev_size(0));

				ehdr = (wispy_fr_header *) new uint8_t[sz];

				ecmd = (wispy_fr_command *) ehdr->data;
				edcmd = (wispy_fr_command_enabledev *) ecmd->command_data;

				ehdr->sentinel = kis_hton32(WISPY_NET_SENTINEL);
				ehdr->frame_len = kis_hton16(sz);
				ehdr->proto_version = WISPY_NET_PROTO_VERSION;
				ehdr->block_type = WISPY_NET_FRAME_COMMAND;
				ehdr->num_blocks = 1;

				ecmd->frame_len =
				  kis_hton16(wispy_fr_command_size(wispy_fr_command_enabledev_size(0)));
				ecmd->command_id = WISPY_NET_COMMAND_ENABLEDEV;
				ecmd->command_len = kis_hton16(wispy_fr_command_enabledev_size(0));

				// Just use network endian source
				edcmd->device_id = dev->device_id;

				if (netclient->WriteData((void *) ehdr, sz) < 0) {
					delete[] ehdr;
					return -1;
				}

				delete[] ehdr;
			}
		} else if (whdr->block_type == WISPY_NET_FRAME_SWEEP) {
			wispy_fr_sweep *sweep;
			spectool_dev *localdev = NULL;

			unsigned int fr_pos = 0;

			for (unsigned int x = 0; x < whdr->num_blocks; x++) {
				// Make sure we can fit the frame header
				if (fr_pos >= (wlen - wispy_fr_sweep_size(0))) {
					_MSG("Invalid size for sweep record, disconnecting spectools "
						 "client", MSGFLAG_ERROR);
					delete[] buf;
					return -1;
				}

				sweep = (wispy_fr_sweep *) &(whdr->data[fr_pos]);

				// Advance along the frame
				fr_pos += kis_ntoh16(sweep->frame_len);

				if (fr_pos >= wlen) {
					_MSG("Frame too short for sweep frame, disconnecting spectools "
						 "client", MSGFLAG_ERROR);
					delete[] buf;
					return -1;
				}

				// Bail if we don't have a device for this
				for (unsigned int y = 0; y < device_vec.size(); y++) {
					if (device_vec[x]->dev_id == kis_ntoh32(sweep->device_id)) {
						localdev = device_vec[x];
						break;
					}
				}

				if (localdev == NULL) {
					_MSG("Got spectool sweep frame for device we don't know about, "
						 "skipping", MSGFLAG_ERROR);
					continue;
				}

				if (kis_ntoh16(sweep->frame_len) - wispy_fr_sweep_size(0) < 
					localdev->num_samples) {
					_MSG("Got spectool sweep frame without the expected number "
						 "of samples for device", MSGFLAG_ERROR);
					continue;
				}

				// Make a sweep record
				kis_spectrum_data *specdata = new kis_spectrum_data;

				specdata->dev_name = localdev->dev_name;
				specdata->start_khz = localdev->start_khz;
				specdata->res_hz = localdev->res_hz;
				specdata->amp_offset_mdbm = localdev->amp_offset_mdbm;
				specdata->amp_res_mdbm = localdev->amp_res_mdbm;
				specdata->rssi_max = localdev->rssi_max;

				specdata->start_tm.tv_sec = kis_ntoh32(sweep->start_sec);
				specdata->start_tm.tv_usec = kis_ntoh32(sweep->start_usec);

				for (unsigned int n = 0; n < localdev->num_samples; n++) {
					specdata->rssi_vec.push_back(sweep->sample_data[n]);
				}

				// Send it to everyone (before we add it to the packetchain which 
				// frees it at the end)
				globalreg->kisnetserver->SendToAll(spec_proto_id, (void *) specdata);

				// Make a new packet in the chain
				kis_packet *newpack = globalreg->packetchain->GeneratePacket();

				newpack->ts = specdata->start_tm;

				newpack->insert(packet_comp_id, specdata);

				globalreg->packetchain->ProcessPacket(newpack);

			}
		}

	}

	delete[] buf;

	return 1;
}

