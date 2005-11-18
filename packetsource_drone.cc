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

#include "packet.h"
#include "packetsource.h"
#include "packetchain.h"
#include "gpscore.h"
#include "kis_droneframe.h"
#include "clinetframework.h"
#include "tcpclient.h"
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

	reconnect = 0;

	cli_type = -1;

	timerid = 
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL, 1,
											  &droneclienttimer_hook, (void *) this);

	last_disconnect = 0;
}

DroneClientFrame::~DroneClientFrame() {
	if (netclient != NULL) {
		netclient->KillConnection();
	}

	if (timerid >= 0 && globalreg != NULL) {
		globalreg->timetracker->RemoveTimer(timerid);
	}
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

int DroneClientFrame::ParseData() {

	return 0;
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

