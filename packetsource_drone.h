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

#ifndef __PACKETSOURCE_DRONE_H__
#define __PACKETSOURCE_DRONE_H__

/* Drone client
 *
 * This forms the heart of the drone client system which gets packets from a
 * remote source.
 *
 * The actual packetsource functions as a simple stub which creates and
 * destroys the ClientFramework-derived DroneClientFrame.  DroneClientFrame 
 * handles all of the processing and injection.
 */

#include "config.h"

#include "packet.h"
#include "packetsource.h"
#include "packetchain.h"
#include "gpscore.h"
#include "kis_droneframe.h"
#include "clinetframework.h"
#include "tcpclient.h"

int droneclienttimer_hook(TIMEEVENT_PARMS);

class DroneClientFrame : public ClientFramework {
public:
	DroneClientFrame();
	DroneClientFrame(GlobalRegistry *in_globalreg);
	virtual ~DroneClientFrame();

	virtual int OpenConnection(string in_conparm, int in_recon);

	virtual unsigned int MergeSet(unsigned int in_max_fd, fd_set *out_rset,
								  fd_set *out_wset) {
		return netclient->MergeSet(in_max_fd, out_rset, out_wset);
	}

	virtual int Poll(fd_set &in_rset, fd_set& in_wset);

	virtual int ParseData();
	virtual int KillConnection();
	virtual int Shutdown();

	virtual int time_handler();
	
protected:
	TcpClient *tcpcli;
	int reconnect;

	time_t last_disconnect;

	int cli_type;
	int cli_port;
	char cli_host[129];

	virtual int Reconnect();

	int timerid;
};

class PacketSource_Drone : public KisPacketSource {
public:
	// Standard interface for capturesource
	PacketSource_Drone(GlobalRegistry *in_globalreg, meta_packsource *in_meta, 
					   string in_name, string in_dev) :
		KisPacketSource(in_globalreg, in_meta, in_name, in_dev) { 
			droneframe = NULL;
		}
	virtual ~PacketSource_Drone();

	virtual int OpenSource();
	virtual int CloseSource();

	virtual int FetchDescriptor();

	virtual int Poll();

	virtual int FetchChannel();

protected:
	virtual void FetchRadioData(kis_packet *in_packet);

	DroneClientFrame *droneframe;
	int reconnect;
};	

// Drone registrant and 0-return unmonitor function
KisPacketSource *packetsource_drone_registrant(REGISTRANT_PARMS);
int unmonitor_drone(MONITOR_PARMS);

#endif

