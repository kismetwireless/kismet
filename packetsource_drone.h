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

#define USE_PACKETSOURCE_DRONE

int droneclienttimer_hook(TIMEEVENT_PARMS);

class DroneClientFrame : public ClientFramework {
public:
	DroneClientFrame();
	DroneClientFrame(GlobalRegistry *in_globalreg);
	virtual ~DroneClientFrame();

	virtual void SetPacketsource(void *in_src);
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

	void *packetsource;

	int timerid;
};

class PacketSource_Drone : public KisPacketSource {
public:
	PacketSource_Drone() {
		fprintf(stderr, "FATAL OOPS:  Packetsource_Drone() called\n");
		exit(1);
	}

	PacketSource_Drone(GlobalRegistry *in_globalreg) :
		KisPacketSource(in_globalreg) {
	}

	virtual KisPacketSource *CreateSource(GlobalRegistry *in_globalreg,
										  string in_type, string in_name,
										  string in_dev) {
		return new PacketSource_Drone(in_globalreg, in_type, in_name, in_dev);
	}

	virtual int AutotypeProbe(string in_device) {
		return 0;
	}

	virtual int RegisterSources(Packetsourcetracker *tracker);

	// Standard interface for capturesource
	PacketSource_Drone(GlobalRegistry *in_globalreg, string in_type, 
					   string in_name, string in_dev) :
		KisPacketSource(in_globalreg, in_type, in_name, in_dev) { 
			droneframe = NULL;
		}
	virtual ~PacketSource_Drone();

	virtual int OpenSource();
	virtual int CloseSource();

	// The 'master source' isn't channel capable, virtual subsources might
	// be.
	virtual int FetchChannelCapable() { return 0; }

	// No meaning on the drone master source
	virtual int EnableMonitor() { return 0; }
	virtual int DisableMonitor() { return PACKSOURCE_UNMONITOR_RET_SILENCE; }
	virtual int SetChannel(int in_ch) { return 0; }
	virtual int FetchChannel() { return 0; }

	virtual int ChildIPCControl() { return 0; }

	virtual int FetchDescriptor();

	virtual int Poll();

protected:
	virtual void FetchRadioData(kis_packet *in_packet);

	DroneClientFrame *droneframe;
	int reconnect;
};

// Virtual packet source that inherits the UUID and characteristics of a capture
// source on a remote drone.  All channel controls are pumped through to the drone
// source.  Packets from the drone remotes will show up from sources based off
// this.
class PacketSource_DroneRemote : public KisPacketSource {
public:
	PacketSource_DroneRemote() {
		fprintf(stderr, "FATAL OOPS:  Packetsource_DroneRemote() called\n");
		exit(1);
	}

	PacketSource_DroneRemote(GlobalRegistry *in_globalreg) :
		KisPacketSource(in_globalreg) {

		}

	virtual KisPacketSource *CreateSource(GlobalRegistry *in_globalreg,
										  string in_type, string in_name,
										  string in_dev) {
		return new PacketSource_DroneRemote(in_globalreg, in_type, in_name, in_dev);
	}

	virtual int AutotypeProbe(string in_device) {
		return 0;
	}

	virtual int RegisterSources(Packetsourcetracker *tracker);

	PacketSource_DroneRemote(GlobalRegistry *in_globalreg, string in_type,
							 string in_name, string in_dev) :
		KisPacketSource(in_globalreg, in_type, in_name, in_dev) {
			droneframe = NULL;
			rem_channelcapable = 0;
		}
	virtual ~PacketSource_DroneRemote();

	// Open and close have no effect
	virtual int OpenSource() { return 0; }
	virtual int CloseSource() { return 0; }

	// Return remote capability
	virtual int FetchChannelCapable() { return rem_channelcapable; }

	// Dropthrough commands to drone
	virtual int SetChannel(int in_ch);
	virtual int SetChannelSequence(vector<int> in_seq);
	virtual int SetChannelSeqPos(int in_offt);
	virtual int FetchChannel();
	virtual int SetChannelHop(int in_hop);
	virtual int FetchChannelHop();

	// Stuff we can't implement
	virtual int FetchNextChannel() { return 0; }
	virtual int EnableMonitor() { return 0; }
	virtual int DisableMonitor() { return PACKSOURCE_UNMONITOR_RET_SILENCE; }

	// Local stuff
	virtual int ChildIPCControl() { return 0; }
	virtual int FetchDescriptor();
	virtual int Poll();

	// Special functions to let the drone framework spawn and control us
	virtual int SetDroneFrame(DroneClientFrame *in_frame) {
		droneframe = in_frame;
		return 1;
	}

	virtual int SetUUID(uuid in_uuid) {
		src_uuid = in_uuid;
		return 1;
	}

protected:
	virtual void FetchRadioData(kis_packet *in_packet);

	int rem_channelcapable;
	DroneClientFrame *droneframe;
};

#endif

