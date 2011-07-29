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

#ifndef __GPSDCLIENT_H__
#define __GPSDCLIENT_H__

#include "config.h"

#ifndef HAVE_LIBGPS

#include "clinetframework.h"
#include "tcpclient.h"
#include "kis_netframe.h"
#include "packetchain.h"
#include "gpscore.h"

// Our command
const char gpsd_init_command[] = "L\n";
// compensate for gpsd ignoring multi-line commands too soon after
// eachother
const char gpsd_watch_command[] = "J=1,W=1,R=1\n";
const char gpsd_poll_command[] = "PAVM\n";

class GPSDClient : public GPSCore {
public:
    GPSDClient();
    GPSDClient(GlobalRegistry *in_globalreg);
    virtual ~GPSDClient();

	string FetchType() {
		return "gpsd";
	}

	string FetchDevice() {
		return "tcp://" + string(host) + ":" + IntToString(port);
	}

	virtual int Timer();

    // Hooks so we can override straight to the TCP core
    virtual int MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
        return netclient->MergeSet(in_max_fd, out_rset, out_wset);
    }

    virtual int Poll(fd_set& in_rset, fd_set& in_wset) {
        return netclient->Poll(in_rset, in_wset);
    }
    
    virtual int ParseData();
    
    virtual int Shutdown();

    virtual int Reconnect();

	virtual void ConnectCB(int status);
protected:
    TcpClient *tcpcli;

    char host[MAXHOSTNAMELEN];
    int port;

	int last_mode;

	int poll_mode;

	int si_units, si_raw;

	time_t last_hed_time;

	time_t last_update;

	time_t last_tpv;
};

#endif

#endif

