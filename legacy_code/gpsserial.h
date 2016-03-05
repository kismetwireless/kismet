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

#ifndef __GPSSERIAL_H__
#define __GPSSERIAL_H__

#include "config.h"

#include "clinetframework.h"
#include "serialclient.h"
#include "kis_netframe.h"
#include "packetchain.h"
#include "gpscore.h"

class GPSSerial : public GPSCore {
public:
    GPSSerial();
    GPSSerial(GlobalRegistry *in_globalreg);
    virtual ~GPSSerial();

	string FetchType() {
		return "serial";
	}

	string FetchDevice() {
		return device;
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
protected:
    SerialClient *sercli;

	int gpseventid;

	char device[128];

	int last_mode;

	time_t last_hed_time;
};

#endif

