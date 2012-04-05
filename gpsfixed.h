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

#ifndef __GPSFIXED_H__
#define __GPSFIXED_H__

#include "config.h"

#ifndef HAVE_LIBGPS

#include "clinetframework.h"
#include "tcpclient.h"
#include "kis_netframe.h"
#include "packetchain.h"
#include "gpscore.h"

class GPSFixed : public GPSCore {
public:
    GPSFixed();
    GPSFixed(GlobalRegistry *in_globalreg);
    virtual ~GPSFixed();

	string FetchType() {
		return "fixed";
	}

	string FetchDevice() {
		return "virtual";
	}

	virtual int Timer();

    // Hooks so we can override straight to the TCP core
    virtual int MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
		return in_max_fd;
    }

    virtual int Poll(fd_set& in_rset, fd_set& in_wset) {
		return 0;
    }
    
    virtual int ParseData();
    
    virtual int Shutdown();

    virtual int Reconnect();

	virtual void ConnectCB(int status);
};

#endif

#endif

