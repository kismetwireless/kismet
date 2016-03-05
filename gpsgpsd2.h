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

#ifndef __GPSGPSD_V2_H__
#define __GPSGPSD_V2_H__

#include "config.h"

#include "kis_gps.h"
#include "timetracker.h"
#include "ringbuf_handler.h"
#include "globalregistry.h"
#include "tcpclient2.h"

// New GPSD interface
//
// This code uses the new ringbuffer handler interface for communicating with a 
// gpsd host

class GPSGpsdV2 : public Kis_Gps, public RingbufferInterface {
public:
    GPSGpsdV2(GlobalRegistry *in_globalreg);
    virtual ~GPSGpsdV2();

    // RingbufferInterface API
    virtual void BufferAvailable(size_t in_amt);

    // Kis_GPS API
    virtual Kis_Gps *BuildGps(string in_opts);

    virtual int OpenGps(string in_opts);

    virtual string FetchGpsDescription();

    virtual bool FetchGpsLocationValid();

    virtual bool FetchGpsConnected();

protected:
    GlobalRegistry *globalreg;

    TcpClientV2 *tcpclient;
    RingbufferHandler *tcphandler;

    // Device
    string host;
    unsigned int port;

    // Last time we calculated the heading, don't do it more than once every 
    // few seconds or we get nasty noise
    time_t last_heading_time;

    // Decaying reconnection algorithm
    int reconnect_tid;
    int num_reconnects;
    static int time_event_reconnect(TIMEEVENT_PARMS);

    // Poll mode (do we know we're JSON, etc
    int poll_mode;
    // Units - different gpsd variants return it different ways
    int si_units;
    // Do we run in raw mode?
    int si_raw;

};

#endif

