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

#ifdef HAVE_GPS

#include "clinetframework.h"
#include "tcpclient.h"
#include "kis_netframe.h"

// Options
#define GPSD_OPT_FORCEMODE    1

// Our command
const char gpsd_command[] = "PAVMH\n";

int GpsInjectEvent(Timetracker::timer_event *evt, void *parm, GlobalRegistry *globalreg);

enum GPS_fields {
    GPS_lat, GPS_lon, GPS_alt, GPS_spd, GPS_heading, GPS_fix
};
extern char *GPS_fields_text[];

typedef struct GPS_data {
    string lat, lon, alt, spd, heading, mode;
};

int Protocol_GPS(PROTO_PARMS);

class GPSDClient : public ClientFramework {
public:
    GPSDClient();
    GPSDClient(GlobalRegistry *in_globalreg);
    virtual ~GPSDClient();

    // Hooks so we can override straight to the TCP core
    virtual unsigned int MergeSet(fd_set in_rset, fd_set in_wset, 
                                  unsigned int in_max_fd,
                                  fd_set *out_rset, fd_set *out_wset) {
        return netclient->MergeSet(in_rset, in_wset, in_max_fd,
                                   out_rset, out_wset);
    }

    virtual int Poll(fd_set& in_rset, fd_set& in_wset) {
        return netclient->Poll(in_rset, in_wset);
    }
    
    virtual int ParseData();
    virtual int KillConnection();
    
    virtual int Shutdown();

    void SetOptions(uint32_t in_opt) {
        gps_options = in_opt;
    }

    // Fetch a location
    int FetchLoc(float *in_lat, float *in_lon, float *in_alt, float *in_spd, float *in_hed, int *mode);

    // Fetch mode
    int FetchMode() { return mode; }

    // Various GPS transformations
    static float CalcHeading(float in_lat, float in_lon, float in_lat2, float in_lon2);
    static double CalcRad(double lat);
    static double Rad2Deg(double x);
    static double Deg2Rad(double x);
    static double EarthDistance(double in_lat, double in_lon, double in_lat2, double in_lon2);

protected:
    TcpClient *tcpcli;

    uint32_t gps_options;

    char host[MAXHOSTNAMELEN];
    int port;
    int reconnect_attempt;
    time_t last_disconnect;

    float lat, lon, alt, spd, hed;
    int mode;

    int gpseventid;

    // Last location used for softheading calcs
    float last_lat, last_lon, last_hed;

    // Reconnect local trigger
    int Reconnect();
    int InjectCommand();
    
    friend int GpsInjectEvent(Timetracker::timer_event *evt, void *parm, 
                              GlobalRegistry *globalreg);
};

#endif

#endif

