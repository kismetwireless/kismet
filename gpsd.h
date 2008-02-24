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

#ifndef __GPSD_H__
#define __GPSD_H__

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <math.h>
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

// gpsd return looks like
// SEND: PAVM
// RECV: GPSD,P=41.711378 -73.931428,A=42.500000,V=0.000000,M=1
// or
// RECV: GPSD,P=41.711548 -73.931020,A=61.800000,V=0.000000,M=3

// POSITION, ALT, VELOCITY, MODE

// Our command
// const char gpsd_command[] = "PAVMH\n";

// Query gpsd version
const char gpsd_init_command[] = "l\n";

// Optional GPSD commands (enable jitter correction, etc)
const char gpsd_opt_commands[] = "j=1\n";

// Watcher mode
const char gpsd_watch_command[] = "w=1\n";

// GPS poll command
const char gpsd_poll_command[] = "PAVM\n";

// Options
#define GPSD_OPT_FORCEMODE		1

// Max data size
#define GPSD_MAX_DATASIZE		2048

// gpsd GPS capture
class GPSD {
public:
    GPSD(char *in_host, int in_port);
    ~GPSD(void);

    char *FetchError();

    // Open gpsd on host, port
    int OpenGPSD();
    // Close it
    int CloseGPSD();

    // Set options
    void SetOptions(uint32_t in_opt) { options = in_opt; }

    // Get our file descriptor
    int FetchDescriptor() { return sock; }

    unsigned int MergeSet(fd_set *in_rset, fd_set *in_wset, unsigned int in_max);
    int Poll(fd_set *in_rset, fd_set *in_wset);

    // Fetch a location
    int FetchLoc(float *in_lat, float *in_lon, float *in_alt, 
				 float *in_spd, float *in_hed, int *mode);

    // Fetch mode
    int FetchMode() { return mode; }

	// Write poll request data
	void WritePoll();

    // Various GPS transformations
    static float CalcHeading(float in_lat, float in_lon, float in_lat2, float in_lon2);
    static double CalcRad(double lat);
    static double Rad2Deg(double x);
    static double Deg2Rad(double x);
    static double EarthDistance(double in_lat, double in_lon, 
								double in_lat2, double in_lon2);

protected:
    char errstr[1024];

	// Are we in polling or watcher mode?
	int poll_mode;

	int poll_timer;
	
	// 'O' response reports speed as m/s instead of knots?
	int si_units;

    int sock;

    float lat, lon, alt, spd, hed;
    int mode;

	int last_mode;

    // Last location used for softheading calcs
    float last_lat, last_lon, last_hed;
	time_t last_hed_time;

    char data[GPSD_MAX_DATASIZE + 1];
	int data_pos;

    char *host;
    int port;

    struct sockaddr_in localaddr, servaddr;
    struct hostent *h;

    uint32_t options;
};

#endif
 
