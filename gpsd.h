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
const char gpsd_command[] = "PAVMH\n";

// Options
#define GPSD_OPT_FORCEMODE    1

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

    // Scan the GPSD so we can return instantly when someone asks for it
    int Scan();

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
    char errstr[1024];

    int sock;

    float lat, lon, alt, spd, hed;
    int mode;

    // Last location used for softheading calcs
    float last_lat, last_lon, last_hed;

    char data[1024];

    char *host;
    int port;

    struct sockaddr_in localaddr, servaddr;
    struct hostent *h;

    uint32_t options;
  
};

#endif
