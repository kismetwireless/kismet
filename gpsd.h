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

#ifdef HAVE_GPS

// gpsd return looks like
// SEND: PAVM
// RECV: GPSD,P=41.711378 -73.931428,A=42.500000,V=0.000000,M=1
// or
// RECV: GPSD,P=41.711548 -73.931020,A=61.800000,V=0.000000,M=3

// POSITION, ALT, VELOCITY, MODE

// Our command
const char gpsd_command[] = "PAVM";

// gpsd GPS capture
class GPSD {
public:
    GPSD(void);
    ~GPSD(void);

    char *FetchError();

    // Open gpsd on host, port
    int OpenGPSD(char *in_host, int in_port);
    // Close it
    int CloseGPSD();

    // Get our file descriptor
    int FetchDescriptor() { return sock; }

    // Scan the GPSD so we can return instantly when someone asks for it
    int Scan();

    // Fetch a location
    int FetchLoc(float *in_lat, float *in_lon, float *in_alt, float *in_spd, int *mode);

    // Fetch mode
    int FetchMode() { return mode; }

protected:
    char errstr[1024];

    int sock;

    float lat, lon, alt, spd;
    int mode;

    char data[1024];

    struct sockaddr_in localaddr, servaddr;
    struct hostent *h;
  
};

#else

class GPSD {
public:
    GPSD(void) { };
    ~GPSD(void) { };

    char *FetchError() { return NULL; };

    // Open gpsd on host, port
    int OpenGPSD(char *in_host, int in_port) { return -1; }
    // Close it
    int CloseGPSD() { return 0; }

    // Scan the GPSD so we can return instantly when someone asks for it
    int Scan() { return -1; }

    // Fetch a location
    int FetchLoc(float *in_lat, float *in_lon, float *in_alt, float *in_spd, int *mode) {
        return -1;
    }

    // Fetch mode
    int FetchMode() { return 0; }
  
};

#endif

#endif
