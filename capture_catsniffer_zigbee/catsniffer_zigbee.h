#include "../config.h"

#ifndef __CATSNIFFERZIGBEE_H__
#define __CATSNIFFERZIGBEE_H__

#ifndef B9600
#define B9600 9600
#endif
#ifndef B19200
#define B19200 19200
#endif
#ifndef B38400
#define B38400 38400
#endif
#ifndef B57600
#define B57600 57600
#endif
#ifndef B115200
#define B115200 115200
#endif
#ifndef B230400
#define B230400 230400
#endif
#ifndef B460800
#define B460800 460800
#endif
#ifndef B500000
#define B500000 500000
#endif
#ifndef B576000
#define B576000 576000
#endif
#ifndef B921600
#define B921600 921600
#endif
#ifndef B1000000
#define B1000000 1000000
#endif
#ifndef B1152000
#define B1152000 1152000
#endif
#ifndef B1500000
#define B1500000 1500000
#endif
#ifndef B2000000
#define B2000000 2000000
#endif
#ifndef B2500000
#define B2500000 2500000
#endif
#ifndef B3000000
#define B3000000 3000000
#endif
#ifndef B3500000
#define B3500000 3500000
#endif
#ifndef B4000000
#define B4000000 4000000
#endif

// SLIP CHARS
#define SLIP_START 0xAB
#define SLIP_END   0xBC

// PACKET ID
#define EVENT_PACKET_ADVERTISING 0x02
#define EVENT_PACKET_DATA        0x06

#define D_BAUDRATE B1152000

#define _POSIX_SOURCE 1 /* POSIX compliant source */

#define FALSE 0
#define TRUE 1

#ifndef bzero
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)
#endif

#endif


