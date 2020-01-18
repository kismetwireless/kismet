#include "../config.h"

#ifndef __NXPKW41Z_H__
#define __NXPKW41Z_H__

#ifdef __APPLE__
#ifndef B115200
#define B115200 115200
#endif
#endif

#define BAUDRATE B115200

#define _POSIX_SOURCE 1 /* POSIX compliant source */

#ifndef bzero
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)
#endif

#endif


