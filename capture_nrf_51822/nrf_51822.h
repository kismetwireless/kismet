#include "../config.h"

#ifndef __NRF51822_H__
#define __NRF51822_H__

#ifdef __APPLE__
#define B460800 460800
#endif

#define D_BAUDRATE B460800

#define _POSIX_SOURCE 1 /* POSIX compliant source */

#define FALSE 0
#define TRUE 1

#ifndef bzero
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)
#endif

#endif


