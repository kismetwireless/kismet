#include "../config.h"

#ifndef __NRF52840_H__
#define __NRF52840_H__

#define BAUDRATE B115200

#define _POSIX_SOURCE 1 /* POSIX compliant source */

#define FALSE 0
#define TRUE 1

#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)

#endif


