#include "../config.h"

#ifndef __NRF51822_H__
#define __NRF51822_H__

#define BAUDRATE B460800

#define _POSIX_SOURCE 1 /* POSIX compliant source */

#define FALSE 0
#define TRUE 1

#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)

#endif


