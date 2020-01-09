#include "../config.h"

#ifndef __TICC2531_H__
#define __TICC2531_H__

#define TICC2531_USB_VENDOR        0x0451 
#define TICC2531_USB_PRODUCT       0x16ae 

#define TICC2531_GET_IDENT 0xC0
#define TICC2531_SET_POWER 0xC5
#define TICC2531_GET_POWER 0xC6
#define TICC2531_SET_START 0xD0
#define TICC2531_SET_END   0xD1
#define TICC2531_SET_CHAN  0xD2 // 0x0d (idx 0) + data)0x00 (idx 1)
#define TICC2531_DIR_OUT   0x40
#define TICC2531_DIR_IN    0xC0
#define TICC2531_TIMEOUT   100 // 2500
#define TICC2531_DATA_TIMEOUT   200

#define TICC2531_POWER_RETRIES 10

#define TICC2531_DATA_EP 0x83

#define TICC2531 0x01

#endif


