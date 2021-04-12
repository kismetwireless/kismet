#include "../config.h"

#ifndef __TICC2540_H__
#define __TICC2540_H__

#define TICC2540_USB_VENDOR        0x0451 
#define TICC2540_USB_PRODUCT       0x16b3 

#define TICC2540_GET_IDENT 0xC0
#define TICC2540_SET_POWER 0xC5
#define TICC2540_GET_POWER 0xC6
#define TICC2540_SET_START 0xD0
#define TICC2540_SET_END   0xD1
#define TICC2540_SET_CHAN  0xD2 // 0x0d (idx 0) + data)0x00 (idx 1)
#define TICC2540_DIR_OUT   0x40
#define TICC2540_DIR_IN    0xC0
#define TICC2540_TIMEOUT   100 
#define TICC2540_DATA_TIMEOUT   200


#define TICC2540_POWER_RETRIES 10

#define TICC2540_DATA_EP 0x83

#define TICC2540 0x02

#endif


