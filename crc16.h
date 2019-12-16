/* Tony Cheneau <tony.cheneau@nist.gov>

 This file defines CRC computation for the FCS field in the IEEE 802.15.4
 The algorithm is defined in the IEEE 802.15.4-2006 standard, Section 7.2.1.9

 This file uses codes from Ross Williams and J. Zibicak that are licenced
 through public domain.
*/

#ifndef __802154_CRC
#define __802154_CRC

#include <stdint.h>

/* compute a CRC-16.
 * crc is the initial CRC value (0 according to the IEEE 802.15.4 standard)
 * data is the data the CRC is computed over
 * len is the length of the data */
uint16_t crc16_block(uint16_t crc, uint8_t *data, int len);

#endif /* __802154_CRC */
