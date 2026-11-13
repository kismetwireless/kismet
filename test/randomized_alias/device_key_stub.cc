/* The device_key constructors the linker tests need, without the tracked element
 * system around them */

#include "config.h"

#include "trackedelement.h"

device_key::device_key() {
    spkey = 0;
    dkey = 0;
    error = true;
}

device_key::device_key(const device_key& k) {
    spkey = k.spkey;
    dkey = k.dkey;
    error = k.error;
}

device_key::device_key(uint32_t in_pkey, uint64_t in_dkey) {
    spkey = in_pkey & 0xFFFFFFFF;
    dkey = in_dkey;
    error = false;
}
