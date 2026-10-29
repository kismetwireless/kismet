// The Kismet server's clock.  Graphs of per-second history need to know what
// "now" is on the server, which may not match this browser's clock (or, when
// replaying a capture file, the real date at all).
//
//   clock.now()   // server time in seconds

import * as eventbus from './eventbus.js';

let offset = 0;     // server time - local time, in seconds
let known = false;

export function now() {
    return Date.now() / 1000 + offset;
}

// Whether we've heard from the server yet
export function isKnown() {
    return known;
}

eventbus.subscribe('TIMESTAMP', ['kismet.system.timestamp.sec'], (e) => {
    const sec = e['kismet.system.timestamp.sec'];
    if (sec) {
        offset = sec - Date.now() / 1000;
        known = true;
    }
});
