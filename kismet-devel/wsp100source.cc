/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
    WSP100 support added by Chris Waters.  chris.waters@networkchemistry.com
    
    This files contains support for the Network Chemistry WSP100 under cygwin.
    The WSP100 can be used by kismet like any other network interface, just 
    specify the MAC address of the sensor you wish to use when asked for the 
    capture interface.

    To create a cygwin import library for the SensorManager interface DLL (sm_if.dll)
    copy and paste the following commands to the shell:

echo EXPORTS > sm_if.def
echo "\tStartSensor" >> sm_if.def
echo "\tStopSensor" >> sm_if.def
echo "\tGetPacket" >> sm_if.def
dlltool --def sm_if.def --dllname sm_if.dll --output-lib sm_if.a

    For some reason the treatment of underscores is not consistent with Borland
    B++ Builder so the sm_if.dll functions used in this file are prefixed with
    underscores.
*/

#include "config.h"

#include "wsp100source.h"

#ifdef HAVE_WSP100

#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
extern "C" {
#include "sm_if.h"
};

int Wsp100Source::OpenSource(const char *dev, card_type ctype) {
    snprintf(type, 64, "WSP100 Remote Sensor");

    paused = 0;

    /* Attempt to start the named sensor. */
    if ( _StartSensor((char*)dev) != 0 ) {
        snprintf(errstr, 1024, "Unable to find WSP100: %s.", dev);
        return(-1);
    }

    snprintf(errstr, 1024, "WSP100 connection opened.");
    return(1);
}

int Wsp100Source::CloseSource() {
    /* Unconditionally stop the sensor and assume that there were no errors. */
    _StopSensor();

    return 1;
}

int Wsp100Source::FetchPacket(pkthdr *in_header, u_char *in_data) {
    int Length = 3000;
    unsigned char Buffer[3000];
    int Offset = 35; // Size of the TZSP header. TODO: the TZSP header is variable
                     // length so this should be computed correctly.

    _GetPacket(&Length, Buffer);
    if ( Length > 0 ) {
        gettimeofday(&in_header->ts, NULL);

        in_header->caplen = Length - Offset;

        if (Length - Offset > MAX_PACKET_LEN)
            in_header->len = MAX_PACKET_LEN;
        else
            in_header->len = Length - Offset;

        // TODO: copy the signal strength out of the TZSP header.
        in_header->quality = 0;
        in_header->signal = 0;
        in_header->noise = 0;

        memcpy(in_data, &Buffer[Offset], in_header->len);
    }
    return(Length);
}

#endif
