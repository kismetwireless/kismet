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

#ifndef __KIS_PACKSOURCES_H__
#define __KIS_PACKSOURCES_H__

#include "config.h"

#include "packetsource.h"
#include "prism2source.h"
#include "pcapsource.h"
#include "wtapfilesource.h"
#include "wsp100source.h"
#include "vihasource.h"
#include "dronesource.h"
#include "packetsourcetracker.h"

// Null packet source for default config
class NullPacketSource : public KisPacketSource {
public:
    NullPacketSource(string in_name, string in_dev) : 
        KisPacketSource(in_name, in_dev) { }

    int OpenSource() {
        snprintf(errstr, 1024, "Please configure at least one packet source.  "
                 "Kismet will not function if no packet sources are defined in "
                 "kismet.conf or on the command line.  Please read the README "
                 "for more information about configuring Kismet.");
        return -1;
    }

    int CloseSource() {
        return 1;
    }

    int FetchDescriptor() {
        return -1;
    }

    int FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
        return -1;
    }

    int FetchChannel() {
        return -1;
    }
};

KisPacketSource *nullsource_registrant(string in_name, string in_device, 
                                       char *in_err);

int unmonitor_nullsource(const char *in_dev, int initch, 
                         char *in_err, void **in_if);

// Shortcut for registering uncompiled sources
#define REG_EMPTY_CARD(x, y) x->RegisterPacketsource(y, 0, "na", 0, \
                                                     NULL, NULL, NULL, NULL, 0)

// Register all our packet sources.  
//
// We register sources we know about but don't have support compiled in for
// so that the sourcetracker can complain intelligently to the user.
int RegisterKismetSources(Packetsourcetracker *sourcetracker);

#endif
