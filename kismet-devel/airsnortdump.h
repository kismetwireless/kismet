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


// Dump a file in a format airsnort likes

#ifndef __AIRSNORTDUMP_H__
#define __AIRSNORTDUMP_H__

#include "config.h"

#include <stdio.h>
#include <string>
#include <map>

#include "dumpfile.h"
#include "wtapdump.h"
#include "wtaplocaldump.h"

class AirsnortDumpFile : public virtual DumpFile {
public:
    int OpenDump(const char *file);

    int CloseDump();

    int DumpPacket(const packet_info *in_info, const kis_packet *packet);

protected:

    DumpFile *dumper;

    map<mac_addr, int> bssid_dumped_map;

};

#endif
