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

#ifndef __WTAPDUMP_H__
#define __WTAPDUMP_H__

#include "config.h"

#include <stdio.h>

#include "packet.h"
#include "dumpfile.h"

#if (defined(HAVE_LIBWIRETAP) && !defined(USE_LOCAL_DUMP))

extern "C" {
#include "wtap.h"
}

class WtapDumpFile : public virtual DumpFile {
public:
    int OpenDump(const char *file);

    int CloseDump();

    int DumpPacket(const packet_info *in_info, const pkthdr *in_header, const u_char *in_data);

protected:
    int Common2Wtap(const pkthdr *in_header, const u_char *in_data);

    /*
    char errstr[1024];
    char type[64];
    */

    wtap_pkthdr packet_header;
    u_char packet_data[MAX_PACKET_LEN];

    wtap_dumper *dump_file;
    int wtap_error;

};

#endif

#endif
