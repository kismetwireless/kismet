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

#include "config.h"

#include "kis_datasource.h"
#include "simple_datasource_proto.h"
#include "datasource_linux_bluetooth.h"

void KisDatasourceLinuxBluetooth::proto_dispatch_packet(string in_type, KVmap in_kvmap) {
    local_locker lock(&source_lock);

    KisDatasource::proto_dispatch_packet(in_type, in_kvmap);

    string ltype = StrLower(in_type);

    if (ltype == "linuxbtdevice") {
        fprintf(stderr, "debug - kismet got btdevice\n");
    }
}

