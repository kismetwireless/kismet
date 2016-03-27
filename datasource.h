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

#ifndef __DATASOURCE_H__
#define __DATASOURCE_H__

#include "config.h"


// Kismet Data Source
//
// Data sources replace packetsources in the new Kismet code model.
// A data source is the kismet_server side of a capture engine:  It accepts
// data frames from a capture engine and will create kis_packet structures
// from them.
//
// The capture engine will, locally, be over IPC channels as defined in
// IpcRemoteV2.  Data may also come from TCP sockets, or in the future,
// other sources - anything which can plug into in a ringbufferhandler
//
// Data frames are defined in simple_cap_proto.h.  A frame consists of an
// overall type and multiple objects indexed by name.  Each object may
// contain additional data.
//
// By default, objects are packed using the msgpack library, as dictionaries
// of named values.  This abstracts problems with endian, complex types such
// as float and double, and changes in the protocol over time.

#endif

