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

#ifndef __STREAMBUF_STREAM_BUFFER__
#define __STREAMBUF_STREAM_BUFFER__

/* A streambuf/ostream compatible object, with optional blocking, to a buf_handler
 * backed buffer system.
 *
 * Useful for streaming serialized data out a memory-managed HTTP connection.
 */

#include "config.h"
#include "buffer_handler.h"
#include "globalregistry.h"
#include "streamtracker.h"

class Streambuf_Stream_Buffer : public streaming_agent {
public:
    Streambuf_Stream_Buffer(GlobalRegistry *in_globalreg,
            std::shared_ptr<BufferHandlerGeneric> in_handler,
            bool in_blocking);

    virtual ~Streambuf_Stream_Buffer();

    virtual void stop_stream(std::string in_reason);

    virtual std::ostream *get_ostream();

protected:
    GlobalRegistry *globalreg;

    std::shared_ptr<BufferHandlerGeneric> handler;

    BufferHandlerOStreambuf streambuf;
};

#endif

