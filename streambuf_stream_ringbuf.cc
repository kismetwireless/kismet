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

#include "streambuf_stream_ringbuf.h"

Streambuf_Stream_Ringbuf::Streambuf_Stream_Ringbuf(GlobalRegistry *in_globalreg,
        shared_ptr<RingbufferHandler> in_handler,
        bool in_blocking) :
        globalreg(in_globalreg), handler(in_handler), 
        streambuf(in_handler, in_blocking) { }

Streambuf_Stream_Ringbuf::~Streambuf_Stream_Ringbuf() {
    handler->ProtocolError();
}

void Streambuf_Stream_Ringbuf::stop_stream(string in_reason __attribute__((unused))) {
    handler->ProtocolError();
}

ostream *Streambuf_Stream_Ringbuf::get_ostream() {
    return (ostream *) &streambuf;
}

