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

#include "streambuf_stream_buffer.h"

streambuf_stream_buffer::streambuf_stream_buffer(global_registry *in_globalreg,
        std::shared_ptr<buffer_handler_generic> in_handler,
        bool in_blocking) :
        globalreg(in_globalreg), handler(in_handler), 
        streambuf(in_handler, in_blocking) { }

streambuf_stream_buffer::~streambuf_stream_buffer() {
    handler->protocol_error();
}

void streambuf_stream_buffer::stop_stream(std::string in_reason __attribute__((unused))) {
    handler->protocol_error();
}

std::ostream *streambuf_stream_buffer::get_ostream() {
    return (std::ostream *) &streambuf;
}

