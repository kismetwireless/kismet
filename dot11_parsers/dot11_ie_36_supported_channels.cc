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

#include "dot11_ie_36_supported_channels.h"
#include "fmt.h"

void dot11_ie_36_supported_channels::parse(std::shared_ptr<kaitai::kstream> p_io) {
    while (!p_io->is_eof()) {
        unsigned int start, count;

        start = p_io->read_u1();
        count = p_io->read_u1();

        if (start + count > 0xFF) 
            throw std::runtime_error(fmt::format("Invalid IEEE 802.11 IE 36; Start channel {} + "
                        "Total channels {} > 255", start, count));

        for (unsigned int i = 0; i < count; i++) {
            m_supported_channels.push_back(start + count);
        }
    }
}

