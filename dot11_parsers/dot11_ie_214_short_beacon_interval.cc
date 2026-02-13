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

#include "dot11_ie_214_short_beacon_interval.h"
#include "util.h"

void dot11_ie_214_short_beacon_interval::parse(const std::string_view *view) {
    membuf view_membuf(view->data(), view->data() + view->length());
    std::istream istream_view(&view_membuf);
    auto p_io = kaitai::kstream(&istream_view);

    m_interval = p_io.read_u2be();

    m_parsed = true;
}
