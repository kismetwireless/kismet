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

#ifndef __DATASOURCE_PROBE_REASON_H__
#define __DATASOURCE_PROBE_REASON_H__

#include <cctype>
#include <string>

// Every driver probes every definition and many decline foreign ones with a
// reason, so a reason is only worth showing from the driver that owns the
// definition: its interface (before the first ':') starts with the driver's
// type, followed by the end or a non-alphanumeric character.
inline bool datasource_reason_is_own_definition(const std::string& definition,
        const std::string& source_type) {
    if (source_type.empty() || definition.empty())
        return false;

    const auto iface = definition.substr(0, definition.find(':'));

    if (iface.length() < source_type.length())
        return false;

    for (size_t i = 0; i < source_type.length(); i++) {
        if (std::tolower((unsigned char) iface[i]) !=
                std::tolower((unsigned char) source_type[i]))
            return false;
    }

    if (iface.length() == source_type.length())
        return true;

    return !std::isalnum((unsigned char) iface[source_type.length()]);
}

#endif
