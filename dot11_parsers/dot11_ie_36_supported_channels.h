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

#ifndef __DOT11_IE_36_SUPPORTED_CHANNELS_H__
#define __DOT11_IE_36_SUPPORTED_CHANNELS_H__

/* dot11 ie 36 
 *
 * Client supported channels
 *
 */

#include <string>
#include <memory>
#include <vector>
#include <kaitai/kaitaistream.h>
#include "multi_constexpr.h"

class dot11_ie_36_supported_channels {
public:
    dot11_ie_36_supported_channels() { }
    ~dot11_ie_36_supported_channels() { }

    void parse(std::shared_ptr<kaitai::kstream> p_io);

    std::vector<unsigned int> supported_channels() const {
        return m_supported_channels;
    }

    void reset() {
        m_supported_channels.clear();
    }

protected:
    std::vector<unsigned int> m_supported_channels;
};


#endif

