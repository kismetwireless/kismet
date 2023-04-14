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

#ifndef __FMT_ASIO_H__
#define __FMT_ASIO_H__

#include "boost/asio/ip/basic_endpoint.hpp"
#include "config.h"
#include "fmt/ostream.h"

#define ASIO_HAS_STD_CHRONO
#define ASIO_HAS_MOVE

#include "boost/asio.hpp"
#include "fmt.h"

template <>struct fmt::formatter<boost::asio::ip::address> : fmt::ostream_formatter {};
template <>struct fmt::formatter<boost::asio::ip::tcp> : fmt::ostream_formatter {};
template <>struct fmt::formatter<boost::asio::ip::basic_endpoint<boost::asio::ip::tcp>> : fmt::ostream_formatter{};

#endif
