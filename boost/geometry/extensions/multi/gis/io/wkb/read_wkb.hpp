// Boost.Geometry

// Copyright (c) 2015 Mats Taraldsvik

// Use, modification and distribution is subject to the Boost Software License,
// Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef BOOST_GEOMETRY_MULTI_IO_WKB_READ_WKB_HPP
#define BOOST_GEOMETRY_MULTI_IO_WKB_READ_WKB_HPP

#include <iterator>

#include <boost/geometry/extensions/multi/gis/io/wkb/detail/parser.hpp>
#include <boost/geometry/extensions/gis/io/wkb/read_wkb.hpp>

namespace boost { namespace geometry
{

#ifndef DOXYGEN_NO_DISPATCH
namespace dispatch
{

template <typename Geometry>
struct read_wkb<multi_point_tag, Geometry>
{
    template <typename Iterator>
    static inline bool parse(Iterator& it, Iterator end, Geometry& geometry,
        detail::wkb::byte_order_type::enum_t order)
    {
        return detail::wkb::multipoint_parser<Geometry>::parse(it, end, geometry, order);
    }
};

template <typename Geometry>
struct read_wkb<multi_linestring_tag, Geometry>
{
    template <typename Iterator>
    static inline bool parse(Iterator& it, Iterator end, Geometry& geometry,
        detail::wkb::byte_order_type::enum_t order)
    {
        return detail::wkb::multilinestring_parser<Geometry>::parse(it, end, geometry, order);
    }
};

template <typename Geometry>
struct read_wkb<multi_polygon_tag, Geometry>
{
    template <typename Iterator>
    static inline bool parse(Iterator& it, Iterator end, Geometry& geometry,
        detail::wkb::byte_order_type::enum_t order)
    {
        return detail::wkb::multipolygon_parser<Geometry>::parse(it, end, geometry, order);
    }
};

} // namespace dispatch
#endif // DOXYGEN_NO_DISPATCH

}} // namespace boost::geometry

#endif // BOOST_GEOMETRY_MULTI_IO_WKB_READ_WKB_HPP
