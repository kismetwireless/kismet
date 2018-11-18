// Boost.Geometry
//
// Copyright (c) 2015 Mats Taraldsvik.
//
// Use, modification and distribution is subject to the Boost Software License,
// Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef BOOST_GEOMETRY_MULTI_IO_WKB_DETAIL_WRITER_HPP
#define BOOST_GEOMETRY_MULTI_IO_WKB_DETAIL_WRITER_HPP

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <limits>

#include <boost/concept_check.hpp>
#include <boost/cstdint.hpp>
#include <boost/range.hpp>
#include <boost/static_assert.hpp>
#include <boost/type_traits/is_integral.hpp>
#include <boost/type_traits/is_same.hpp>

#include <boost/geometry/extensions/gis/io/wkb/detail/writer.hpp>

#include <boost/geometry/core/access.hpp>
#include <boost/geometry/core/coordinate_dimension.hpp>
#include <boost/geometry/core/coordinate_type.hpp>
#include <boost/geometry/core/exterior_ring.hpp>
#include <boost/geometry/core/interior_rings.hpp>
#include <boost/geometry/extensions/gis/io/wkb/detail/endian.hpp>
#include <boost/geometry/extensions/gis/io/wkb/detail/ogc.hpp>

#include <iostream>

namespace boost { namespace geometry
{

#ifndef DOXYGEN_NO_DETAIL
namespace detail { namespace wkb
{
    template <typename MultiPoint>
    struct multipoint_writer
    {
        template <typename OutputIterator>
        static bool write(MultiPoint const& multipoint,
                          OutputIterator& iter,
                          byte_order_type::enum_t byte_order)
        {
            // write endian type
            value_writer<uint8_t>::write(byte_order, iter, byte_order);

            // write geometry type
            uint32_t type = geometry_type<MultiPoint>::get();
            value_writer<uint32_t>::write(type, iter, byte_order);

            // write num points
            uint32_t num_points = boost::size(multipoint);
            value_writer<uint32_t>::write(num_points, iter, byte_order);
            
            typedef typename point_type<MultiPoint>::type point_type;
            
            for(typename boost::range_iterator<MultiPoint const>::type
                    point_iter = boost::begin(multipoint);
                point_iter != boost::end(multipoint);
                ++point_iter)
            {
                detail::wkb::point_writer<point_type>::write(*point_iter, iter, byte_order);
            }

            return true;
        }
    };

    template <typename MultiLinestring>
    struct multilinestring_writer
    {
        template <typename OutputIterator>
        static bool write(MultiLinestring const& multilinestring,
                          OutputIterator& iter,
                          byte_order_type::enum_t byte_order)
        {
            // write endian type
            value_writer<uint8_t>::write(byte_order, iter, byte_order);

            // write geometry type
            uint32_t type = geometry_type<MultiLinestring>::get();
            value_writer<uint32_t>::write(type, iter, byte_order);

            // write num linestrings
            uint32_t num_linestrings = boost::size(multilinestring);
            value_writer<uint32_t>::write(num_linestrings, iter, byte_order);
            
            typedef typename boost::range_value<MultiLinestring>::type linestring_type;
            
            for(typename boost::range_iterator<MultiLinestring const>::type
                    linestring_iter = boost::begin(multilinestring);
                linestring_iter != boost::end(multilinestring);
                ++linestring_iter)
            {
                detail::wkb::linestring_writer<linestring_type>::write(*linestring_iter, iter, byte_order);
            }

            return true;
        }
    };

    template <typename MultiPolygon>
    struct multipolygon_writer
    {
        template <typename OutputIterator>
        static bool write(MultiPolygon const& multipolygon,
                          OutputIterator& iter,
                          byte_order_type::enum_t byte_order)
        {
            // write endian type
            value_writer<uint8_t>::write(byte_order, iter, byte_order);

            // write geometry type
            uint32_t type = geometry_type<MultiPolygon>::get();
            value_writer<uint32_t>::write(type, iter, byte_order);

            // write num polygons
            uint32_t num_polygons = boost::size(multipolygon);
            value_writer<uint32_t>::write(num_polygons, iter, byte_order);
            
            typedef typename boost::range_value<MultiPolygon>::type polygon_type;
            
            for(typename boost::range_iterator<MultiPolygon const>::type
                    polygon_iter = boost::begin(multipolygon);
                polygon_iter != boost::end(multipolygon);
                ++polygon_iter)
            {
                detail::wkb::polygon_writer<polygon_type>::write(*polygon_iter, iter, byte_order);
            }

            return true;
        }
    };

}} // namespace detail::wkb
#endif // DOXYGEN_NO_IMPL

}} // namespace boost::geometry
#endif // BOOST_GEOMETRY_MULTI_IO_WKB_DETAIL_WRITER_HPP
