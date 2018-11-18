// Boost.Geometry (aka GGL, Generic Geometry Library)

// Copyright (c) 2009-2012 Mateusz Loskot, London, UK.

// Use, modification and distribution is subject to the Boost Software License,
// Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef BOOST_GEOMETRY_MULTI_IO_WKB_DETAIL_PARSER_HPP
#define BOOST_GEOMETRY_MULTI_IO_WKB_DETAIL_PARSER_HPP

#include <cstddef>
#include <iterator>
#include <limits>

#include <boost/geometry/core/exception.hpp>

#include <boost/geometry/extensions/gis/io/wkb/detail/endian.hpp>
#include <boost/geometry/extensions/gis/io/wkb/detail/parser.hpp>
#include <boost/geometry/extensions/gis/io/wkb/detail/ogc.hpp>


#include <boost/geometry/multi/core/point_type.hpp>
#include <boost/geometry/multi/core/ring_type.hpp>
#include <boost/geometry/core/exterior_ring.hpp>

#include <boost/geometry/multi/core/interior_rings.hpp>

namespace boost { namespace geometry
{

#ifndef DOXYGEN_NO_DETAIL
namespace detail { namespace wkb
{

template <typename MultiPoint>
struct multipoint_parser
{
    template <typename Iterator>
    static bool parse(Iterator& it, Iterator end, MultiPoint& multipoint, byte_order_type::enum_t order)
    {
        if (!geometry_type_parser<MultiPoint>::parse(it, end, order))
        {
            return false;
        }
        
        boost::uint32_t num_points(0);
        if (!value_parser<boost::uint32_t>::parse(it, end, num_points, order))
        {
            return false;
        }
        
        // Check that the number of double values in the stream is equal
        // or greater than the number of expected values in the multipoint
        
        typedef typename std::iterator_traits<Iterator>::difference_type size_type;
        
        typedef typename point_type<MultiPoint>::type point_type;
        
        size_type const container_byte_size = dimension<point_type>::value * num_points * sizeof(double)
                                            + num_points * sizeof(boost::uint8_t)
                                            + num_points * sizeof(boost::uint32_t);
        
        size_type const stream_byte_size = std::distance(it,end);
        
        if(stream_byte_size < container_byte_size)
        {
            throw boost::geometry::read_wkb_exception();
        }
        
        point_type point_buffer;
        std::back_insert_iterator<MultiPoint> output(std::back_inserter(multipoint));
        
        typedef typename std::iterator_traits<Iterator>::difference_type size_type;
        if(num_points > (std::numeric_limits<boost::uint32_t>::max)() )
        {
            throw boost::geometry::read_wkb_exception();
        }
        
        size_type points_parsed = 0;
        while (points_parsed < num_points && it != end)
        {
            detail::wkb::byte_order_type::enum_t point_byte_order;
            if (!detail::wkb::byte_order_parser::parse(it, end, point_byte_order))
            {
                return false;
            }
            
            if (!geometry_type_parser<point_type>::parse(it, end, point_byte_order))
            {
                return false;
            }
            
            parsing_assigner<point_type, 0, dimension<point_type>::value>::run(it, end, point_buffer, point_byte_order);
            
            output = point_buffer;
            
            ++output;
            ++points_parsed;
        }
        return true;
    }
};

template <typename MultiLinestring>
struct multilinestring_parser
{
    template <typename Iterator>
    static bool parse(Iterator& it, Iterator end, MultiLinestring& multilinestring, byte_order_type::enum_t order)
    {
        typedef typename MultiLinestring::value_type linestring_type;
        typedef typename point_type<MultiLinestring>::type point_type;
        
        if (!geometry_type_parser<MultiLinestring>::parse(it, end, order))
        {
            return false;
        }
        
        boost::uint32_t num_linestrings(0);
        if (!value_parser<boost::uint32_t>::parse(it, end, num_linestrings, order))
        {
            return false;
        }
        
        std::back_insert_iterator<MultiLinestring> output(std::back_inserter(multilinestring));
        
        typedef typename std::iterator_traits<Iterator>::difference_type size_type;
        if(num_linestrings > (std::numeric_limits<boost::uint32_t>::max)() )
        {
            throw boost::geometry::read_wkb_exception();
        }
        
        size_type linestrings_parsed = 0;
        while (linestrings_parsed < num_linestrings && it != end)
        {
            linestring_type linestring_buffer;
            
            detail::wkb::byte_order_type::enum_t linestring_byte_order;
            if (!detail::wkb::byte_order_parser::parse(it, end, linestring_byte_order))
            {
                return false;
            }
            
            if (!geometry_type_parser<linestring_type>::parse(it, end, order))
            {
                return false;
            }
            
            if(!point_container_parser<linestring_type>::parse(it, end, linestring_buffer, linestring_byte_order))
            {
                return false;
            }
            
            output = linestring_buffer;
            
            ++output;
            ++linestrings_parsed;
        }
        return true;
    }
};

template <typename MultiPolygon>
struct multipolygon_parser
{
    template <typename Iterator>
    static bool parse(Iterator& it, Iterator end, MultiPolygon& multipolygon, byte_order_type::enum_t order)
    {
        typedef typename boost::range_value<MultiPolygon>::type polygon_type;
        
        if (!geometry_type_parser<MultiPolygon>::parse(it, end, order))
        {
            return false;
        }
        
        boost::uint32_t num_polygons(0);
        if (!value_parser<boost::uint32_t>::parse(it, end, num_polygons, order))
        {
            return false;
        }
        
        std::back_insert_iterator<MultiPolygon> output(std::back_inserter(multipolygon));
        
        std::size_t polygons_parsed = 0;
        while(polygons_parsed < num_polygons && it != end)
        {
            polygon_type polygon_buffer;
            
            detail::wkb::byte_order_type::enum_t polygon_byte_order;
            if (!detail::wkb::byte_order_parser::parse(it, end, polygon_byte_order))
            {
                return false;
            }
            
            if (!geometry_type_parser<polygon_type>::parse(it, end, order))
            {
                return false;
            }
            
            boost::uint32_t num_rings(0);
            if (!value_parser<boost::uint32_t>::parse(it, end, num_rings, polygon_byte_order))
            {
                return false;
            }
            
            std::size_t rings_parsed = 0;
            
            while (rings_parsed < num_rings && it != end)
            {
                typedef typename boost::geometry::ring_return_type<polygon_type>::type ring_type;

                if (0 == rings_parsed)
                {
                    ring_type ring0 = exterior_ring(polygon_buffer);
                    
                    if (!point_container_parser<ring_type>::parse(it, end, ring0, polygon_byte_order))
                    {
                        return false;
                    }
                }
                else
                {
                    boost::geometry::range::resize(interior_rings(polygon_buffer), rings_parsed);
                    ring_type ringN = boost::geometry::range::back(interior_rings(polygon_buffer));
                    
                    if (!point_container_parser<ring_type>::parse(it, end, ringN, polygon_byte_order))
                    {
                        return false;
                    }
                }
                ++rings_parsed;
            }
            
            output = polygon_buffer;
            ++output;
        }
        
        return true;
    }
};

}} // namespace detail::wkb
#endif // DOXYGEN_NO_IMPL

}} // namespace boost::geometry


#endif // BOOST_GEOMETRY_MULTI_IO_WKB_DETAIL_PARSER_HPP
