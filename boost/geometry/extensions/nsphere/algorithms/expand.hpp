// Boost.Geometry (aka GGL, Generic Geometry Library)

// Copyright (c) 2007-2012 Barend Gehrels, Amsterdam, the Netherlands.
// Copyright (c) 2008-2012 Bruno Lalande, Paris, France.
// Copyright (c) 2009-2012 Mateusz Loskot, London, UK.
// Copyright (c) 2013 Adam Wulkiewicz, Lodz, Poland.

// This file was modified by Oracle on 2017.
// Modifications copyright (c) 2017, Oracle and/or its affiliates.

// Contributed and/or modified by Adam Wulkiewicz, on behalf of Oracle

// Parts of Boost.Geometry are redesigned from Geodan's Geographic Library
// (geolib/GGL), copyright (c) 1995-2010 Geodan, Amsterdam, the Netherlands.

// Use, modification and distribution is subject to the Boost Software License,
// Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef BOOST_GEOMETRY_EXTENSIONS_NSPHERE_ALGORITHMS_EXPAND_HPP
#define BOOST_GEOMETRY_EXTENSIONS_NSPHERE_ALGORITHMS_EXPAND_HPP


#include <cstddef>
#include <functional>

#include <boost/numeric/conversion/cast.hpp>

#include <boost/geometry/algorithms/not_implemented.hpp>
#include <boost/geometry/core/coordinate_dimension.hpp>
#include <boost/geometry/geometries/concepts/check.hpp>

#include <boost/geometry/util/select_coordinate_type.hpp>


namespace boost { namespace geometry
{

#ifndef DOXYGEN_NO_DETAIL
namespace detail { namespace expand
{


template
<
    std::size_t Dimension, std::size_t DimensionCount
>
struct nsphere_loop
{
    template <typename Box, typename NSphere>
    static inline void apply(Box& box, NSphere const& source)
    {
        typedef typename select_coordinate_type<NSphere, Box>::type coordinate_type;

        std::less<coordinate_type> const less;
        std::greater<coordinate_type> const greater;

        coordinate_type const min_coord = get<Dimension>(source) - get_radius<0>(source);
        coordinate_type const max_coord = get<Dimension>(source) + get_radius<0>(source);

        if (less(min_coord, get<min_corner, Dimension>(box)))
        {
            set<min_corner, Dimension>(box, min_coord);
        }

        if (greater(max_coord, get<max_corner, Dimension>(box)))
        {
            set<max_corner, Dimension>(box, max_coord);
        }

        nsphere_loop
            <
                Dimension + 1, DimensionCount
            >::apply(box, source);
    }
};


template
<
    std::size_t DimensionCount
>
struct nsphere_loop
    <
        DimensionCount, DimensionCount
    >
{
    template <typename Box, typename NSphere>
    static inline void apply(Box&, NSphere const&) {}
};


}} // namespace detail::expand
#endif // DOXYGEN_NO_DETAIL

#ifndef DOXYGEN_NO_DISPATCH
namespace dispatch
{


// Box + Nsphere -> new box containing also nsphere
template
<
    typename BoxOut, typename NSphere
>
struct expand<BoxOut, NSphere, box_tag, nsphere_tag>
    : detail::expand::nsphere_loop
        <
            0, dimension<NSphere>::type::value
        >
{};


} // namespace dispatch
#endif // DOXYGEN_NO_DISPATCH


}} // namespace boost::geometry

#endif // BOOST_GEOMETRY_EXTENSIONS_NSPHERE_ALGORITHMS_EXPAND_HPP
