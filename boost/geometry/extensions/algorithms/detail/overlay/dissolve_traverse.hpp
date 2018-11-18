// Boost.Geometry (aka GGL, Generic Geometry Library)

// Copyright (c) 2018 Barend Gehrels, Amsterdam, the Netherlands.

// Use, modification and distribution is subject to the Boost Software License,
// Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef BOOST_GEOMETRY_EXTENSIONS_ALGORITHMS_DISSOLVE_TRAVERSE_HPP
#define BOOST_GEOMETRY_EXTENSIONS_ALGORITHMS_DISSOLVE_TRAVERSE_HPP

#include <cstddef>

#include <boost/geometry/algorithms/detail/overlay/backtrack_check_si.hpp>
#include <boost/geometry/algorithms/detail/overlay/traversal_ring_creator.hpp>


namespace boost { namespace geometry
{

#ifndef DOXYGEN_NO_DETAIL
namespace detail { namespace dissolve
{


/*!
    \brief Traverses through intersection points / geometries. This version
        for dissolves calls traversal_ring_creator in two phases
    \ingroup dissolve
 */
template <bool Reverse, typename Backtrack>
class traverse
{

public :
    template
    <
        typename Geometry,
        typename IntersectionStrategy,
        typename RobustPolicy,
        typename Turns,
        typename Rings,
        typename TurnInfoMap,
        typename Clusters,
        typename Visitor
    >
    static inline void apply(Geometry const& geometry,
                IntersectionStrategy const& intersection_strategy,
                RobustPolicy const& robust_policy,
                Turns& turns, Rings& rings,
                TurnInfoMap& turn_info_map,
                Clusters& clusters,
                Visitor& visitor)
    {
        detail::overlay::traversal_ring_creator
            <
                Reverse, Reverse, overlay_dissolve,
                Geometry, Geometry,
                Turns, TurnInfoMap, Clusters,
                IntersectionStrategy,
                RobustPolicy, Visitor,
                Backtrack
            > trav(geometry, geometry, turns, turn_info_map, clusters,
                   intersection_strategy, robust_policy, visitor);

        std::size_t finalized_ring_size = boost::size(rings);

        typename Backtrack::state_type state;

        for (std::size_t phase = 0; phase < 2; phase++)
        {
            trav.iterate_with_preference(phase, rings, finalized_ring_size, state);
        }
    }
};

}} // namespace detail::dissolve
#endif // DOXYGEN_NO_DETAIL

}} // namespace boost::geometry

#endif // BOOST_GEOMETRY_EXTENSIONS_ALGORITHMS_DISSOLVE_TRAVERSE_HPP
