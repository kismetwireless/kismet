// Boost.Geometry (aka GGL, Generic Geometry Library)

// Copyright (c) 2007-2012 Barend Gehrels, Amsterdam, the Netherlands.

// This file was modified by Oracle on 2017.
// Modifications copyright (c) 2017, Oracle and/or its affiliates.
// Contributed and/or modified by Adam Wulkiewicz, on behalf of Oracle

// Use, modification and distribution is subject to the Boost Software License,
// Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#ifndef BOOST_GEOMETRY_EXTENSIONS_ALGORITHMS_DISSOLVE_HPP
#define BOOST_GEOMETRY_EXTENSIONS_ALGORITHMS_DISSOLVE_HPP


#include <map>
#include <deque>

#include <boost/range.hpp>

#include <boost/geometry/algorithms/detail/overlay/get_turns.hpp>
#include <boost/geometry/algorithms/detail/overlay/self_turn_points.hpp>
#include <boost/geometry/algorithms/detail/overlay/overlay.hpp>

#include <boost/geometry/algorithms/detail/overlay/turn_info.hpp>
#include <boost/geometry/algorithms/detail/overlay/enrichment_info.hpp>
#include <boost/geometry/algorithms/detail/overlay/traversal_info.hpp>

#include <boost/geometry/algorithms/detail/overlay/enrich_intersection_points.hpp>
#include <boost/geometry/algorithms/detail/overlay/traverse.hpp>

#include <boost/geometry/algorithms/detail/overlay/add_rings.hpp>
#include <boost/geometry/algorithms/detail/overlay/assign_parents.hpp>
#include <boost/geometry/algorithms/detail/overlay/ring_properties.hpp>
#include <boost/geometry/algorithms/detail/overlay/select_rings.hpp>

#include <boost/geometry/algorithms/convert.hpp>
#include <boost/geometry/algorithms/correct.hpp>
#include <boost/geometry/algorithms/sym_difference.hpp>

#include <boost/geometry/geometries/concepts/check.hpp>

#include <boost/geometry/multi/geometries/multi_polygon.hpp>

#include <boost/geometry/extensions/algorithms/detail/overlay/dissolver.hpp>
#include <boost/geometry/extensions/algorithms/detail/overlay/dissolve_traverse.hpp>

namespace boost { namespace geometry
{


#ifndef DOXYGEN_NO_DETAIL
namespace detail { namespace dissolve
{

struct no_interrupt_policy
{
    static bool const enabled = false;
    static bool const has_intersections = false;


    template <typename Range>
    static inline bool apply(Range const&)
    {
        return false;
    }
};


template<typename Geometry>
class backtrack_for_dissolve
{
public :
    typedef detail::overlay::backtrack_state state_type;

    template
        <
            typename Operation,
            typename Rings,
            typename Turns,
            typename IntersectionStrategy,
            typename RobustPolicy,
            typename Visitor
        >
    static inline void apply(std::size_t size_at_start,
                Rings& rings,
                typename boost::range_value<Rings>::type& ring,
                Turns& turns,
                typename boost::range_value<Turns>::type const& /*turn*/,
                Operation& operation,
                detail::overlay::traverse_error_type,
                Geometry const& ,
                Geometry const& ,
                IntersectionStrategy const& ,
                RobustPolicy const& ,
                state_type& state,
                Visitor const& /*visitor*/
                )
    {
        state.m_good = false;

        // Make bad output clean
        rings.resize(size_at_start);
        ring.clear();

        // Reject this as a starting point
        operation.visited.set_rejected();

        // And clear all visit info
        clear_visit_info(turns);
    }
};

template <typename Ring, typename GeometryOut, bool Reverse>
struct dissolve_ring
{
    template <typename Turns>
    static void adapt_turns(Turns& turns)
    {
        typedef typename boost::range_value<Turns>::type turn_type;
        typedef typename turn_type::turn_operation_type turn_operation_type;

        for (typename Turns::iterator it = turns.begin();
             it != turns.end(); ++it)
        {
            turn_type& turn = *it;
            for (int i = 0; i < 2; i++)
            {
                turn_operation_type& op = turn.operations[i];

                if (op.operation != detail::overlay::operation_union
                    && op.operation != detail::overlay::operation_continue)
                {
                    // Only prefer union and continue turns
                    op.enriched.prefer_start = false;
                }

                if (op.operation == detail::overlay::operation_intersection)
                {
                    // Make all ii->uu, iu->uu, etc, basically handle most
                    // as if it is union
                    op.operation = detail::overlay::operation_union;
                }
            }
        }
    }

    template
    <
        typename RescalePolicy, typename OutputIterator,
        typename Strategy, typename Visitor
    >
    static inline void apply_one(Ring const& input_ring,
                RescalePolicy const& rescale_policy,
                OutputIterator out,
                Strategy const& strategy,
                Visitor& visitor)
    {
        typedef typename point_type<Ring>::type point_type;

        // Get the self-intersection points, including turns
        typedef detail::overlay::traversal_turn_info
            <
                point_type,
                typename segment_ratio_type<point_type, RescalePolicy>::type
            > turn_info;

        std::deque<turn_info> turns;
        detail::dissolve::no_interrupt_policy policy;
        detail::self_get_turn_points::self_turns
            <
                Reverse,
                detail::overlay::assign_null_policy
            >(input_ring, strategy, rescale_policy, turns, policy, 0, false);

        adapt_turns(turns);

        visitor.visit_turns(1, turns);

        if (boost::size(turns) == 0)
        {
            // No self-turns, then add original ring,
            // possibly reversing the order
            GeometryOut g;
            geometry::convert(input_ring, g);
            geometry::correct(g);
            *out++ = g;
        }

        typedef std::deque<Ring> ring_container_type;
        ring_container_type rings;

        typedef std::map
            <
                signed_size_type,
                detail::overlay::cluster_info
            > cluster_type;

        cluster_type clusters;

        // Enrich/traverse the polygons
        typename Strategy::side_strategy_type const
            side_strategy = strategy.get_side_strategy();

        enrich_intersection_points<Reverse, Reverse, overlay_dissolve>(turns,
                    clusters, input_ring, input_ring, rescale_policy,
                    side_strategy);

        visitor.visit_turns(2, turns);

        visitor.visit_clusters(clusters, turns);

        std::map<ring_identifier, overlay::ring_turn_info> turn_info_per_ring;

        detail::dissolve::traverse<Reverse, backtrack_for_dissolve<Ring> >
                ::apply(input_ring, strategy, rescale_policy,
                     turns, rings, turn_info_per_ring, clusters, visitor);

        visitor.visit_turns(3, turns);
        visitor.visit_generated_rings(rings);

        detail::overlay::get_ring_turn_info<overlay_dissolve>(turn_info_per_ring, turns, clusters);

        typedef typename geometry::point_type<Ring>::type point_type;
        typedef typename Strategy::template area_strategy
            <
                point_type
            >::type area_strategy_type;
        typedef typename area_strategy_type::template result_type<point_type>::type area_result_type;
        typedef detail::overlay::ring_properties<point_type, area_result_type> properties;

        std::map<ring_identifier, properties> selected;

        detail::overlay::select_rings<overlay_dissolve>(input_ring, turn_info_per_ring, selected, strategy);

        // Add intersected rings
        area_strategy_type const area_strategy = strategy.template get_area_strategy<point_type>();

        {
            ring_identifier id(2, 0, -1);
            for (typename boost::range_iterator<ring_container_type const>::type
                    it = boost::begin(rings);
                    it != boost::end(rings);
                    ++it)
            {
                selected[id] = properties(*it, area_strategy);
                id.multi_index++;
            }
        }

        detail::overlay::assign_parents<overlay_dissolve>(input_ring,
            rings, selected, strategy);
        detail::overlay::add_rings<GeometryOut>(selected, input_ring, rings, out, area_strategy);
    }

    template
    <
        typename RescalePolicy, typename OutputIterator,
        typename Strategy, typename Visitor
    >
    static inline OutputIterator apply(Ring const& geometry,
                RescalePolicy const& rescale_policy,
                OutputIterator out,
                Strategy const& strategy,
                Visitor& visitor)
    {
        typedef model::multi_polygon<GeometryOut> multi_polygon;
        multi_polygon step1;
        apply_one(geometry, rescale_policy, std::back_inserter(step1), strategy, visitor);

        // Step 2: remove mutual overlap
        {
            multi_polygon step2; // TODO avoid this, output to "out", if possible
            detail::dissolver::dissolver_generic
                <
                    detail::dissolver::plusmin_policy
                >::apply(step1, rescale_policy, step2, strategy);
            for (typename multi_polygon::const_iterator it = step2.begin();
                it != step2.end(); ++it)
            {
                *out++ = *it;
            }
        }
        return out;
    }
};

template <typename Polygon, typename GeometryOut, bool Reverse>
struct dissolve_polygon
{
    typedef typename ring_type<Polygon>::type ring_type;

    template
    <
        typename RescalePolicy, typename OutputCollection,
        typename Strategy, typename Visitor
    >
    static inline void apply_ring(ring_type const& ring,
                RescalePolicy const& rescale_policy,
                OutputCollection& out,
                Strategy const& strategy,
                Visitor& visitor)
    {
        bool const orientation_ok = geometry::area(ring) >= 0;
        if (orientation_ok)
        {
            dissolve_ring<ring_type, GeometryOut, Reverse>
                    ::apply(ring, rescale_policy,
                            std::back_inserter(out), strategy, visitor);
        }
        else
        {
            // Apply the whole dissolve implementation reversed
            dissolve_ring<ring_type, GeometryOut, ! Reverse>
                    ::apply(ring, rescale_policy,
                            std::back_inserter(out), strategy, visitor);
        }
    }

    template
    <
        typename Rings,
        typename RescalePolicy, typename OutputCollection,
        typename Strategy, typename Visitor
    >
    static inline void apply_rings(Rings const& rings,
                RescalePolicy const& rescale_policy,
                OutputCollection& out,
                Strategy const& strategy,
                Visitor& visitor)
    {
        for (typename boost::range_iterator<Rings const>::type
             it = boost::begin(rings); it != boost::end(rings); ++it)
        {
            apply_ring(*it, rescale_policy, out, strategy, visitor);
        }
    }

    template
    <
        typename RescalePolicy, typename OutputIterator,
        typename Strategy, typename Visitor
    >
    static inline OutputIterator apply(Polygon const& polygon,
                RescalePolicy const& rescale_policy,
                OutputIterator out,
                Strategy const& strategy,
                Visitor& visitor)
    {
        typedef model::multi_polygon<GeometryOut> multi_polygon;

        // Handle exterior ring
        multi_polygon exterior_out;
        apply_ring(exterior_ring(polygon), rescale_policy,
                   exterior_out, strategy, visitor);

        // Dissolve all the (negative) interior rings into
        // a (positive) mulpolygon. Do this per interior ring and combine them.
        multi_polygon interior_out_per_ring;
        apply_rings(interior_rings(polygon), rescale_policy,
                   interior_out_per_ring, strategy, visitor);

        // Remove mutual overlap in the interior ring output
        multi_polygon interior_out;
        detail::dissolver::dissolver_generic
            <
                detail::dissolver::plusmin_policy
            >::apply(interior_out_per_ring, rescale_policy, interior_out, strategy);

        // Subtract the interior rings from the output. Where interior rings
        // are partly or completely outside the polygon, sym_difference will
        // turn them into exterior rings. This is probably what most users will
        // expect - alternatively, difference could be used to have them pure
        // as interior rings only
        return detail::sym_difference::sym_difference_insert<GeometryOut>(
                    exterior_out, interior_out, rescale_policy, out);
    }
};


}} // namespace detail::dissolve
#endif // DOXYGEN_NO_DETAIL


#ifndef DOXYGEN_NO_DISPATCH
namespace dispatch
{

template
<
    typename Geometry,
    typename GeometryOut,
    bool Reverse,
    typename GeometryTag = typename tag<Geometry>::type,
    typename GeometryOutTag = typename tag<GeometryOut>::type
>
struct dissolve
    : not_implemented<GeometryTag, GeometryOutTag>
{};


template<typename Ring, typename RingOut, bool Reverse>
struct dissolve<Ring, RingOut, Reverse, ring_tag, ring_tag>
    : detail::dissolve::dissolve_ring<Ring, RingOut, Reverse>
{};


template<typename Polygon, typename PolygonOut, bool Reverse>
struct dissolve<Polygon, PolygonOut, Reverse, polygon_tag, polygon_tag>
    : detail::dissolve::dissolve_polygon<Polygon, PolygonOut, Reverse>
{};


} // namespace dispatch
#endif // DOXYGEN_NO_DISPATCH



/*!
    \brief Removes self intersections from a geometry
    \ingroup overlay
    \tparam Geometry geometry type
    \tparam OutputIterator type of intersection container
        (e.g. vector of "intersection/turn point"'s)
    \tparam Strategy type of a strategy
    \param geometry first geometry
    \param out output iterator getting dissolved geometry
    \param strategy a strategy
    \note Currently dissolve with a (multi)linestring does NOT remove internal
        overlap, it only tries to connect multiple line end-points.
        TODO: we should change this behaviour and add a separate "connect"
        algorithm, and let dissolve work like polygon.
 */
template
<
    typename GeometryOut,
    typename Geometry,
    typename OutputIterator,
    typename Strategy
>
inline OutputIterator dissolve_inserter(Geometry const& geometry,
                                        OutputIterator out,
                                        Strategy const& strategy)
{
    concepts::check<Geometry const>();
    concepts::check<GeometryOut>();

    typedef typename geometry::rescale_policy_type
    <
        typename geometry::point_type<Geometry>::type
    >::type rescale_policy_type;

    rescale_policy_type robust_policy
        = geometry::get_rescale_policy<rescale_policy_type>(geometry);

    detail::overlay::overlay_null_visitor visitor;

    return dispatch::dissolve
    <
        Geometry,
        GeometryOut,
        detail::overlay::do_reverse
        <
            geometry::point_order<Geometry>::value
        >::value
    >::apply(geometry, robust_policy, out, strategy, visitor);
}

/*!
    \brief Removes self intersections from a geometry
    \ingroup overlay
    \tparam Geometry geometry type
    \tparam OutputIterator type of intersection container
        (e.g. vector of "intersection/turn point"'s)
    \param geometry first geometry
    \param out output iterator getting dissolved geometry
    \note Currently dissolve with a (multi)linestring does NOT remove internal
        overlap, it only tries to connect multiple line end-points.
        TODO: we should change this behaviour and add a separate "connect"
        algorithm, and let dissolve work like polygon.
 */
template
<
    typename GeometryOut,
    typename Geometry,
    typename OutputIterator
>
inline OutputIterator dissolve_inserter(Geometry const& geometry,
                                        OutputIterator out)
{
    typedef typename strategy::intersection::services::default_strategy
        <
            typename cs_tag<Geometry>::type
        >::type strategy_type;

    return dissolve_inserter<GeometryOut>(geometry, out, strategy_type());
}


template
<
    typename Geometry,
    typename Collection,
    typename Strategy
>
inline void dissolve(Geometry const& geometry, Collection& output_collection,
                     Strategy const& strategy)
{
    concepts::check<Geometry const>();

    typedef typename boost::range_value<Collection>::type geometry_out;

    concepts::check<geometry_out>();

    typedef typename geometry::rescale_policy_type
    <
        typename geometry::point_type<Geometry>::type
    >::type rescale_policy_type;

    rescale_policy_type robust_policy
        = geometry::get_rescale_policy<rescale_policy_type>(geometry);

    detail::overlay::overlay_null_visitor visitor;

    dispatch::dissolve
    <
        Geometry,
        geometry_out,
        detail::overlay::do_reverse
        <
            geometry::point_order<Geometry>::value
        >::value
    >::apply(geometry, robust_policy,
             std::back_inserter(output_collection),
             strategy, visitor);
}

template
<
    typename Geometry,
    typename Collection
>
inline void dissolve(Geometry const& geometry, Collection& output_collection)
{
    typedef typename strategy::intersection::services::default_strategy
        <
            typename cs_tag<Geometry>::type
        >::type strategy_type;

    dissolve(geometry, output_collection, strategy_type());
}



}} // namespace boost::geometry

#endif // BOOST_GEOMETRY_EXTENSIONS_ALGORITHMS_DISSOLVE_HPP
