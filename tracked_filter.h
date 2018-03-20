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

#ifndef __TRACKED_FILTER_H__
#define __TRACKED_FILTER_H__

// Tracked element filter grammar
//
// Provides a framework for fabricating complex queries and filters
// of tracked objects

#include "config.h"

#include <string>
#include <memory>
#include <vector>

#ifdef HAVE_LIBPCRE
#include <pcre.h>
#endif

#include "structured.h"
#include "trackedelement.h"

// Possible input from json:
// {"op": "&&", "filters": 
//  [ 
//   {"field": "kismet.device.base.packets", "op": ">=", "value": 50}, 
//   {"field": "kismet.device.base.signal/kismet.common.signal.max_signal_dbm", "op": ">", "value": -40},
//   {"field": "dot11.device/dot11.device.last_beaconed_ssid", "op": "regex", "value": "^FOO.*"} 
//  ] 
// }

class tracked_filter_operation;
typedef std::shared_ptr<tracked_filter_operation> shared_filter_operation;

class tracked_filter_operation {
public:
    enum filter_op_type {
        // and/or operations contain a vector of sub-ops
        op_and, op_or,

        op_equal, op_not_equal,
        op_lessthan, op_lessthaneq,
        op_greaterthan, op_greaterthaneq,
        op_bitand, 
        op_regex, op_contains,
        op_strcase_equal, op_strcase_not_equal,
    };

    // Generate an arbitrarily complex operation from structured data
    tracked_filter_operation(StructuredData *in_structured);
    // Generate a multi-operation
    tracked_filter_operation(std::string in_op, std::vector<shared_filter_operation> in_filters);
    // Generate a string-based option (regex, ==, !=, contains, string equals)
    tracked_filter_operation(std::string in_op, std::string in_field, std::string in_string);
    // Generate a numerical option (< > <= >= B& == !=)
    tracked_filter_operation(std::string in_op, std::string in_field, double in_number);

    bool compute(SharedTrackerElement e);

protected:
    std::string m_field;
    std::vector<int> m_field_path;

    std::vector<std::shared_ptr<tracked_filter_operation> > m_filters;

    // String match used for equals and contains
    std::string m_stringmatch;
    // Numerical used for all number-like formats; ints, unsigned, double, float, bitwise ops, etc
    double m_num_match;

#ifdef HAV_LIBPCRE
    pcre *m_re;
    pcre_extra *m_study;
#endif

};


class tracked_filter {
public:



};

#endif

