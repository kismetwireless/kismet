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
//
// Designed to be similar to an ELK-style query, where complex operations can
// be applied to the data.  Ultimately this will be used to form primitives elsewhere
// in kismet and expose complex queries directly to the API.
//
// Possible input from json:
// {"op": "&&", "filters": 
//  [ 
//   {"field": "kismet.device.base.packets", "op": ">=", "value": 50}, 
//   {"field": "kismet.device.base.signal/kismet.common.signal.max_signal_dbm", "op": ">", "value": -40},
//   {"field": "dot11.device/dot11.device.last_beaconed_ssid", "op": "regex", "value": "^FOO.*"} 
//  ] 
// }
//
// Nested conditions:
// {"op": "||", "filters": 
// [
//  {"op": "&&", "filters":
//  [
//  {"field": "kismet.device.base.packets", "op": ">=", "value": 50},
//  {"filed": "kismet.device.base.signal/kismet.common.signal.max_signal_dbm", "op": ">", "value": -40}
//  ]
//  },
//  {"field": "kismet.dot11/dot11.last_beaconed_ssid", "op": "==", "MonitoredSsid"}
// ]}
//
// Operators:
//  Comparison
//   '=='           Equal (numeric and string)
//   '!='           Not equal (numeric and string)
//   '<'            Less-than (numeric)
//   '>'            Greater-than (numeric)
//   '<='           Less-than or equal (numeric)
//   '>='           Greater-than or equal (numeric)
//   '&'            Bitwise-and (numeric), evaluated as result
//   '|'            Bitwise-or (numeric), evaluated as result
//   '^'            Bitwise-xor (numeric), evaluated as result
//   'regex'        Matches regex (string)
//   '!regex'       Does not match regex (string)
//   'contains'     Simple contains match (string)
//   '!contains'    Simple does not contain match (string)
//   'icontains'    Simple contains match, case insensitive (string)
//   '!icontains'   Simple does not contain match, case insensitive (string)
//
// Combinationators:
//  '&&'     And
//  '||'     Or


#include "config.h"

#include <string>
#include <memory>
#include <vector>

#ifdef HAVE_LIBPCRE1
#include <pcre.h>
#endif

#ifdef HAVE_LIBPCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#include "json/json.h"
#include "trackedelement.h"

class tracked_filter_operation;
typedef std::shared_ptr<tracked_filter_operation> shared_filter_operation;

class tracked_filter_operation {
public:
    enum class filter_op_type {
        // and/or operations contain a vector of sub-ops
        op_and, op_or,

        op_equal, op_not_equal,

        op_lessthan, op_lessthaneq,
        op_greaterthan, op_greaterthaneq,

        op_bitand, op_bitor, op_bitxor,

        op_regex, op_notregex,
        op_contains, op_notcontains, op_icontains, op_noticontains,
    };

    // Generate a multi-operation
    tracked_filter_operation(std::string in_op, std::vector<shared_filter_operation> in_filters);
    // Generate a string-based option (regex, ==, !=, contains, string equals)
    tracked_filter_operation(std::string in_op, std::string in_field, std::string in_string);
    // Generate a numerical option (< > <= >= B& == !=)
    tracked_filter_operation(std::string in_op, std::string in_field, double in_number);

    bool compute(shared_tracker_element e);

protected:
    std::string m_field;
    std::vector<int> m_field_path;

    std::vector<std::shared_ptr<tracked_filter_operation> > m_filters;

    // String match used for equals and contains
    std::string m_stringmatch;
    // Numerical used for all number-like formats; ints, unsigned, double, float, bitwise ops, etc
    double m_num_match;

#if defined(HAVE_LIBPCRE1)
    pcre *m_re;
    pcre_extra *m_study;
#elif defined(HAVE_LIBPCRE2)
    pcre2_code *m_re;
    pcre2_match_data *m_match_data;
#endif

};


class tracked_filter {
public:



};

#endif

