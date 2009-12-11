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

#ifndef __KISMET_JSON_H__
#define __KISMET_JSON_H__

#include "config.h"

#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <pwd.h>
#include <ctype.h>
#include <math.h>

#include <string>
#include <map>
#include <vector>
#include <list>
#include <sstream>
#include <iomanip>

#include "util.h"

// Basic JSON interpreter - understands numbers, floats, quoted strings, bools, 
// arrays, dictionaries, arbitrary nesting.  Currently sufficient for parsing
// from GPSD, may be extended for other protocols in the future
//
// JSON is annoyingly complex, requiring a full lex and parse process.

enum JSON_token_type {
	JSON_start, JSON_end, JSON_quoted, JSON_numeric, JSON_boolean, 
	JSON_arrstart, JSON_arrend, JSON_colon, JSON_comma, 
	// Meta-types for expected values
	JSON_sep, JSON_value, JSON_sym,
	JSON_unknown
};

struct JSON_token {
	JSON_token_type tok_type;
	string tok_str;
	int tok_position;
};

struct JSON_value {
	JSON_token value;

	// Dictionary of values, used for parents.  Values may in turn be
	// dictionaries or arrays
	map<string, struct JSON_value *> value_map;

	// If we're an array, the array of our values is here.  We can't be
	// both a dictionary and an array.
	vector<struct JSON_value *> value_array;
};

// Recursively free a JSON value
void JSON_delete(struct JSON_value *v);

// Parse a JSON string into a value struct.
// How value structs work:
//   A basic JSON structure is a dictionary which holds multiple symbol => value maps.
//   A value can be a string, int, float, bool, a sub-dictionary, or a sub-array.
//   An array can also hold multiple dictionaries as values.  Arrays are not forced to
//    hold all values of a single type, [1.2345, false, "foo"] is considered valid by
//    this parser.
//
//   Once parsed, the JSON_value returned struct is the top level dictionary.  Values
//    stored in this dictionary can be found in value_map keyed by their symbols.
//
//   When a value is extracted from value_map, value.tok_type should be checked to
//    determine what kind of value it is.  JSON_quoted, _numeric, _boolean contain
//    their values in value.tok_str as an unchecked string (numbers and bools should
//    be valid because they passed the lexer, but the caller should perform safe
//    transforms anyhow).
//
//   Nested dictionaries are stored as value.tok_type JSON_start, and nested arrays
//    are stored as JSON_arrstart.  The values contained in the nested structure are
//    stored in value_map and value_array, respectively.
//
//   Complex JSON data may require crawling through multiple levels of the dictionary
//    and array maps, examine the GPSD or look at the JSON_display() example function.
struct JSON_value *JSON_parse(string in_json, string& error);

struct JSON_value *JSON_dict_get_value(struct JSON_value *in_parent, string in_key,
									   string& error);

// Some basic JSON extraction functions for common actions
string JSON_dict_get_string(struct JSON_value *in_parent, string in_key,
							string& error);
// Always return a float, cast it to an int if you need to, can be used
// for bools too (you get a 0 or 1)
float JSON_dict_get_number(struct JSON_value *in_parent, string in_key,
							string& error);

// Example function which dumps to stdout a representation of the parsed JSON data
void JSON_dump(struct JSON_value *jsonv, string key, int depth);

#endif

