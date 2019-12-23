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

#ifndef __KISMET_STRUCTURED_H__
#define __KISMET_STRUCTURED_H__

/* A generic superclass for handling structured input - specifically a common
 * interface between json, with the option to expand to other
 * structured encodings
 *
 * In general the structured API seeks to address fetching basic elements
 * from incoming data - strings, integers, arrays, and dictionaries,
 * with additional helpers for checking types and fetching values.
 *
 * Because encodings like json lack strict type definitions, the best we
 * can do in the generic case is tell if it's a number, string, and so on; 
 * the consumer will need to determine if it is in-range.  For instance, we
 * currently have to assume all numbers are doubles
 *
 */

#include "config.h"

#include <string>
#include <vector>
#include <map>
#include <memory>

class structured_data;
typedef std::shared_ptr<structured_data> shared_structured;

// Top-level exception
struct structured_data_exception : public std::runtime_error {
    structured_data_exception(std::string const& message) : 
        std::runtime_error(message) {}
};

// Can't parse the initial data given (json/msgpack error)
struct structured_data_unparseable : public structured_data_exception {
    structured_data_unparseable(std::string const& message) : 
        structured_data_exception(message) {}
};

// No data available
struct structured_data_null : public structured_data_exception {
    structured_data_null(std::string const& message) : 
        structured_data_exception(message) {}
};

// Can't extract the type asked for
struct structured_data_unsuitable : public structured_data_exception {
    structured_data_unsuitable(std::string const& message) : 
        structured_data_exception(message) {}
};

struct structured_data_no_such_key : public structured_data_exception {
    structured_data_no_such_key(std::string const& message) : 
        structured_data_exception(message) {}
};

class structured_data {
public:
    typedef std::vector<shared_structured> structured_vec;
    typedef structured_vec::iterator structured_vec_iterator;

    typedef std::map<double, shared_structured> structured_num_map;
    typedef structured_num_map::iterator structured_num_map_iterator;

    typedef std::map<std::string, shared_structured> structured_str_map;
    typedef structured_str_map::iterator structured_str_map_iterator;

    typedef std::vector<double> number_vec;
    typedef number_vec::iterator number_vec_iterator;

    typedef std::vector<std::string> string_vec;
    typedef string_vec::iterator string_vec_iterator;

    structured_data() { };
    structured_data(std::string data __attribute__((unused))) { };

    virtual ~structured_data() { };

    // Describe this current object
    virtual bool is_number() = 0;
    virtual bool is_bool() = 0;
    virtual bool is_string() = 0;
    virtual bool is_array() = 0;
    virtual bool is_dictionary() = 0;
    virtual bool is_binary() = 0;

    virtual double as_number() = 0;
    virtual std::string as_string() = 0;
    virtual bool as_bool() = 0;
    virtual std::string as_binary_string() = 0;

    // Get vectors of numbers and strings
    virtual number_vec as_number_vector() = 0;
    virtual string_vec as_string_vector() = 0;

    // Get keyed values as...
    virtual bool has_key(std::string key) = 0;
    virtual shared_structured get_structured_by_key(std::string key) = 0;
    virtual double key_as_number(std::string key) = 0;
    virtual double key_as_number(std::string key, double def) = 0;
    virtual std::string key_as_string(std::string key, std::string def) = 0;
    virtual std::string key_as_string(std::string key) = 0;
    virtual bool key_as_bool(std::string key) = 0;
    virtual bool key_as_bool(std::string key, bool def) = 0;

    // Get structured sub-arrays
    virtual structured_vec as_vector() = 0;
    virtual structured_num_map as_number_map() = 0;
    virtual structured_str_map as_string_map() = 0;

    // Convert a structured array of paired arrays, or a structured dictionary of k:v pairs, to
    // a std::pair<string, string> structure useful in other functions.  May throw its own exceptions
    // OR other structured exceptions.
    std::vector<std::pair<std::string, std::string>> as_pair_vector() {
        auto ret = std::vector<std::pair<std::string, std::string>>();

        if (is_array()) {
            for (auto i : as_vector()) {
                if (!i->is_array()) 
                    throw structured_data_unsuitable("Cannot parse object as vector of pairs for conversion to "
                            "pair list");

                auto sub = i->as_vector();

                if (sub.size() != 2) 
                    throw structured_data_unsuitable("Cannot parse object as vector of pairs, expected 2"
                            "elements in nested list, cannot convert to pair list");

                ret.push_back(std::make_pair(sub[0]->as_string(), sub[1]->as_string()));
            }
        } else if (is_dictionary()) {
            for (auto i : as_string_map()) {
                ret.push_back(std::make_pair(i.first, i.second->as_string()));
            }
        } else {
            throw structured_data_unsuitable("Cannot parse object as vector or dictionary for conversion "
                    "to pair list");
        }

        return ret;
    }

};

#endif

