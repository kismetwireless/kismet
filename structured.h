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
 * interface between msgpack and json, with the option to expand to other
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

class StructuredData;
typedef shared_ptr<StructuredData> SharedStructured;

class StructuredData {
public:
    typedef vector<SharedStructured> structured_vec;
    typedef structured_vec::iterator structured_vec_iterator;

    typedef map<double, SharedStructured> structured_num_map;
    typedef structured_num_map::iterator structured_num_map_iterator;

    typedef map<string, SharedStructured> structured_str_map;
    typedef structured_str_map::iterator structured_str_map_iterator;

    typedef vector<double> number_vec;
    typedef number_vec::iterator number_vec_iterator;

    typedef vector<string> string_vec;
    typedef string_vec::iterator string_vec_iterator;

    StructuredData() { };
    StructuredData(string data __attribute__((unused))) { };

    virtual ~StructuredData() { };

    // Describe this current object
    virtual bool isNumber() = 0;
    virtual bool isBool() = 0;
    virtual bool isString() = 0;
    virtual bool isArray() = 0;
    virtual bool isDictionary() = 0;
    virtual bool isBinary() = 0;

    virtual double getNumber() = 0;
    virtual string getString() = 0;
    virtual bool getBool() = 0;
    virtual string getBinaryStr() = 0;

    // Get vectors of numbers and strings
    virtual number_vec getNumberVec() = 0;
    virtual string_vec getStringVec() = 0;

    // Get keyed values as...
    virtual bool hasKey(string key) = 0;
    virtual SharedStructured getStructuredByKey(string key) = 0;
    virtual double getKeyAsNumber(string key) = 0;
    virtual double getKeyAsNumber(string key, double def) = 0;
    virtual string getKeyAsString(string key, string def) = 0;
    virtual string getKeyAsString(string key) = 0;
    virtual bool getKeyAsBool(string key) = 0;
    virtual bool getKeyAsBool(string key, bool def) = 0;

    // Get structured sub-arrays
    virtual structured_vec getStructuredArray() = 0;
    virtual structured_num_map getStructuredNumMap() = 0;
    virtual structured_str_map getStructuredStrMap() = 0;

};

// Top-level exception
struct StructuredDataException : public std::runtime_error {
    StructuredDataException(std::string const& message) : 
        std::runtime_error(message) {}
};

// Can't parse the initial data given (json/msgpack error)
struct StructuredDataUnparseable : public StructuredDataException {
    StructuredDataUnparseable(std::string const& message) : 
        StructuredDataException(message) {}
};

// No data available
struct StructuredDataNull : public StructuredDataException {
    StructuredDataNull(std::string const& message) : 
        StructuredDataException(message) {}
};

// Can't extract the type asked for
struct StructuredDataUnsuitable : public StructuredDataException {
    StructuredDataUnsuitable(std::string const& message) : 
        StructuredDataException(message) {}
};

struct StructuredDataNoSuchKey : public StructuredDataException {
    StructuredDataNoSuchKey(std::string const& message) : 
        StructuredDataException(message) {}
};

#endif

