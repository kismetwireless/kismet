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

class StructuredData;
typedef std::shared_ptr<StructuredData> SharedStructured;

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

class StructuredData {
public:
    typedef std::vector<SharedStructured> structured_vec;
    typedef structured_vec::iterator structured_vec_iterator;

    typedef std::map<double, SharedStructured> structured_num_map;
    typedef structured_num_map::iterator structured_num_map_iterator;

    typedef std::map<std::string, SharedStructured> structured_str_map;
    typedef structured_str_map::iterator structured_str_map_iterator;

    typedef std::vector<double> number_vec;
    typedef number_vec::iterator number_vec_iterator;

    typedef std::vector<std::string> string_vec;
    typedef string_vec::iterator string_vec_iterator;

    StructuredData() { };
    StructuredData(std::string data __attribute__((unused))) { };

    virtual ~StructuredData() { };

    // Describe this current object
    virtual bool isNumber() = 0;
    virtual bool isBool() = 0;
    virtual bool isString() = 0;
    virtual bool isArray() = 0;
    virtual bool isDictionary() = 0;
    virtual bool isBinary() = 0;

    virtual double getNumber() = 0;
    virtual std::string getString() = 0;
    virtual bool getBool() = 0;
    virtual std::string getBinaryStr() = 0;

    // Get vectors of numbers and strings
    virtual number_vec getNumberVec() = 0;
    virtual string_vec getStringVec() = 0;

    // Get keyed values as...
    virtual bool hasKey(std::string key) = 0;
    virtual SharedStructured getStructuredByKey(std::string key) = 0;
    virtual double getKeyAsNumber(std::string key) = 0;
    virtual double getKeyAsNumber(std::string key, double def) = 0;
    virtual std::string getKeyAsString(std::string key, std::string def) = 0;
    virtual std::string getKeyAsString(std::string key) = 0;
    virtual bool getKeyAsBool(std::string key) = 0;
    virtual bool getKeyAsBool(std::string key, bool def) = 0;

    // Get structured sub-arrays
    virtual structured_vec getStructuredArray() = 0;
    virtual structured_num_map getStructuredNumMap() = 0;
    virtual structured_str_map getStructuredStrMap() = 0;

    // Convert a structured array of paired arrays, or a structured dictinary of k:v pairs, to
    // a std::pair<string, string> structure useful in other functions.  May throw its own exceptions
    // OR other structured exceptions.
    std::vector<std::pair<std::string, std::string>> getAsPairVector() {
        auto ret = std::vector<std::pair<std::string, std::string>>();

        if (isArray()) {
            for (auto i : getStructuredArray()) {
                if (!i->isArray()) 
                    throw StructuredDataUnsuitable("Cannot parse object as vector of pairs for converstion to "
                            "pair list");

                auto sub = i->getStructuredArray();

                if (sub.size() != 2) 
                    throw StructuredDataUnsuitable("Cannot parse object as vector of pairs, expected 2"
                            "elements in nested list, cannot convert to pair list");

                ret.push_back(std::make_pair(sub[0]->getString(), sub[1]->getString()));
            }
        } else if (isDictionary()) {
            for (auto i : getStructuredStrMap()) {
                ret.push_back(std::make_pair(i.first, i.second->getString()));
            }
        } else {
            throw StructuredDataUnsuitable("Cannot parse object as vector or dictionary for conversion "
                    "to pair list");
        }

        return ret;
    }

};

#endif

