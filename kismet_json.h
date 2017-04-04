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

#include "config.hpp"

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

#include "structured.h"

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
// Always return a double, cast it to an int if you need to, can be used
// for bools too (you get a 0 or 1)
double JSON_dict_get_number(struct JSON_value *in_parent, string in_key,
        string& error);

vector<struct JSON_value *> JSON_dict_get_array(struct JSON_value *in_parent,
        string in_key, string& error);

double JSON_get_number(struct JSON_value *val, string& error);
string JSON_get_string(struct JSON_value *val, string& error);

// Do we have a key?
bool JSON_dict_has_key(struct JSON_value *val, string in_key);

// Example function which dumps to stdout a representation of the parsed JSON data
void JSON_dump(struct JSON_value *jsonv, string key, int depth);

class StructuredJson : public StructuredData {
public:
    StructuredJson(string data) : StructuredData(data) {
        json = JSON_parse(data, err);

        if (json == NULL || err.length() != 0) {
            throw StructuredDataUnparseable(err);
        }

        free_me = true;
    }

    StructuredJson(struct JSON_value *in_json) {
        free_me = false;
        json = in_json;
    }

    virtual ~StructuredJson() {
        if (free_me && json != NULL)
            JSON_delete(json);
    }

    void exceptIfNull() {
        if (json == NULL)
            throw StructuredDataNull("no JSON data");
    }

    void exceptIfNot(bool match, string t) {
        if (!match) {
            throw StructuredDataUnsuitable("JSON field is not " + t);
        }
    }

    virtual bool isNumber() {
        exceptIfNull();
        return (json->value.tok_type == JSON_numeric);
    }

    virtual bool isBool() {
        exceptIfNull();
        return (json->value.tok_type == JSON_boolean);
    }

    virtual bool isString() {
        exceptIfNull();
        return (json->value.tok_type == JSON_quoted);
    }

    virtual bool isArray() {
        exceptIfNull();
        return (json->value_array.size() != 0);
    }

    virtual bool isDictionary() {
        exceptIfNull();
        return (json->value_map.size() != 0);
    }

    virtual double getNumber() {
        exceptIfNull();
        exceptIfNot(isNumber(), "number");

        double n = JSON_get_number(json, err);

        if (err.length() != 0)
            throw StructuredDataUnparseable(err);

        return n;
    }

    virtual string getString() {
        exceptIfNull();
        exceptIfNot(isString(), "string");

        string s = JSON_get_string(json, err);

        if (err.length() != 0) 
            throw StructuredDataUnparseable(err);

        return s;
    }

    virtual bool getBool() {
        exceptIfNull();
        exceptIfNot(isBool() || isString(), "Boolean");

        bool b = (JSON_get_number(json, err) == 1.0f);

        if (err.length() != 0)
            throw StructuredDataUnparseable(err);

        return b;
    }

    virtual number_vec getNumberVec() {
        exceptIfNull();
        exceptIfNot(isArray(), "Array/Vector");

        number_vec v;

        for (vector<struct JSON_value *>::iterator jvi = json->value_array.begin();
                jvi != json->value_array.end(); ++jvi) {
            double d = JSON_get_number(*jvi, err);

            if (err.length() != 0)
                throw StructuredDataUnparseable(err);

            v.push_back(d);
        }

        return v;
    }

    virtual string_vec getStringVec() {
        exceptIfNull();
        exceptIfNot(isArray(), "Array/Vector");

        string_vec v;

        for (vector<struct JSON_value *>::iterator jvi = json->value_array.begin();
                jvi != json->value_array.end(); ++jvi) {
            string s = JSON_get_string(*jvi, err);

            if (err.length() != 0)
                throw StructuredDataUnparseable(err);

            v.push_back(s);
        }

        return v;
    }

    virtual bool hasKey(string key) {
        return JSON_dict_has_key(json, key);
    }

    virtual SharedStructured getStructuredByKey(string key) {
        exceptIfNull();
        exceptIfNot(isDictionary(), "Dictionary/Map");

        if (!JSON_dict_has_key(json, key)) 
            throw StructuredDataNoSuchKey("No such key: " + key);

        struct JSON_value *nj = JSON_dict_get_value(json, key, err);

        if (err.length() != 0 || nj == NULL)
            throw StructuredDataUnsuitable(err);

        return SharedStructured(new StructuredJson(nj));
    }

    virtual double getKeyAsNumber(string key) {
        return getStructuredByKey(key)->getNumber();
    }

    virtual double getKeyAsNumber(string key, double def) {
        if (!hasKey(key))
            return def;

        SharedStructured v = getStructuredByKey(key);

        if (!v->isNumber())
            return def;

        return v->getNumber();
    }

    virtual string getKeyAsString(string key) {
        return getStructuredByKey(key)->getString();
    }

    virtual string getKeyAsString(string key, string def) {
        if (!hasKey(key))
            return def;

        SharedStructured v = getStructuredByKey(key);

        if (!v->isString())
            return def;

        return v->getString();
    }

    virtual bool getKeyAsBool(string key) {
        return getStructuredByKey(key)->getBool();
    }

    virtual bool getKeyAsBool(string key, bool def) {
        if (!hasKey(key))
            return def;

        SharedStructured v = getStructuredByKey(key);

        if (!v->isBool())
            return def;

        return v->getBool();
    }

    virtual structured_vec getStructuredArray() {
        exceptIfNull();
        exceptIfNot(isArray(), "array/vector");

        structured_vec v;

        for (vector<struct JSON_value *>::iterator jvi = json->value_array.begin();
                jvi != json->value_array.end(); ++jvi) {
            v.push_back(SharedStructured(new StructuredJson(*jvi)));
        }

        return v;
    }

    virtual structured_num_map getStructuredNumMap() {
        exceptIfNull();
        exceptIfNot(isArray(), "dictionary/map");

        structured_num_map m;

        for (map<string, struct JSON_value *>::iterator jmi = json->value_map.begin();
                jmi != json->value_map.end(); ++jmi) {
            double n;

            if (sscanf(jmi->first.c_str(), "%lf", &n) != 1)
                throw StructuredDataUnsuitable("got non-numerical key converting "
                        "to structured numerical map");

            m[n] = SharedStructured(new StructuredJson(jmi->second));
        }

        return m;
    }

    virtual structured_str_map getStructuredStrMap() {
        exceptIfNull();
        exceptIfNot(isDictionary(), "dictionary/map");

        structured_str_map m;

        for (map<string, struct JSON_value *>::iterator jmi = json->value_map.begin();
                jmi != json->value_map.end(); ++jmi) {
            m[jmi->first] = SharedStructured(new StructuredJson(jmi->second));
        }

        return m;
    }

protected:
    bool free_me;
    struct JSON_value *json;
    string err;
};

#endif

