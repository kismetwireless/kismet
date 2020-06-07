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

#include "json/json.h"

#include "util.h"

#include "structured.h"

class structured_json : public structured_data {
public:
    structured_json(std::string data) : structured_data(data) {
        try {
            std::stringstream ss(data);
            ss >> json;
        } catch (std::exception& e) {
            throw structured_data_unparseable(e.what());
        }
    }

    structured_json(Json::Value in_json) {
        json = in_json;
    }

    virtual ~structured_json() { }

    void except_if_not(bool match, std::string t) {
        if (!match) {
            throw structured_data_unsuitable("JSON field is not " + t);
        }
    }

    virtual bool is_number() {
        return json.isNumeric();
    }

    virtual bool is_bool() {
        return json.isBool();
    }

    virtual bool is_string() {
        return json.isString();
    }

    virtual bool is_array() {
        return json.isArray();
    }

    virtual bool is_dictionary() {
        return json.isObject();
    }

    // Binary in json is an encoded string
    virtual bool is_binary() {
        return is_string();
    }

    virtual double as_number() {
        except_if_not(is_number(), "number");
        return json.asDouble();
    }

    virtual std::string as_string() {
        except_if_not(is_string(), "string");
        return json.asString();
    }

    virtual std::string as_binary_string() {
        except_if_not(is_string(), "binary string");
        return hex_to_bytes(as_string());
    }

    virtual bool as_bool() {
        except_if_not(is_bool() || is_string(), "Boolean");
        return json.asBool();
    }

    virtual number_vec as_number_vector() {
        except_if_not(is_array(), "Array/Vector");

        number_vec v;

        for (auto jvi : json) {
            double d = jvi.asDouble();
            v.push_back(d);
        }

        return v;
    }

    virtual string_vec as_string_vector() {
        except_if_not(is_array(), "Array/Vector");

        string_vec v;

        for (auto jvi : json) {
            std::string s = jvi.asString();
            v.push_back(s);
        }

        return v;
    }

    virtual bool has_key(std::string key) {
        return json.isMember(key);
    }

    virtual shared_structured get_structured_by_key(std::string key) {
        except_if_not(is_dictionary(), "Dictionary/Map");

        if (!has_key(key)) 
            throw structured_data_no_such_key("No such key: " + key);

        auto ki = json[key];

        return shared_structured(new structured_json(ki));
    }

    virtual double key_as_number(std::string key) {
        return get_structured_by_key(key)->as_number();
    }

    virtual double key_as_number(std::string key, double def) {
        if (!has_key(key))
            return def;

        shared_structured v = get_structured_by_key(key);

        if (!v->is_number())
            return def;

        return v->as_number();
    }

    virtual std::string key_as_string(std::string key) {
        return get_structured_by_key(key)->as_string();
    }

    virtual std::string key_as_string(std::string key, std::string def) {
        if (!has_key(key))
            return def;

        shared_structured v = get_structured_by_key(key);

        if (!v->is_string())
            return def;

        return v->as_string();
    }

    virtual bool key_as_bool(std::string key) {
        return get_structured_by_key(key)->as_bool();
    }

    virtual bool key_as_bool(std::string key, bool def) {
        if (!has_key(key))
            return def;

        shared_structured v = get_structured_by_key(key);

        if (!v->is_bool())
            return def;

        return v->as_bool();
    }

    virtual structured_vec as_vector() {
        except_if_not(is_array(), "array/vector");

        structured_vec v;

        for (auto jvi : json) {
            v.push_back(shared_structured(new structured_json(jvi)));
        }

        return v;
    }

    virtual structured_num_map as_number_map() {
        except_if_not(is_dictionary(), "dictionary/map");

        structured_num_map m;

        for (Json::ValueIterator jvi = json.begin(); jvi != json.end(); ++jvi) {
            double n;
           
            if (sscanf(jvi.key().asString().c_str(), "%lf", &n) != 1)
                throw structured_data_unsuitable("got non-numerical key converting "
                        "to structured numerical map");
            
            m[n] = shared_structured(new structured_json(*jvi));
        }

        return m;
    }

    virtual structured_str_map as_string_map() {
        except_if_not(is_dictionary(), "dictionary/map");

        structured_str_map m;

        for (Json::ValueIterator jvi = json.begin(); jvi != json.end(); ++jvi) {
            m[jvi.key().asString()] = shared_structured(new structured_json(*jvi));
        }

        return m;
    }

protected:
    bool free_me;
    Json::Value json;
    std::string err;
};

#endif

