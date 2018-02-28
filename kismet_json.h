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

class StructuredJson : public StructuredData {
public:
    StructuredJson(std::string data) : StructuredData(data) {
        try {
            std::stringstream ss(data);
            ss >> json;
        } catch (std::exception& e) {
            throw StructuredDataUnparseable(e.what());
        }
    }

    StructuredJson(Json::Value in_json) {
        json = in_json;
    }

    virtual ~StructuredJson() { }

    void exceptIfNot(bool match, std::string t) {
        if (!match) {
            throw StructuredDataUnsuitable("JSON field is not " + t);
        }
    }

    virtual bool isNumber() {
        return json.isNumeric();
    }

    virtual bool isBool() {
        return json.isBool();
    }

    virtual bool isString() {
        return json.isString();
    }

    virtual bool isArray() {
        return json.isArray();
    }

    virtual bool isDictionary() {
        return json.isObject();
    }

    // Binary in json is an encoded string
    virtual bool isBinary() {
        return isString();
    }

    virtual double getNumber() {
        exceptIfNot(isNumber(), "number");
        return json.asDouble();
    }

    virtual std::string getString() {
        exceptIfNot(isString(), "string");
        return json.asString();
    }

    virtual std::string getBinaryStr() {
        exceptIfNot(isString(), "binary string");
        return hexstr_to_binstr(getString().c_str());
    }

    virtual bool getBool() {
        exceptIfNot(isBool() || isString(), "Boolean");
        return json.asBool();
    }

    virtual number_vec getNumberVec() {
        exceptIfNot(isArray(), "Array/Vector");

        number_vec v;

        for (auto jvi : json) {
            double d = jvi.asDouble();
            v.push_back(d);
        }

        return v;
    }

    virtual string_vec getStringVec() {
        exceptIfNot(isArray(), "Array/Vector");

        string_vec v;

        for (auto jvi : json) {
            std::string s = jvi.asString();
            v.push_back(s);
        }

        return v;
    }

    virtual bool hasKey(std::string key) {
        return json.isMember(key);
    }

    virtual SharedStructured getStructuredByKey(std::string key) {
        exceptIfNot(isDictionary(), "Dictionary/Map");

        if (!hasKey(key)) 
            throw StructuredDataNoSuchKey("No such key: " + key);

        auto ki = json[key];

        return SharedStructured(new StructuredJson(ki));
    }

    virtual double getKeyAsNumber(std::string key) {
        return getStructuredByKey(key)->getNumber();
    }

    virtual double getKeyAsNumber(std::string key, double def) {
        if (!hasKey(key))
            return def;

        SharedStructured v = getStructuredByKey(key);

        if (!v->isNumber())
            return def;

        return v->getNumber();
    }

    virtual std::string getKeyAsString(std::string key) {
        return getStructuredByKey(key)->getString();
    }

    virtual std::string getKeyAsString(std::string key, std::string def) {
        if (!hasKey(key))
            return def;

        SharedStructured v = getStructuredByKey(key);

        if (!v->isString())
            return def;

        return v->getString();
    }

    virtual bool getKeyAsBool(std::string key) {
        return getStructuredByKey(key)->getBool();
    }

    virtual bool getKeyAsBool(std::string key, bool def) {
        if (!hasKey(key))
            return def;

        SharedStructured v = getStructuredByKey(key);

        if (!v->isBool())
            return def;

        return v->getBool();
    }

    virtual structured_vec getStructuredArray() {
        exceptIfNot(isArray(), "array/vector");

        structured_vec v;

        for (auto jvi : json) {
            v.push_back(SharedStructured(new StructuredJson(jvi)));
        }

        return v;
    }

    virtual structured_num_map getStructuredNumMap() {
        exceptIfNot(isDictionary(), "dictionary/map");

        structured_num_map m;

        for (Json::ValueIterator jvi = json.begin(); jvi != json.end(); ++jvi) {
            double n;
           
            if (sscanf(jvi.key().asString().c_str(), "%lf", &n) != 1)
                throw StructuredDataUnsuitable("got non-numerical key converting "
                        "to structured numerical map");
            
            m[n] = SharedStructured(new StructuredJson(*jvi));
        }

        return m;
    }

    virtual structured_str_map getStructuredStrMap() {
        exceptIfNot(isDictionary(), "dictionary/map");

        structured_str_map m;

        for (Json::ValueIterator jvi = json.begin(); jvi != json.end(); ++jvi) {
            m[jvi.key().asString()] = SharedStructured(new StructuredJson(*jvi));
        }

        return m;
    }

protected:
    bool free_me;
    Json::Value json;
    std::string err;
};

#endif

