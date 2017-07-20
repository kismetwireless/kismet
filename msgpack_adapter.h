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

#ifndef __MSGPACK_ADAPTER_H__
#define __MSGPACK_ADAPTER_H__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <msgpack.hpp>

#include "globalregistry.h"
#include "trackedelement.h"
#include "structured.h"

namespace MsgpackAdapter {

typedef map<string, msgpack::object> MsgpackStrMap;

void Packer(GlobalRegistry *globalreg, SharedTrackerElement v, 
        msgpack::packer<std::ostream> &packer,
        TrackerElementSerializer::rename_map *name_map = NULL);

void Pack(GlobalRegistry *globalreg, std::ostream &stream, 
        SharedTrackerElement e, 
        TrackerElementSerializer::rename_map *name_map = NULL);

class Serializer : public TrackerElementSerializer {
public:
    Serializer(GlobalRegistry *in_globalreg) :
        TrackerElementSerializer(in_globalreg) { }

    virtual void serialize(SharedTrackerElement in_elem, std::ostream &stream,
            rename_map *name_map = NULL) {
        local_locker lock(&mutex);
        Pack(globalreg, stream, in_elem, name_map);
    }
};

// Convert to std::vector<std::string>.  MAY THROW EXCEPTIONS.
void AsStringVector(msgpack::object &obj, std::vector<std::string> &vec);

}

class StructuredMsgpack : public StructuredData {
public:
    StructuredMsgpack(string data) : StructuredData(data) {
        try {
            msgpack::unpack(result, data.data(), data.size());
            object = result.get();
        } catch (const std::exception& e) {
            string se = string("Unable to unpack msgpack object: ") + e.what();
            throw StructuredDataUnparseable(se);
        }
    }

    StructuredMsgpack(msgpack::object obj) {
        object = obj;
    }

    virtual ~StructuredMsgpack() {

    }

    void exceptIfNot(bool match, string t) {
        if (!match) {
            throw StructuredDataUnsuitable("msgpack field is not " + t);
        }
    }

    virtual bool isNumber() {

        return (object.type == msgpack::type::POSITIVE_INTEGER ||
                object.type == msgpack::type::NEGATIVE_INTEGER ||
                object.type == msgpack::type::FLOAT);
    }

    virtual bool isBool() {
        return (object.type == msgpack::type::BOOLEAN ||
                isNumber());
    }
   
    virtual bool isString() {
        return object.type == msgpack::type::STR;
    }

    virtual bool isArray() {
        return object.type == msgpack::type::ARRAY;
    }

    virtual bool isDictionary() {
        return object.type == msgpack::type::MAP;
    }

    virtual double getNumber() {
        exceptIfNot(isNumber(), "number");

        try {
            return object.as<double>();
        } catch (const std::exception& e) {
            throw StructuredDataUnsuitable(e.what());
        }
    }

    virtual bool getBool() {
        exceptIfNot(isBool(), "boolean");
        return getNumber() != 0;
    }

    virtual string getString() {
        exceptIfNot(isString(), "string");

        try {
            return object.as<string>();
        } catch (const std::exception& e) {
            throw StructuredDataUnsuitable(e.what());
        }
    }

    virtual number_vec getNumberVec() {
        exceptIfNot(isArray(), "array/vector");

        try {
            return object.as<number_vec>();
        } catch (const std::exception& e) {
            throw StructuredDataUnsuitable(e.what());
        }
    }

    virtual string_vec getStringVec() {
        exceptIfNot(isArray(), "dictionary / map");

        try {
            return object.as<string_vec>();
        } catch (const std::exception& e) {
            throw StructuredDataUnsuitable(e.what());
        }
    }

    virtual bool hasKey(string key) {
        exceptIfNot(isDictionary(), "dictionary / map");

        try {
            string_key_map km = object.as<string_key_map>();
            return km.find(key) != km.end();
        } catch (const std::exception& e) {
            throw StructuredDataUnsuitable(e.what());
        }
    }

    virtual SharedStructured getStructuredByKey(string key) {
        exceptIfNot(isDictionary(), "dictionary / map");

        try {
            string_key_map km = object.as<string_key_map>();
            string_key_map::iterator i = km.find(key);

            if (i == km.end())
                throw StructuredDataNoSuchKey("No such key: " + key);

            return SharedStructured(new StructuredMsgpack(i->second));
        } catch (const std::exception& e) {
            throw StructuredDataUnsuitable(e.what());
        }
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
        exceptIfNot(isArray(), "array/vector");

        try {
            object_vector ov = object.as<object_vector>();
            structured_vec rv;

            for (object_vector::iterator i = ov.begin(); i != ov.end(); ++i) {
                rv.push_back(SharedStructured(new StructuredMsgpack(*i)));
            }

            return rv;

        } catch (const std::exception& e) {
            throw StructuredDataUnsuitable(e.what());
        }
    }

    virtual structured_num_map getStructuredNumMap() {
        exceptIfNot(isDictionary(), "dictionary/map");

        try {
            number_key_map nm = object.as<number_key_map>();
            structured_num_map rm;

            for (number_key_map::iterator i = nm.begin(); i != nm.end(); ++i) {
                rm[i->first] = SharedStructured(new StructuredMsgpack(i->second));
            }

            return rm;

        } catch (const std::exception& e) {
            throw StructuredDataUnsuitable(e.what());
        }
    }

    virtual structured_str_map getStructuredStrMap() {
        exceptIfNot(isDictionary(), "dictionary/map");

        try {
            string_key_map sm = object.as<string_key_map>();
            structured_str_map rm;

            for (string_key_map::iterator i = sm.begin(); i != sm.end(); ++i) {
                rm[i->first] = SharedStructured(new StructuredMsgpack(i->second));
            }

            return rm;
        } catch (const std::exception& e) {
            throw StructuredDataUnsuitable(e.what());
        }
    }

protected:
    typedef map<string, msgpack::object> string_key_map;
    typedef map<double, msgpack::object> number_key_map;
    typedef vector<msgpack::object> object_vector;

    msgpack::unpacked result;
    msgpack::object object;
};

#endif

