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

#include <string>
#include <memory>
#include <fstream>
#include <iostream>

#include "storage_deserializer.h"

#include "trackedelement.h"
#include "globalregistry.h"
#include "entrytracker.h"
#include "structured.h"
#include "kismet_json.h"
#include "json_adapter.h"
#include "devicetracker.h"

SharedTrackerElement StorageLoader::storage_to_tracker(std::shared_ptr<EntryTracker> entrytracker, SharedStructured d) {

    // A '0' object is a NULL reference, skip it
    if (d->isNumber() && d->getNumber() == 0)
        return NULL;

    // Each object should be a dictionary containing a 'storage' format record from 
    // Kismet...
    if (!d->isDictionary()) 
        throw std::runtime_error("expected dictionary object from structured serialization");

    StructuredData::structured_str_map m = d->getStructuredStrMap();

    std::string objname;
    std::string objtypestr;
    TrackerType objtype;

    shared_ptr<StructuredData> objdata;

    SharedTrackerElement elem;
    int elemid;

    if (!d->hasKey("objname"))
        throw std::runtime_error("JSON storage object missing 'objname'");

    objname = d->getKeyAsString("objname");

    if (!d->hasKey("objtype"))
        throw std::runtime_error("JSON storage object missing 'objtype'");

    objtypestr = d->getKeyAsString("objtype");

    objtype = TrackerElement::typestring_to_type(objtypestr);

    if (!d->hasKey("objdata"))
        throw std::runtime_error("JSON storage object missing 'objdata'");

    elemid = entrytracker->GetFieldId(objname);

    elem.reset(new TrackerElement(objtype, elemid));

    objdata = d->getStructuredByKey("objdata");

    switch (objtype) {
        // Integer types are directly coerced
        case TrackerInt8:
        case TrackerUInt8:
        case TrackerInt16:
        case TrackerUInt16:
        case TrackerInt32:
        case TrackerUInt32:
        case TrackerInt64:
        case TrackerUInt64:
        case TrackerFloat:
        case TrackerDouble:
            elem->coercive_set(objdata->getNumber());
            break;
            // String and string-like types are directly coerced
        case TrackerString:
        case TrackerMac:
        case TrackerUuid:
            elem->coercive_set(objdata->getString());
            break;
            // Map and vector types need to be iteratively processed
        case TrackerVector:
            for (auto i : objdata->getStructuredArray()) {
                SharedTrackerElement re = storage_to_tracker(entrytracker, i);
               
                if (re != NULL)
                    elem->add_vector(re);
            }

            break;
        case TrackerMap:
            for (auto i : objdata->getStructuredStrMap()) {
                SharedTrackerElement re = storage_to_tracker(entrytracker, i.second);

                // We just don't add NULL objects
                if (re != NULL) 
                    elem->add_map(re);
            }

            break;
        case TrackerMacMap:
            for (auto i : objdata->getStructuredStrMap()) {
                mac_addr m(i.first);
                if (m.error)
                    throw std::runtime_error("unable to process mac address key in macmap");

                SharedTrackerElement re = storage_to_tracker(entrytracker, i.second);

                if (re != NULL)
                    elem->add_macmap(m, re);
            }

            break;
        case TrackerIntMap:
            for (auto i : objdata->getStructuredNumMap()) {
                SharedTrackerElement re = storage_to_tracker(entrytracker, i.second);

                if (re != NULL)
                    elem->add_intmap((int) i.first, re);
            }

            break;
        case TrackerDoubleMap:
            for (auto i : objdata->getStructuredNumMap()) {
                SharedTrackerElement re = storage_to_tracker(entrytracker, i.second);

                if (re != NULL)
                    elem->add_doublemap(i.first, re);
            }

            break;
        case TrackerStringMap:
            for (auto i : objdata->getStructuredStrMap()) {
                SharedTrackerElement re = storage_to_tracker(entrytracker, i.second);

                if (re != NULL)
                    elem->add_stringmap(i.first, re);
            }

            break;
        case TrackerByteArray:

            break;

        default:
            throw std::runtime_error("unknown trackerelement type " + objtypestr);
    }

    return elem;
}

