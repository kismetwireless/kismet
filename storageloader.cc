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

#include "storageloader.h"

#include "trackedelement.h"
#include "globalregistry.h"
#include "entrytracker.h"
#include "structured.h"
#include "devicetracker.h"

SharedTrackerElement StorageLoader::storage_to_tracker(SharedStructured d) {

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

    std::shared_ptr<StructuredData> objdata;

    SharedTrackerElement elem;
    int elemid;

    std::string hexstr;

    if (d->hasKey("on"))
        objname = d->getKeyAsString("on");
    else if (d->hasKey("objname"))
        objname = d->getKeyAsString("objname");
    else
        throw std::runtime_error("storage object missing 'on'/'objname'");

    if (d->hasKey("ot"))
        objtypestr = d->getKeyAsString("ot");
    else if (d->hasKey("objtype"))
        objtypestr = d->getKeyAsString("objtype");
    else
        throw std::runtime_error("storage object missing 'ot'/'objtype'");

    objtype = TrackerElement::typestring_to_type(objtypestr);

    if (d->hasKey("od"))
        objdata = d->getStructuredByKey("od");
    else if (d->hasKey("objdata"))
        objdata = d->getStructuredByKey("objdata");
    else
        throw std::runtime_error("storage object missing 'od'/'objdata'");

    elemid = Globalreg::globalreg->entrytracker->GetFieldId(objname);
    // elem.reset(new TrackerElement(objtype, elemid));

    try {
        switch (objtype) {
            // Integer types are directly coerced
            case TrackerType::TrackerInt8:
                elem = std::make_shared<TrackerElementInt8>();
                elem->coercive_set(objdata->getNumber());
                break;
            case TrackerType::TrackerUInt8:
                elem = std::make_shared<TrackerElementUInt8>();
                elem->coercive_set(objdata->getNumber());
                break;
            case TrackerType::TrackerInt16:
                elem = std::make_shared<TrackerElementInt16>();
                elem->coercive_set(objdata->getNumber());
                break;
            case TrackerType::TrackerUInt16:
                elem = std::make_shared<TrackerElementUInt16>();
                elem->coercive_set(objdata->getNumber());
                break;
            case TrackerType::TrackerInt32:
                elem = std::make_shared<TrackerElementInt32>();
                elem->coercive_set(objdata->getNumber());
                break;
            case TrackerType::TrackerUInt32:
                elem = std::make_shared<TrackerElementUInt32>();
                elem->coercive_set(objdata->getNumber());
                break;
            case TrackerType::TrackerInt64:
                elem = std::make_shared<TrackerElementInt64>();
                elem->coercive_set(objdata->getNumber());
                break;
            case TrackerType::TrackerUInt64:
                elem = std::make_shared<TrackerElementUInt64>();
                elem->coercive_set(objdata->getNumber());
                break;
            case TrackerType::TrackerFloat:
                elem = std::make_shared<TrackerElementFloat>();
                elem->coercive_set(objdata->getNumber());
                break;
            case TrackerType::TrackerDouble:
                elem = std::make_shared<TrackerElementDouble>();
                elem->coercive_set(objdata->getNumber());
                break;
                // String and string-like types are directly coerced
            case TrackerType::TrackerString:
                elem = std::make_shared<TrackerElementString>();
                elem->coercive_set(objdata->getString());
                break;
            case TrackerType::TrackerMac:
                elem = std::make_shared<TrackerElementMacAddr>();
                elem->coercive_set(objdata->getString());
                break;
            case TrackerType::TrackerUuid:
                elem = std::make_shared<TrackerElementUUID>();
                elem->coercive_set(objdata->getString());
                break;
            case TrackerType::TrackerKey:
                elem = std::make_shared<TrackerElementDeviceKey>();
                elem->coercive_set(objdata->getString());
                break;
                // Map and vector types need to be iteratively processed
            case TrackerType::TrackerVector:
                elem = std::make_shared<TrackerElementVector>();
                for (auto i : objdata->getStructuredArray()) {
                    auto re = storage_to_tracker(i);

                    if (re != NULL)
                        std::static_pointer_cast<TrackerElementVector>(elem)->push_back(re);
                }

                break;
            case TrackerType::TrackerMap:
                elem = std::make_shared<TrackerElementMap>();

                for (auto i : objdata->getStructuredStrMap()) {
                    auto re = storage_to_tracker(i.second);

                    if (re != NULL) 
                        std::static_pointer_cast<TrackerElementMap>(elem)->insert(re);
                }

                break;
            case TrackerType::TrackerMacMap:
                elem = std::make_shared<TrackerElementMacMap>();

                for (auto i : objdata->getStructuredStrMap()) {
                    mac_addr m(i.first);
                    if (m.error)
                        throw std::runtime_error("unable to process mac address key in macmap");

                    auto re = storage_to_tracker(i.second);

                    if (re != NULL)
                        std::static_pointer_cast<TrackerElementMacMap>(elem)->insert(m, re);
                }

                break;
            case TrackerType::TrackerIntMap:
                elem = std::make_shared<TrackerElementIntMap>();

                for (auto i : objdata->getStructuredNumMap()) {
                    auto re = storage_to_tracker(i.second);

                    if (re != NULL) 
                        std::static_pointer_cast<TrackerElementIntMap>(elem)->insert(i.first, re);
                }

                break;
            case TrackerType::TrackerDoubleMap:
                elem = std::make_shared<TrackerElementDoubleMap>();

                for (auto i : objdata->getStructuredNumMap()) {
                    auto re = storage_to_tracker(i.second);

                    if (re != NULL) 
                        std::static_pointer_cast<TrackerElementDoubleMap>(elem)->insert(i.first, re);
                }
            case TrackerType::TrackerStringMap:
                elem = std::make_shared<TrackerElementStringMap>();

                for (auto i : objdata->getStructuredStrMap()) {
                    auto re = storage_to_tracker(i.second);

                    if (re != NULL)
                        std::static_pointer_cast<TrackerElementStringMap>(elem)->insert(i.first, re);
                }

                break;
            case TrackerType::TrackerKeyMap:
                elem = std::make_shared<TrackerElementDeviceKeyMap>();

                for (auto i : objdata->getStructuredStrMap()) {
                    device_key k(i.first);
                    if (k.get_error())
                        throw std::runtime_error("unable to process device key in keymap");

                    auto re = storage_to_tracker(i.second);

                    if (re != NULL) 
                        std::static_pointer_cast<TrackerElementDeviceKeyMap>(elem)->insert(k, re);
                }
                break;
            case TrackerType::TrackerByteArray:
                // hexstr = hexstr_to_binstr(objdata->getString().c_str());
                elem = std::make_shared<TrackerElementByteArray>();

                std::static_pointer_cast<TrackerElementByteArray>(elem)->set(objdata->getBinaryStr());

                break;
            default:
                throw std::runtime_error("unknown trackerelement type " + objtypestr);
        }
    } catch (const StructuredDataException &e) {
        throw std::runtime_error("unable to process field '" + objname + "' type '" + 
                objtypestr + "' " + std::string(e.what()));
    }

    return elem;
}

