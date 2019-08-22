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

shared_tracker_element storage_loader::storage_to_tracker(shared_structured d) {

    // A '0' object is a NULL reference, skip it
    if (d->is_number() && d->as_number() == 0)
        return NULL;

    // Each object should be a dictionary containing a 'storage' format record from 
    // Kismet...
    if (!d->is_dictionary()) 
        throw std::runtime_error("expected dictionary object from structured serialization");

    structured_data::structured_str_map m = d->as_string_map();

    std::string objname;
    std::string objtypestr;
    tracker_type objtype;

    std::shared_ptr<structured_data> objdata;

    shared_tracker_element elem;
    int elemid;

    std::string hexstr;

    if (d->has_key("on"))
        objname = d->key_as_string("on");
    else if (d->has_key("objname"))
        objname = d->key_as_string("objname");
    else
        throw std::runtime_error("storage object missing 'on'/'objname'");

    if (d->has_key("ot"))
        objtypestr = d->key_as_string("ot");
    else if (d->has_key("objtype"))
        objtypestr = d->key_as_string("objtype");
    else
        throw std::runtime_error("storage object missing 'ot'/'objtype'");

    objtype = tracker_element::typestring_to_type(objtypestr);

    if (d->has_key("od"))
        objdata = d->get_structured_by_key("od");
    else if (d->has_key("objdata"))
        objdata = d->get_structured_by_key("objdata");
    else
        throw std::runtime_error("storage object missing 'od'/'objdata'");

    elemid = Globalreg::globalreg->entrytracker->get_field_id(objname);
    // elem.reset(new tracker_element(objtype, elemid));

    try {
        switch (objtype) {
            // Integer types are directly coerced
            case tracker_type::tracker_int8:
                elem = std::make_shared<tracker_element_int8>();
                elem->coercive_set(objdata->as_number());
                break;
            case tracker_type::tracker_uint8:
                elem = std::make_shared<tracker_element_uint8>();
                elem->coercive_set(objdata->as_number());
                break;
            case tracker_type::tracker_int16:
                elem = std::make_shared<tracker_element_int16>();
                elem->coercive_set(objdata->as_number());
                break;
            case tracker_type::tracker_uint16:
                elem = std::make_shared<tracker_element_uint16>();
                elem->coercive_set(objdata->as_number());
                break;
            case tracker_type::tracker_int32:
                elem = std::make_shared<tracker_element_int32>();
                elem->coercive_set(objdata->as_number());
                break;
            case tracker_type::tracker_uint32:
                elem = std::make_shared<tracker_element_uint32>();
                elem->coercive_set(objdata->as_number());
                break;
            case tracker_type::tracker_int64:
                elem = std::make_shared<tracker_element_int64>();
                elem->coercive_set(objdata->as_number());
                break;
            case tracker_type::tracker_uint64:
                elem = std::make_shared<tracker_element_uint64>();
                elem->coercive_set(objdata->as_number());
                break;
            case tracker_type::tracker_float:
                elem = std::make_shared<tracker_element_float>();
                elem->coercive_set(objdata->as_number());
                break;
            case tracker_type::tracker_double:
                elem = std::make_shared<tracker_element_double>();
                elem->coercive_set(objdata->as_number());
                break;
                // String and string-like types are directly coerced
            case tracker_type::tracker_string:
                elem = std::make_shared<tracker_element_string>();
                elem->coercive_set(objdata->as_string());
                break;
            case tracker_type::tracker_mac_addr:
                elem = std::make_shared<tracker_element_mac_addr>();
                elem->coercive_set(objdata->as_string());
                break;
            case tracker_type::tracker_uuid:
                elem = std::make_shared<tracker_element_uuid>();
                elem->coercive_set(objdata->as_string());
                break;
            case tracker_type::tracker_key:
                elem = std::make_shared<tracker_element_device_key>();
                elem->coercive_set(objdata->as_string());
                break;
                // Map and vector types need to be iteratively processed
            case tracker_type::tracker_vector:
                elem = std::make_shared<tracker_element_vector>();
                for (auto i : objdata->as_vector()) {
                    auto re = storage_to_tracker(i);

                    if (re != NULL)
                        std::static_pointer_cast<tracker_element_vector>(elem)->push_back(re);
                }

                break;
            case tracker_type::tracker_map:
                elem = std::make_shared<tracker_element_map>();

                for (auto i : objdata->as_string_map()) {
                    auto re = storage_to_tracker(i.second);

                    if (re != NULL) 
                        std::static_pointer_cast<tracker_element_map>(elem)->insert(re);
                }

                break;
            case tracker_type::tracker_mac_map:
                elem = std::make_shared<tracker_element_mac_map>();

                for (auto i : objdata->as_string_map()) {
                    mac_addr m(i.first);
                    if (m.error)
                        throw std::runtime_error("unable to process mac address key in macmap");

                    auto re = storage_to_tracker(i.second);

                    if (re != NULL)
                        std::static_pointer_cast<tracker_element_mac_map>(elem)->insert(m, re);
                }

                break;
            case tracker_type::tracker_int_map:
                elem = std::make_shared<tracker_element_int_map>();

                for (auto i : objdata->as_number_map()) {
                    auto re = storage_to_tracker(i.second);

                    if (re != NULL) 
                        std::static_pointer_cast<tracker_element_int_map>(elem)->insert(i.first, re);
                }

                break;
            case tracker_type::tracker_double_map:
                elem = std::make_shared<tracker_element_double_map>();

                for (auto i : objdata->as_number_map()) {
                    auto re = storage_to_tracker(i.second);

                    if (re != NULL) 
                        std::static_pointer_cast<tracker_element_double_map>(elem)->insert(i.first, re);
                }
            case tracker_type::tracker_string_map:
                elem = std::make_shared<tracker_element_string_map>();

                for (auto i : objdata->as_string_map()) {
                    auto re = storage_to_tracker(i.second);

                    if (re != NULL)
                        std::static_pointer_cast<tracker_element_string_map>(elem)->insert(i.first, re);
                }

                break;
            case tracker_type::tracker_key_map:
                elem = std::make_shared<tracker_element_device_key_map>();

                for (auto i : objdata->as_string_map()) {
                    device_key k(i.first);
                    if (k.get_error())
                        throw std::runtime_error("unable to process device key in keymap");

                    auto re = storage_to_tracker(i.second);

                    if (re != NULL) 
                        std::static_pointer_cast<tracker_element_device_key_map>(elem)->insert(k, re);
                }
                break;
            case tracker_type::tracker_byte_array:
                // hexstr = hexstr_to_binstr(objdata->as_string().c_str());
                elem = std::make_shared<tracker_element_byte_array>();

                std::static_pointer_cast<tracker_element_byte_array>(elem)->set(objdata->as_binary_string());

                break;
            default:
                throw std::runtime_error("unknown trackerelement type " + objtypestr);
        }
    } catch (const structured_data_exception &e) {
        throw std::runtime_error("unable to process field '" + objname + "' type '" + 
                objtypestr + "' " + std::string(e.what()));
    }

    return elem;
}

