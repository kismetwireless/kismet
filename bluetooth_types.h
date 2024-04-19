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

#ifndef __BLUETOOTH_TYPES_H__
#define __BLUETOOTH_TYPES_H__

#include "config.h"

#include <string>
#include <unordered_map>

#include "globalregistry.h"
#include "trackedcomponent.h"

// Very basic mapped class to map the (large number) of bt type
// IDs to human strings.  
//
// Major and minor classes are stored as pre-typed string elements
// since these are known types for the device tracker elements.

class kis_bt_types : public lifetime_global {
public:
    static std::string global_name() { return "BT_TYPES"; }

    static std::shared_ptr<kis_bt_types> create_bt_types() {
        std::shared_ptr<kis_bt_types> r(new kis_bt_types());
        Globalreg::globalreg->register_lifetime_global(r);
        Globalreg::globalreg->insert_global(global_name(), r);
        return r;
    }

    ~kis_bt_types();

private:
    kis_bt_types();

public:
    std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string> > bt_major_dev_class;
    std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string> > bt_minor_dev_class_computer;
    std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string> > bt_minor_dev_class_phone;
    std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string> > bt_minor_dev_class_lan_load;
    std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string> > bt_minor_dev_class_av;
    std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string> > bt_minor_dev_class_peripheral;
    std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string> > bt_minor_dev_type_peripheral;
    std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string> > bt_minor_dev_class_wearable;
    std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string> > bt_minor_dev_class_toy;
    std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string> > bt_minor_dev_class_health;
    std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string> > bt_appearance;
    std::unordered_map<unsigned int, std::shared_ptr<tracker_element_string> > bt_io_capability;

protected:
    int major_class_id, minor_class_id;
};

#endif

