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

extern std::unordered_map<unsigned int, const char *> bt_major_dev_class;
extern std::unordered_map<unsigned int, const char *> bt_minor_dev_class_computer;
extern std::unordered_map<unsigned int, const char *> bt_minor_dev_class_phone;
extern std::unordered_map<unsigned int, const char *> bt_minor_dev_class_lan_load;
extern std::unordered_map<unsigned int, const char *> bt_minor_dev_class_av;
extern std::unordered_map<unsigned int, const char *> bt_minor_dev_class_peripheral;
extern std::unordered_map<unsigned int, const char *> bt_minor_dev_type_peripheral;
extern std::unordered_map<unsigned int, const char *> bt_minor_dev_class_wearable;
extern std::unordered_map<unsigned int, const char *> bt_minor_dev_class_toy;
extern std::unordered_map<unsigned int, const char *> bt_minor_dev_class_health;
extern std::unordered_map<unsigned int, const char *> bt_appearance;
extern std::unordered_map<unsigned int, const char *> bt_io_capability;

#endif

