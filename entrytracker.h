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

#ifndef __ENTRYTRACKER_H__
#define __ENTRYTRACKER_H__

#include "config.h"

#include <stdio.h>
#include <stdint.h>

#include <string>
#include <map>

#include "trackedelement.h"

#define __EntryLocation()     EntryTracker::GenerateLocationString(__FILE__, __LINE__, __func__)

// Allocate and track named fields and give each one a custom int
class EntryTracker {
public:
    EntryTracker();

    // Reserve a field name.  Field names are plain strings, which can
    // be used to derive namespaces later.
    // Return: Registered field number, or negative on error such as field exists
    int RegisterField(string in_name, TrackerType in_type,
                      string in_desc, string in_location);

    // Reserve a field name, and return an instance.  If the field ALREADY EXISTS, return
    // an instance.
    TrackerElement *RegisterAndGetField(string in_name, TrackerType in_type,
                                        string in_desc, string in_location);

    // Reserve a field name, include a builder instance of the field
    int RegisterField(string in_name, TrackerElement *in_builder, 
                      string in_desc, string in_location);
    
    // Reserve a field name, and return an instance.  If the field ALREADY EXISTS, return
    // an instance.
    TrackerElement *RegisterAndGetField(string in_name, TrackerElement *in_builder,
                                        string in_desc, string in_location);

    int GetFieldId(string in_name);

    // Get a field instance
    // Return: NULL if unknown
    TrackerElement *GetTrackedInstance(string in_name);
    TrackerElement *GetTrackedInstance(int in_id);

    static string GenerateLocationString(const char *in_file, const int in_line, const char *in_func);

protected:
    int next_field_num;

    struct reserved_field {
        // ID we assigned
        int field_id;

        // How we create it
        string field_name;
        TrackerType track_type;

        // Or a builder instance
        TrackerElement *builder;

        // Might as well track this for auto-doc
        string field_description;
        string field_location;
    };

    map<string, reserved_field *> field_name_map;
    map<int, reserved_field *> field_id_map;

};

#endif
