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

#ifndef __JSON_ADAPTER_H__
#define __JSON_ADAPTER_H__

#include "config.h"

#include "globalregistry.h"
#include "trackedelement.h"
#include "devicetracker_component.h"

// Standard JSON serialization adapter; will form complete JSON objects out
// of the input objects.  Best connected to a chainbuf output stream via a
// BufferHandlerOStreambuf or similar
namespace JsonAdapter {

void Pack(GlobalRegistry *globalreg, std::ostream &stream, SharedTrackerElement e,
        TrackerElementSerializer::rename_map *name_map = NULL);

string SanitizeString(string in);

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

}

// "ELK-style" JSON adapter.  This will behave the same as the normal JSON
// serializer with one important difference:  If the top-level object *is a vector
// type*, it will serialize each member of the vector independently as a complete
// JSON object separated by newlines.  This allows for a 'streamed' JSON output
// which will not require loading the entire object into RAM
namespace EkJsonAdapter {

string SanitizeString(string in);

class Serializer : public TrackerElementSerializer {
public:
    Serializer(GlobalRegistry *in_globalreg) :
        TrackerElementSerializer(in_globalreg) { }

    virtual void serialize(SharedTrackerElement in_elem, std::ostream &stream,
            rename_map *name_map = NULL) {
        local_locker lock(&mutex);

        if (in_elem->get_type() == TrackerVector) {
            TrackerElementVector v(in_elem);

            for (auto i : v) {
                JsonAdapter::Pack(globalreg, stream, i, name_map);
                stream << "\n";
            }
        } else {
            JsonAdapter::Pack(globalreg, stream, in_elem, name_map);
        }
    }
};

}


#endif
