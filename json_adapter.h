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
#include "json_adapter.h"

namespace JsonAdapter {

void Pack(GlobalRegistry *globalreg, std::stringstream &stream, TrackerElement *e);

void Pack(GlobalRegistry *globalreg, std::stringstream &stream, tracker_component *c);

string SanitizeString(string in);

class Serializer : public TrackerElementSerializer {
public:
    Serializer(GlobalRegistry *in_globalreg, std::stringstream &in_stream) : 
        TrackerElementSerializer(in_globalreg, in_stream) { }

    virtual void serialize(TrackerElement *in_elem) {
        Pack(globalreg, stream, in_elem);
    }
};

}

#endif
