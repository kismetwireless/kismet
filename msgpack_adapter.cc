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
#include "macaddr.h"
#include "entrytracker.h"
#include "uuid.h"
#include "devicetracker_component.h"
#include "msgpack_adapter.h"

namespace msgpack {
MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
namespace adaptor {

EntryTracker *entrytracker;

template<>
    struct pack<mac_addr> {
        template <typename Stream>
            packer<Stream>& operator()(msgpack::packer<Stream>& o, 
                    mac_addr const& v) const {
                o.pack_array(2);
                o.pack(v.Mac2String());
                o.pack(v.MacMask2String());
                return o;
            }
    };

template<>
    struct pack<TrackerElement *> {
        template <typename Stream>
            packer<Stream>& operator()(msgpack::packer<Stream>& o, 
                    TrackerElement * const& v) const {
                o.pack_array(2);

                o.pack((int) v->get_type());

                v->pre_serialize();

                TrackerElement::tracked_map *tmap;
                TrackerElement::map_iterator map_iter;

                TrackerElement::tracked_mac_map *tmacmap;
                TrackerElement::mac_map_iterator mac_map_iter;

                switch (v->get_type()) {
                    case TrackerString:
                        o.pack(GetTrackerValue<string>(v));
                        break;
                    case TrackerInt8:
                        o.pack(GetTrackerValue<int8_t>(v));
                        break;
                    case TrackerUInt8:
                        o.pack(GetTrackerValue<uint8_t>(v));
                        break;
                    case TrackerInt16:
                        o.pack(GetTrackerValue<int16_t>(v));
                        break;
                    case TrackerUInt16:
                        o.pack(GetTrackerValue<uint16_t>(v));
                        break;
                    case TrackerInt32:
                        o.pack(GetTrackerValue<int32_t>(v));
                        break;
                    case TrackerUInt32:
                        o.pack(GetTrackerValue<uint32_t>(v));
                        break;
                    case TrackerInt64:
                        o.pack(GetTrackerValue<int64_t>(v));
                        break;
                    case TrackerUInt64:
                        o.pack(GetTrackerValue<uint64_t>(v));
                        break;
                    case TrackerFloat:
                        o.pack(GetTrackerValue<float>(v));
                        break;
                    case TrackerDouble:
                        o.pack(GetTrackerValue<double>(v));
                        break;
                    case TrackerMac:
                        o.pack(GetTrackerValue<mac_addr>(v));
                        break;
                    case TrackerUuid:
                        o.pack(GetTrackerValue<uuid>(v).UUID2String());
                        break;
                    case TrackerVector:
                        o.pack(*(v->get_vector()));
                        break;
                    case TrackerMap:
                        tmap = v->get_map();
                        o.pack_map(tmap->size());
                        for (map_iter = tmap->begin(); map_iter != tmap->end(); 
                                ++map_iter) {
                            o.pack(entrytracker->GetFieldName(map_iter->first));
                            o.pack(map_iter->second);

                        }
                        break;
                    case TrackerIntMap:
                        tmap = v->get_intmap();
                        o.pack_map(tmap->size());
                        for (map_iter = tmap->begin(); map_iter != tmap->end(); 
                                ++map_iter) {
                            o.pack(map_iter->first);
                            o.pack(map_iter->second);

                        }
                        break;
                    case TrackerMacMap:
                        tmacmap = v->get_macmap();
                        o.pack_map(tmacmap->size());
                        for (mac_map_iter = tmacmap->begin(); 
                                mac_map_iter != tmacmap->end();
                                ++mac_map_iter) {
                            // Macmaps need to go out as just the mac string,
                            // not a vector of mac+mask
                            o.pack(mac_map_iter->first.MacFull2String());
                            o.pack(mac_map_iter->second);
                        }

                    default:
                        break;
                }

                return o;
            }
    };

}
}
}

void MsgpackAdapter::Pack(GlobalRegistry *globalreg, std::stringstream &stream,
        tracker_component *c) {
    msgpack::adaptor::entrytracker = globalreg->entrytracker; 
    msgpack::pack(stream, (TrackerElement *) c);
}

void MsgpackAdapter::Pack(GlobalRegistry *globalreg, std::stringstream &stream,
        TrackerElement *e) {
    msgpack::adaptor::entrytracker = globalreg->entrytracker; 
    msgpack::pack(stream, e);
}


