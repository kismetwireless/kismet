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

void MsgpackAdapter::Packer(GlobalRegistry *globalreg, SharedTrackerElement v,
        msgpack::packer<std::stringstream> &o,
        TrackerElementSerializer::rename_map *name_map) {

    if (v == NULL) {
        o.pack_array(2);
        o.pack((int) TrackerUInt8);
        o.pack((uint8_t) 0);
        return;
    }

    // If we have a rename map, find out if we've got a pathed element that needs
    // to be custom-serialized
    if (name_map != NULL) {
        TrackerElementSerializer::rename_map::iterator nmi = name_map->find(v);
        if (nmi != name_map->end()) {
            TrackerElementSerializer::pre_serialize_path(nmi->second);
        } else {
            v->pre_serialize();
        } 
    } else {
        v->pre_serialize();
    }

    o.pack_array(2);
    o.pack((int) v->get_type());

    TrackerElement::tracked_vector *tvec;
    unsigned int x;

    TrackerElement::tracked_map *tmap;
    TrackerElement::map_iterator map_iter;

    TrackerElement::tracked_int_map *tintmap;
    TrackerElement::int_map_iterator int_map_iter;

    TrackerElement::tracked_mac_map *tmacmap;
    TrackerElement::mac_map_iterator mac_map_iter;

    TrackerElement::tracked_string_map *tstringmap;
    TrackerElement::string_map_iterator string_map_iter;

    TrackerElement::tracked_double_map *tdoublemap;
    TrackerElement::double_map_iterator double_map_iter;

    mac_addr mac;

    shared_ptr<uint8_t> bytes;
    size_t sz;

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
            mac = GetTrackerValue<mac_addr>(v);
            o.pack_array(2);
            o.pack(mac.Mac2String());
            o.pack(mac.MacMask2String());
            break;
        case TrackerUuid:
            o.pack(GetTrackerValue<uuid>(v).UUID2String());
            break;
        case TrackerVector:
            // o.pack(*(v->get_vector()));
            tvec = v->get_vector();

            o.pack_array(v->size());
            for (x = 0; x < tvec->size(); x++) {
                Packer(globalreg, (*tvec)[x], o, name_map);
            }

            break;
        case TrackerMap:
            tmap = v->get_map();
            o.pack_map(tmap->size());
            for (map_iter = tmap->begin(); map_iter != tmap->end(); ++map_iter) {
                TrackerElementSerializer::rename_map::iterator nmi;
                if (name_map != NULL &&
                        (nmi = name_map->find(map_iter->second)) != name_map->end() &&
                        nmi->second->rename.length() != 0) {
                    o.pack(nmi->second->rename);
                } else {
                    string tname;
                    if (map_iter->second != NULL &&
                            (tname = map_iter->second->get_local_name()) != "")
                        o.pack(tname);
                    else
                        o.pack(globalreg->entrytracker->GetFieldName(map_iter->first));
                }

                Packer(globalreg, map_iter->second, o, name_map);
            }
            break;
        case TrackerIntMap:
            tintmap = v->get_intmap();
            o.pack_map(tintmap->size());
            for (int_map_iter = tintmap->begin(); int_map_iter != tintmap->end(); 
                    ++int_map_iter) {
                o.pack(int_map_iter->first);
                Packer(globalreg, int_map_iter->second, o, name_map);
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
                Packer(globalreg, mac_map_iter->second, o, name_map);
            }
            break;
        case TrackerStringMap:
            tstringmap = v->get_stringmap();
            o.pack_map(tstringmap->size());
            for (string_map_iter = tstringmap->begin();
                    string_map_iter != tstringmap->end();
                    ++string_map_iter) {
                o.pack(string_map_iter->first);
                Packer(globalreg, string_map_iter->second, o, name_map);
            }
            break;
        case TrackerDoubleMap:
            tdoublemap = v->get_doublemap();
            o.pack_map(tdoublemap->size());
            for (double_map_iter = tdoublemap->begin();
                    double_map_iter != tdoublemap->end();
                    ++double_map_iter) {
                o.pack(double_map_iter->first);
                Packer(globalreg, double_map_iter->second, o, name_map);
            }
            break;
        case TrackerByteArray:
            bytes = v->get_bytearray();
            sz = v->get_bytearray_size();

            o.pack_bin(sz);
            o.pack_bin_body((const char *) bytes.get(), sz);

            break;

        default:
            break;
    }
}

void MsgpackAdapter::Pack(GlobalRegistry *globalreg, std::stringstream &stream,
        SharedTrackerElement e, TrackerElementSerializer::rename_map *name_map) {
    msgpack::packer<std::stringstream> packer(&stream);
    Packer(globalreg, e, packer, name_map);
}

void MsgpackAdapter::AsStringVector(msgpack::object &obj, 
        std::vector<std::string> &vec) {
    if (obj.type != msgpack::type::ARRAY)
        throw msgpack::type_error();

    for (unsigned int i = 0; i < obj.via.array.size; i++)
        vec.push_back(obj.via.array.ptr[i].as<string>());
}


