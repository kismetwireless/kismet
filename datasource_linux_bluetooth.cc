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

#include "kis_datasource.h"
#include "simple_datasource_proto.h"
#include "datasource_linux_bluetooth.h"
#include "phy_bluetooth.h"
#include "msgpack_adapter.h"

KisDatasourceLinuxBluetooth::KisDatasourceLinuxBluetooth(GlobalRegistry *in_globalreg, 
        SharedDatasourceBuilder in_builder) : KisDatasource(in_globalreg, in_builder) {
    // Set the capture binary
    set_int_source_ipc_binary("kismet_cap_linux_bluetooth");

    pack_comp_btdevice = packetchain->RegisterPacketComponent("BTDEVICE");
}

void KisDatasourceLinuxBluetooth::proto_dispatch_packet(string in_type, KVmap in_kvmap) {
    local_locker lock(&source_lock);

    KisDatasource::proto_dispatch_packet(in_type, in_kvmap);

    string ltype = StrLower(in_type);

    if (ltype == "linuxbtdevice") {
        proto_packet_linuxbtdevice(in_kvmap);
    }
}

void KisDatasourceLinuxBluetooth::proto_packet_linuxbtdevice(KVmap in_kvpairs) {
    KVmap::iterator i;

    kis_packet *packet = NULL;
    kis_layer1_packinfo *siginfo = NULL;
    kis_gps_packinfo *gpsinfo = NULL;

    if ((i = in_kvpairs.find("message")) != in_kvpairs.end()) {
        handle_kv_message(i->second);
    }

    if ((i = in_kvpairs.find("warning")) != in_kvpairs.end()) {
        handle_kv_warning(i->second);
    }

    if ((i = in_kvpairs.find("btdevice")) != in_kvpairs.end()) {
        packet = handle_kv_btdevice(i->second);
    }

    if (packet == NULL)
        return;

    // Gather signal data
    if ((i = in_kvpairs.find("signal")) != in_kvpairs.end()) {
        siginfo = handle_kv_signal(i->second);
    }

    // Gather GPS data
    if ((i = in_kvpairs.find("gps")) != in_kvpairs.end()) {
        gpsinfo = handle_kv_gps(i->second);
    }

    // Add them to the packet
    if (siginfo != NULL) {
        packet->insert(pack_comp_l1info, siginfo);
    }

    if (gpsinfo != NULL) {
        packet->insert(pack_comp_gps, gpsinfo);
    }
    
    packetchain_comp_datasource *datasrcinfo = new packetchain_comp_datasource();
    datasrcinfo->ref_source = this;

    packet->insert(pack_comp_datasrc, datasrcinfo);

    inc_source_num_packets(1);
    get_source_packet_rrd()->add_sample(1, time(0));

    // Inject the packet into the packetchain if we have one
    packetchain->ProcessPacket(packet);
}

kis_packet *
    KisDatasourceLinuxBluetooth::handle_kv_btdevice(KisDatasourceCapKeyedObject *in_obj) {

    kis_packet *packet = packetchain->GeneratePacket();

    MsgpackAdapter::MsgpackStrMap dict;
    msgpack::unpacked result;
    MsgpackAdapter::MsgpackStrMap::iterator obj_iter;
    vector<string> uuid_str_vec;

    bluetooth_packinfo *bpi = new bluetooth_packinfo();

    try {
        msgpack::unpack(result, in_obj->object, in_obj->size);
        msgpack::object deserialized = result.get();

        dict = deserialized.as<MsgpackAdapter::MsgpackStrMap>();

        if (clobber_timestamp && get_source_remote()) {
            gettimeofday(&(packet->ts), NULL);
        } else {
            if ((obj_iter = dict.find("tv_sec")) != dict.end()) {
                packet->ts.tv_sec = (time_t) obj_iter->second.as<uint64_t>();
            } else {
                throw std::runtime_error(string("tv_sec timestamp missing"));
            }

            if ((obj_iter = dict.find("tv_usec")) != dict.end()) {
                packet->ts.tv_usec = (time_t) obj_iter->second.as<uint64_t>();
            } else {
                throw std::runtime_error(string("tv_usec timestamp missing"));
            }
        }

        if ((obj_iter = dict.find("address")) != dict.end()) {
            mac_addr m(obj_iter->second.as<string>());

            if (m.error)
                throw std::runtime_error(string("invalid mac address for btdevice"));

            bpi->address = m;
        } else {
            throw std::runtime_error(string("address missing from bt device"));
        }

        if ((obj_iter = dict.find("name")) != dict.end()) {
            bpi->name = obj_iter->second.as<string>();
        }

        if ((obj_iter = dict.find("txpower")) != dict.end()) {
            bpi->txpower = obj_iter->second.as<int>();
        } else {
            // Spec says -127 - 127 so -256 is out of bounds
            bpi->txpower = -256;
        }

        /* Optional uuid vector */
        if ((obj_iter = dict.find("uuid_vec")) != dict.end()) {
            MsgpackAdapter::AsStringVector(obj_iter->second, uuid_str_vec);

            for (auto u : uuid_str_vec) {
                uuid ui(u);

                if (ui.error) {
                    throw std::runtime_error(string("invalid uuid in service vec from "
                                "bt device"));
                }

                bpi->service_uuid_vec.push_back(ui);
            }
        }
    } catch (const std::exception& e) {
        packetchain->DestroyPacket(packet);
        delete(bpi);

        stringstream ss;
        ss << "failed to unpack btdevice bundle: " << e.what();
        trigger_error(ss.str());
        
        return NULL;
    }

    packet->insert(pack_comp_btdevice, bpi);

    return packet;
}

