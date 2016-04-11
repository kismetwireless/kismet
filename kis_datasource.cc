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
#include "endian_magic.h"

#ifdef HAVE_LIBPCRE
#include <pcre.h>
#endif

KisDataSource::KisDataSource(GlobalRegistry *in_globalreg) :
    tracker_component(in_globalreg, 0) {
    globalreg = in_globalreg;

    register_fields();
    reserve_fields(NULL);
}

KisDataSource::~KisDataSource() {

}

void KisDataSource::register_fields() {
    source_name_id =
        RegisterField("kismet.datasource.source_name", TrackerString,
                "Human name of data source", (void **) &source_name);
    source_interface_id =
        RegisterField("kismet.datasource.source_interface", TrackerString,
                "Primary capture interface", (void **) &source_interface);
    source_uuid_id =
        RegisterField("kismet.datasource.source_uuid", TrackerUuid,
                "UUID", (void **) &source_uuid);
    source_id_id =
        RegisterField("kismet.datasource.source_id", TrackerInt32,
                "Run-time ID", (void **) &source_id);
    source_channel_capable_id =
        RegisterField("kismet.datasource.source_channel_capable", TrackerUInt8,
                "(bool) source capable of channel change", 
                (void **) &source_channel_capable);
    child_pid_id =
        RegisterField("kismet.datasource.child_pid", TrackerInt64,
                "PID of data capture process", (void **) &child_pid);
    source_definition_id =
        RegisterField("kismet.datasource.definition", TrackerString,
                "original source definition", (void **) &source_definition);
}

void KisDataSource::BufferAvailable(size_t in_amt) {
    simple_cap_proto_t *frame_header;
    uint8_t *buf;
    uint32_t frame_sz;
    uint32_t frame_checksum, calc_checksum;

    if (in_amt < sizeof(simple_cap_proto_t)) {
        return;
    }

    // Peek the buffer
    buf = new uint8_t[in_amt];
    ipchandler->PeekReadBufferData(buf, in_amt);

    frame_header = (simple_cap_proto_t *) buf;

    if (kis_ntoh32(frame_header->signature) != KIS_CAP_SIMPLE_PROTO_SIG) {
        // TODO kill connection or seek for valid
        delete[] buf;
        return;
    }

    frame_sz = kis_ntoh32(frame_header->packet_sz);

    if (frame_sz > in_amt) {
        // Nothing we can do right now, not enough data to make up a
        // complete packet.
        delete[] buf;
        return;
    }

    // Get the checksum
    frame_checksum = kis_ntoh32(frame_header->checksum);

    // Zero the checksum field in the packet
    frame_header->checksum = 0x00000000;

    // Calc the checksum of the rest
    calc_checksum = Adler32Checksum((const char *) buf, frame_sz);

    if (calc_checksum != frame_checksum) {
        // TODO report invalid checksum and disconnect
        delete[] buf;
        return;
    }

    // Consume the packet in the ringbuf 
    ipchandler->GetReadBufferData(NULL, frame_sz);

    // Extract the kv pairs
    vector<KisDataSource_CapKeyedObject *> kv_vec;

    ssize_t data_offt = 0;
    for (unsigned int kvn = 0; kvn < kis_ntoh32(frame_header->num_kv_pairs); kvn++) {
        simple_cap_proto_kv *pkv =
            (simple_cap_proto_kv *) &((frame_header->data)[data_offt]);

        data_offt = 
            sizeof(simple_cap_proto_kv_h_t) +
            kis_ntoh32(pkv->header.obj_sz);

        KisDataSource_CapKeyedObject *kv =
            new KisDataSource_CapKeyedObject(pkv);

        kv_vec.push_back(kv);
    }

    char ctype[17];
    snprintf(ctype, 17, "%s", frame_header->type);
    HandlePacket(ctype, kv_vec);

    for (unsigned int x = 0; x < kv_vec.size(); x++) {
        delete(kv_vec[x]);
    }

    delete[] buf;

}

void KisDataSource::HandlePacket(string in_type,
        vector<KisDataSource_CapKeyedObject *> in_kvpairs) {

}

KisDataSource_CapKeyedObject::KisDataSource_CapKeyedObject(simple_cap_proto_kv *in_kp) {
    char ckey[17];

    snprintf(ckey, 17, "%s", in_kp->header.key);
    key = string(ckey);

    size = kis_ntoh32(in_kp->header.obj_sz);
    object = new uint8_t[size];
    memcpy(object, in_kp->object, size);
}

KisDataSource_CapKeyedObject::~KisDataSource_CapKeyedObject() {
    delete[] object;
}

