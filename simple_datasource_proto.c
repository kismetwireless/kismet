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

#include "util.h"

#include <stdio.h>
#include <string.h>
#include <msgpack.h>

#include "simple_datasource_proto.h"
#include "endian_magic.h"

simple_cap_proto_kv_t *encode_simple_cap_proto_kv(char *in_key, uint8_t *in_obj,
        unsigned int in_obj_len) {
    simple_cap_proto_kv_t *kv;

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + in_obj_len);
    if (kv == NULL)
        return NULL;

    snprintf(kv->key, 16, "%16s", in_key);
    kv->obj_sz = kis_hton32(in_obj_len);

    memcpy(kv->object, in_obj, in_obj_len);

    return kv;
}

simple_cap_proto_t *encode_simple_cap_proto(char *in_type,
        simple_cap_proto_kv_t **in_kv_list, unsigned int in_kv_len) {
    simple_cap_proto_t *cp;
    simple_cap_proto_kv_t *kv;
    unsigned int x;
    size_t sz = sizeof(simple_cap_proto_t);
    size_t offt = 0;
    uint32_t csum;

    for (x = 0; x < in_kv_len; x++) {
        kv = in_kv_list[x];
        sz += sizeof(simple_cap_proto_t) + kv->obj_sz;
    }

    cp = (simple_cap_proto_t *) malloc(sz);

    if (cp == NULL)
        return NULL;

    cp->signature = kis_hton32(KIS_CAP_SIMPLE_PROTO_SIG);
    cp->checksum = 0;
    snprintf(cp->type, 16, "%16s", in_type);
    cp->packet_sz = kis_hton32((uint32_t) sz);
    cp->num_kv_pairs = kis_hton32(in_kv_len);

    for (x = 0; x < in_kv_len; x++) {
        kv = in_kv_list[x];
        memcpy(cp->data + offt, kv, sizeof(simple_cap_proto_kv_t) + kv->obj_sz);
        offt += sizeof(simple_cap_proto_kv_t) + kv->obj_sz;
    }

    csum = Adler32Checksum((const char *) cp, sz);
    cp->checksum = kis_hton32(csum);

    return cp;
}

int pack_packet_capdata(uint8_t **ret_buffer, uint32_t *ret_sz,
        struct timeval in_ts, int in_dlt, uint32_t in_pack_sz, uint8_t *in_pack) {
    char key[16];
    msgpack_sbuffer sbuf;
    msgpack_packer pk;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&pk, 5);

    snprintf(key, 16, "tv_sec");
    msgpack_pack_str(&pk, strlen(key));
    msgpack_pack_str_body(&pk, key, strlen(key));
    msgpack_pack_uint64(&pk, in_ts.tv_sec);

    snprintf(key, 16, "tv_usec");
    msgpack_pack_str(&pk, strlen(key));
    msgpack_pack_str_body(&pk, key, strlen(key));
    msgpack_pack_uint64(&pk, in_ts.tv_usec);

    snprintf(key, 16, "dlt");
    msgpack_pack_str(&pk, strlen(key));
    msgpack_pack_str_body(&pk, key, strlen(key));
    msgpack_pack_uint64(&pk, in_dlt);

    snprintf(key, 16, "pack_sz");
    msgpack_pack_str(&pk, strlen(key));
    msgpack_pack_str_body(&pk, key, strlen(key));
    msgpack_pack_uint32(&pk, in_pack_sz);

    snprintf(key, 16, "packet");
    msgpack_pack_str(&pk, strlen(key));
    msgpack_pack_str_body(&pk, key, strlen(key));
    msgpack_pack_bin(&pk, in_pack_sz);
    msgpack_pack_bin_body(&pk, in_pack, in_pack_sz);

    *ret_buffer = (uint8_t *) malloc(sbuf.size);

    if (*ret_buffer == NULL) {
        msgpack_sbuffer_destroy(&sbuf);
        return -1;
    }

    memcpy(*ret_buffer, sbuf.data, sbuf.size);
    *ret_sz = sbuf.size;

    msgpack_sbuffer_destroy(&sbuf);

    return 1;
}

int pack_packet_gps(uint8_t **ret_buffer, uint32_t *ret_sz,
        double in_lat, double in_lon, double in_alt, double in_speed, double in_heading,
        double in_precision, int in_fix, time_t in_time, 
        char *in_gps_type, char *in_gps_name) {
    char key[16];
    msgpack_sbuffer sbuf;
    msgpack_packer pk;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&pk, 5);

    snprintf(key, 16, "lat");
    msgpack_pack_str(&pk, strlen(key));
    msgpack_pack_str_body(&pk, key, strlen(key));
    msgpack_pack_double(&pk, in_lat);

    snprintf(key, 16, "lon");
    msgpack_pack_str(&pk, strlen(key));
    msgpack_pack_str_body(&pk, key, strlen(key));
    msgpack_pack_double(&pk, in_lon);

    snprintf(key, 16, "alt");
    msgpack_pack_str(&pk, strlen(key));
    msgpack_pack_str_body(&pk, key, strlen(key));
    msgpack_pack_double(&pk, in_alt);

    snprintf(key, 16, "speed");
    msgpack_pack_str(&pk, strlen(key));
    msgpack_pack_str_body(&pk, key, strlen(key));
    msgpack_pack_double(&pk, in_speed);

    snprintf(key, 16, "heading");
    msgpack_pack_str(&pk, strlen(key));
    msgpack_pack_str_body(&pk, key, strlen(key));
    msgpack_pack_double(&pk, in_heading);

    snprintf(key, 16, "precision");
    msgpack_pack_str(&pk, strlen(key));
    msgpack_pack_str_body(&pk, key, strlen(key));
    msgpack_pack_double(&pk, in_precision);

    snprintf(key, 16, "fix");
    msgpack_pack_str(&pk, strlen(key));
    msgpack_pack_str_body(&pk, key, strlen(key));
    msgpack_pack_int32(&pk, in_fix);

    snprintf(key, 16, "time");
    msgpack_pack_str(&pk, strlen(key));
    msgpack_pack_str_body(&pk, key, strlen(key));
    msgpack_pack_uint64(&pk, in_time);

    snprintf(key, 16, "type");
    msgpack_pack_str(&pk, strlen(key));
    msgpack_pack_str_body(&pk, key, strlen(key));
    msgpack_pack_str(&pk, strlen(in_gps_type));
    msgpack_pack_str_body(&pk, in_gps_type, strlen(in_gps_type));

    snprintf(key, 16, "name");
    msgpack_pack_str(&pk, strlen(key));
    msgpack_pack_str_body(&pk, key, strlen(key));
    msgpack_pack_str(&pk, strlen(in_gps_name));
    msgpack_pack_str_body(&pk, in_gps_name, strlen(in_gps_name));

    *ret_buffer = (uint8_t *) malloc(sbuf.size);

    if (*ret_buffer == NULL) {
        msgpack_sbuffer_destroy(&sbuf);
        return -1;
    }

    memcpy(*ret_buffer, sbuf.data, sbuf.size);
    *ret_sz = sbuf.size;

    msgpack_sbuffer_destroy(&sbuf);

    return 1;
}

