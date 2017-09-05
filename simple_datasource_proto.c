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

#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include "simple_datasource_proto.h"

// Use alternate simpler msgpack library, msgpuck
#include "msgpuck.h"
// And use our resizing buffer code
#include "msgpuck_buffer.h"

uint32_t adler32_partial_csum(uint8_t *in_buf, size_t in_len,
        uint32_t *s1, uint32_t *s2) {
	size_t i;
	uint8_t *buf = in_buf;
	int CHAR_OFFSET = 0;

    if (in_len < 4)
        return 0;

    for (i = 0; i < (in_len - 4); i += 4) {
        *s2 += 4 * (*s1 + buf[i]) + 3 * buf[i + 1] + 2 * buf[i+2] + buf[i + 3] + 
            10 * CHAR_OFFSET;
        *s1 += (buf[i + 0] + buf[i + 1] + buf[i + 2] + buf[i + 3] + 4 * CHAR_OFFSET); 
	}

    for (; i < in_len; i++) {
        *s1 += (buf[i] + CHAR_OFFSET); 
        *s2 += *s1;
	}

	return (*s1 & 0xffff) + (*s2 << 16);
}

uint32_t adler32_csum(uint8_t *in_buf, size_t in_len) {
    uint32_t s1, s2;

    s1 = 0;
    s2 = 0;

    return adler32_partial_csum(in_buf, in_len, &s1, &s2);
}

simple_cap_proto_kv_t *encode_simple_cap_proto_kv(const char *in_key, uint8_t *in_obj,
        size_t in_obj_len) {
    simple_cap_proto_kv_t *kv;

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + in_obj_len);
    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%.16s", in_key);
    kv->header.obj_sz = htonl(in_obj_len);

    memcpy(kv->object, in_obj, in_obj_len);

    return kv;
}

simple_cap_proto_frame_t *encode_simple_cap_proto(const char *in_type, uint32_t in_seqno,
        simple_cap_proto_kv_t **in_kv_list, unsigned int in_kv_len) {
    simple_cap_proto_frame_t *cp;
    simple_cap_proto_kv_t *kv;
    unsigned int x;
    size_t sz = sizeof(simple_cap_proto_t);
    size_t offt = 0;
    uint32_t hcsum, dcsum;

    for (x = 0; x < in_kv_len; x++) {
        kv = in_kv_list[x];
        sz += sizeof(simple_cap_proto_frame_t) + ntohl(kv->header.obj_sz);
    }

    cp = (simple_cap_proto_frame_t *) malloc(sz);

    if (cp == NULL)
        return NULL;

    cp->header.signature = htonl(KIS_CAP_SIMPLE_PROTO_SIG);
    cp->header.header_checksum = 0;
    cp->header.data_checksum = 0;
    cp->header.sequence_number = htonl(in_seqno);
    snprintf(cp->header.type, 16, "%.16s", in_type);
    cp->header.packet_sz = htonl((uint32_t) sz);
    cp->header.num_kv_pairs = htonl(in_kv_len);

    for (x = 0; x < in_kv_len; x++) {
        kv = in_kv_list[x];
        memcpy(cp->data + offt, kv, sizeof(simple_cap_proto_kv_t) + 
                ntohl(kv->header.obj_sz));
        offt += sizeof(simple_cap_proto_kv_t) + ntohl(kv->header.obj_sz);
    }

    hcsum = adler32_csum((uint8_t *) cp, sizeof(simple_cap_proto_t));
    dcsum = adler32_csum((uint8_t *) cp, sz);
    cp->header.header_checksum = htonl(hcsum);
    cp->header.data_checksum = htonl(dcsum);

    return cp;
}

simple_cap_proto_t *encode_simple_cap_proto_hdr(size_t *ret_sz, 
        const char *in_type, uint32_t in_seqno,
        simple_cap_proto_kv_t **in_kv_list, unsigned int in_kv_len) {
    simple_cap_proto_t *cp;
    simple_cap_proto_kv_t *kv;
    unsigned int x;
    size_t sz = sizeof(simple_cap_proto_t);

    uint32_t hcsum, dcsum;
    uint32_t csum_s1 = 0;
    uint32_t csum_s2 = 0;

    /* measure the size */
    for (x = 0; x < in_kv_len; x++) {
        kv = in_kv_list[x];
        sz += sizeof(simple_cap_proto_kv_t) + ntohl(kv->header.obj_sz);
    }

    /* allocate just the header */
    cp = (simple_cap_proto_t *) malloc(sizeof(simple_cap_proto_t));

    if (cp == NULL)
        return NULL;

    cp->signature = htonl(KIS_CAP_SIMPLE_PROTO_SIG);
    cp->header_checksum = 0;
    cp->data_checksum = 0;
    cp->sequence_number = htonl(in_seqno);
    snprintf(cp->type, 16, "%.16s", in_type);
    cp->packet_sz = htonl((uint32_t) sz);
    cp->num_kv_pairs = htonl(in_kv_len);

    /* calculate the incremental checksum; first we calc the header and save
     * it as the header-only cssum */
    hcsum = adler32_partial_csum((uint8_t *) cp, 
            sizeof(simple_cap_proto_t), &csum_s1, &csum_s2);

    /* Then add the checksum of the KVs */
    for (x = 0; x < in_kv_len; x++) {
        kv = in_kv_list[x];
        dcsum = adler32_partial_csum((uint8_t *) kv, 
                sizeof(simple_cap_proto_kv_t) + ntohl(kv->header.obj_sz), 
                &csum_s1, &csum_s2);
    } 
    
    if (in_kv_len == 0) {
        dcsum = hcsum;
    }

    /* Set the total checksums */
    cp->header_checksum = htonl(hcsum);
    cp->data_checksum = htonl(dcsum);

    *ret_sz = sz;

    return cp;
}

simple_cap_proto_kv_t *encode_kv_success(unsigned int success, uint32_t sequence) {
    simple_cap_proto_kv_t *kv;

    size_t content_sz = sizeof(simple_cap_proto_success_t);

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + content_sz);

    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%.16s", "SUCCESS");
    kv->header.obj_sz = htonl(content_sz);

    ((simple_cap_proto_success_t *) kv->object)->success = success;
    ((simple_cap_proto_success_t *) kv->object)->sequence_number = htonl(sequence);

    return kv;
}

simple_cap_proto_kv_t *encode_kv_dlt(unsigned int dlt) {
    simple_cap_proto_kv_t *kv;

    size_t content_sz = sizeof(uint32_t);

    uint32_t conv_dlt = htonl((uint32_t) dlt);

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + content_sz);

    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%.16s", "DLT");
    kv->header.obj_sz = htonl(content_sz);

    memcpy(kv->object, &conv_dlt, sizeof(uint32_t));

    return kv;
}

simple_cap_proto_kv_t *encode_kv_chanset(const char *channel) {
    simple_cap_proto_kv_t *kv;

    size_t content_sz = strlen(channel);

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + content_sz);

    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%.16s", "CHANSET");
    kv->header.obj_sz = htonl(content_sz);

    memcpy(&(kv->object), channel, content_sz);

    return kv;
}

simple_cap_proto_kv_t *encode_kv_uuid(const char *uuid) {
    simple_cap_proto_kv_t *kv;

    size_t content_sz = strlen(uuid);

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + content_sz);

    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%.16s", "UUID");
    kv->header.obj_sz = htonl(content_sz);

    memcpy(&(kv->object), uuid, content_sz);

    return kv;
}

simple_cap_proto_kv_t *encode_kv_capif(const char *capif) {
    simple_cap_proto_kv_t *kv;

    size_t content_sz = strlen(capif);

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + content_sz);

    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%.16s", "CAPIF");
    kv->header.obj_sz = htonl(content_sz);

    memcpy(&(kv->object), capif, content_sz);

    return kv;
}

simple_cap_proto_kv_t *encode_kv_capdata(struct timeval in_ts, 
        uint32_t in_pack_sz, uint8_t *in_pack) {

    const char *key_tv_sec = "tv_sec";
    const char *key_tv_usec = "tv_usec";
    const char *key_pack_sz = "size";
    const char *key_packet = "packet";

    msgpuck_buffer_t *puckbuffer;

    simple_cap_proto_kv_t *kv;
    size_t content_sz;

    // Allocate a fairly generous headroom in our buffer
    puckbuffer = mp_b_create_buffer(in_pack_sz + 256);

    if (puckbuffer == NULL) {
        return NULL;
    }

    mp_b_encode_map(puckbuffer, 4);

    mp_b_encode_str(puckbuffer, key_tv_sec, strlen(key_tv_sec));
    mp_b_encode_uint(puckbuffer, in_ts.tv_sec);

    mp_b_encode_str(puckbuffer, key_tv_usec, strlen(key_tv_usec));
    mp_b_encode_uint(puckbuffer, in_ts.tv_usec);

    mp_b_encode_str(puckbuffer, key_pack_sz, strlen(key_pack_sz));
    mp_b_encode_uint(puckbuffer, in_pack_sz);

    mp_b_encode_str(puckbuffer, key_packet, strlen(key_packet));
    mp_b_encode_bin(puckbuffer, (const char *) in_pack, in_pack_sz);

    content_sz = mp_b_used_buffer(puckbuffer);

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + content_sz);

    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%.16s", "PACKET");
    kv->header.obj_sz = htonl(content_sz);

    memcpy(kv->object, mp_b_get_buffer(puckbuffer), content_sz);

    mp_b_free_buffer(puckbuffer);

    return kv;
}

simple_cap_proto_kv_t *encode_kv_gps(double in_lat, double in_lon, double in_alt,
        double in_speed, double in_heading,
        double in_precision, int in_fix, time_t in_time, 
        char *in_gps_type, char *in_gps_name) {

    const char *key_lat = "lat";
    const char *key_lon = "lon";
    const char *key_alt = "alt";
    const char *key_speed = "speed";
    const char *key_heading = "heading";
    const char *key_precision = "precision";
    const char *key_fix = "fix";
    const char *key_time = "time";
    const char *key_type = "type";
    const char *key_name = "name";

    msgpuck_buffer_t *puckbuffer;

    simple_cap_proto_kv_t *kv;
    size_t content_sz;

    unsigned int num_fields = 10;
    
    // Allocate a fairly generous headroom in our buffer
    puckbuffer = mp_b_create_buffer(1024);

    if (puckbuffer == NULL) {
        return NULL;
    }

    if (in_precision == 0.0f)
        num_fields--;

    mp_b_encode_map(puckbuffer, num_fields);

    mp_b_encode_str(puckbuffer, key_lat, strlen(key_lat));
    mp_b_encode_double(puckbuffer, in_lat);

    mp_b_encode_str(puckbuffer, key_lon, strlen(key_lon));
    mp_b_encode_double(puckbuffer, in_lon);

    mp_b_encode_str(puckbuffer, key_alt, strlen(key_alt));
    mp_b_encode_double(puckbuffer, in_alt);

    mp_b_encode_str(puckbuffer, key_speed, strlen(key_speed));
    mp_b_encode_double(puckbuffer, in_speed);

    mp_b_encode_str(puckbuffer, key_heading, strlen(key_heading));
    mp_b_encode_double(puckbuffer, in_heading);

    if (in_precision != 0.0f) {
        mp_b_encode_str(puckbuffer, key_precision, strlen(key_precision));
        mp_b_encode_double(puckbuffer, in_alt);
    }

    mp_b_encode_str(puckbuffer, key_fix, strlen(key_fix));
    mp_b_encode_int(puckbuffer, in_fix);

    mp_b_encode_str(puckbuffer, key_time, strlen(key_time));
    mp_b_encode_uint(puckbuffer, in_time);

    mp_b_encode_str(puckbuffer, key_type, strlen(key_type));
    mp_b_encode_str(puckbuffer, in_gps_type, strlen(in_gps_type));

    mp_b_encode_str(puckbuffer, key_name, strlen(key_name));
    mp_b_encode_str(puckbuffer, in_gps_name, strlen(in_gps_name));

    content_sz = mp_b_used_buffer(puckbuffer);

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + content_sz);

    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%16s", "GPS");
    kv->header.obj_sz = htonl(content_sz);

    memcpy(kv->object, mp_b_get_buffer(puckbuffer), content_sz);

    mp_b_free_buffer(puckbuffer);

    return kv;
}

simple_cap_proto_kv_t *encode_kv_signal(int32_t signal_dbm, uint32_t signal_rssi, 
        int32_t noise_dbm, uint32_t noise_rssi, double freq_khz, char *channel, 
        double datarate) {

    const char *key_signal_dbm = "signal_dbm";
    const char *key_signal_rssi = "signal_rssi";
    const char *key_noise_dbm = "noise_dbm";
    const char *key_noise_rssi = "noise_rssi";
    const char *key_freq = "freq_khz";
    const char *key_channel = "channel";
    const char *key_datarate = "datarate";

    simple_cap_proto_kv_t *kv;
    size_t content_sz;

    size_t num_fields = 0;

    /* Count up all the filled-in fields */
    
    if (signal_dbm != 0)
        num_fields++;

    if (noise_dbm != 0)
        num_fields++;

    if (signal_rssi != 0)
        num_fields++;

    if (noise_rssi != 0)
        num_fields++;

    if (freq_khz != 0.0f)
        num_fields++;

    if (channel != NULL)
        num_fields++;

    if (datarate != 0.0f)
        num_fields++;

    msgpuck_buffer_t *puckbuffer;

    /* Make a rough guess */
    size_t initial_sz = num_fields * 32;

    puckbuffer = mp_b_create_buffer(initial_sz);

    if (puckbuffer == NULL) {
        return NULL;
    }

    mp_b_encode_map(puckbuffer, num_fields);

    if (signal_dbm != 0) {
        mp_b_encode_str(puckbuffer, key_signal_dbm, strlen(key_signal_dbm));
        mp_b_encode_int(puckbuffer, signal_dbm);
    }

    if (noise_dbm != 0) {
        mp_b_encode_str(puckbuffer, key_noise_dbm, strlen(key_noise_dbm));
        mp_b_encode_int(puckbuffer, noise_dbm);
    }

    if (signal_rssi != 0) {
        mp_b_encode_str(puckbuffer, key_signal_rssi, strlen(key_signal_rssi));
        mp_b_encode_int(puckbuffer, signal_rssi);
    }

    if (noise_rssi != 0) {
        mp_b_encode_str(puckbuffer, key_noise_rssi, strlen(key_noise_rssi));
        mp_b_encode_int(puckbuffer, noise_rssi);
    }

    if (freq_khz != 0.0f) {
        mp_b_encode_str(puckbuffer, key_freq, strlen(key_freq));
        mp_b_encode_double(puckbuffer, freq_khz);
    }

    if (channel != NULL) {
        mp_b_encode_str(puckbuffer, key_channel, strlen(key_channel));
        mp_b_encode_str(puckbuffer, channel, strlen(channel));
    }

    if (datarate != 0.0f) {
        mp_b_encode_str(puckbuffer, key_datarate, strlen(key_datarate));
        mp_b_encode_double(puckbuffer, datarate);
    }

    content_sz = mp_b_used_buffer(puckbuffer);

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + content_sz);

    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%.16s", "SIGNAL");
    kv->header.obj_sz = htonl(content_sz);

    memcpy(kv->object, mp_b_get_buffer(puckbuffer), content_sz);

    mp_b_free_buffer(puckbuffer);

    return kv;
}

simple_cap_proto_kv_t *encode_kv_interfacelist(char **interfaces, 
        char **options, size_t len) {

    const char *key_interface = "interface";
    const char *key_flags = "flags";

    msgpuck_buffer_t *puckbuffer;

    simple_cap_proto_kv_t *kv;
    size_t content_sz;

    size_t i;

    /* Allocate a chunk per interface as a guess, seems reasonable */
    size_t initial_sz = len * 512;

    /* If we got passed a 0, we're an empty array */
    if (initial_sz == 0)
        initial_sz = 32;

    puckbuffer = mp_b_create_buffer(initial_sz);

    if (puckbuffer == NULL) {
        return NULL;
    }

    mp_b_encode_array(puckbuffer, len);

    for (i = 0; i < len; i++) {
        if (options[i] != NULL) {
            /* If we have options encode both in the dictionary */
            mp_b_encode_map(puckbuffer, 2);

            mp_b_encode_str(puckbuffer, key_interface, strlen(key_interface));
            mp_b_encode_str(puckbuffer, interfaces[i], strlen(interfaces[i]));

            mp_b_encode_str(puckbuffer, key_flags, strlen(key_flags));
            mp_b_encode_str(puckbuffer, options[i], strlen(options[i]));
        } else {
            /* Otherwise no flags, one dict entry */
            mp_b_encode_map(puckbuffer, 1);

            mp_b_encode_str(puckbuffer, key_interface, strlen(key_interface));
            mp_b_encode_str(puckbuffer, interfaces[i], strlen(interfaces[i]));
        }
    }

    content_sz = mp_b_used_buffer(puckbuffer);

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + content_sz);

    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%.16s", "INTERFACELIST");
    kv->header.obj_sz = htonl(content_sz);

    memcpy(kv->object, mp_b_get_buffer(puckbuffer), content_sz);

    mp_b_free_buffer(puckbuffer);

    return kv;
}

simple_cap_proto_kv_t *encode_kv_warning(const char *warning) {
    simple_cap_proto_kv_t *kv;

    size_t content_sz = strlen(warning);

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + content_sz);

    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%.16s", "WARNING");
    kv->header.obj_sz = htonl(content_sz);

    strncpy((char *) kv->object, warning, content_sz);

    return kv;
}

simple_cap_proto_kv_t *encode_kv_sourcetype(const char *sourcetype) {
    simple_cap_proto_kv_t *kv;

    size_t content_sz = strlen(sourcetype);

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + content_sz);

    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%.16s", "SOURCETYPE");
    kv->header.obj_sz = htonl(content_sz);

    strncpy((char *) kv->object, sourcetype, content_sz);

    return kv;
}

simple_cap_proto_kv_t *encode_kv_definition(const char *definition) {
    simple_cap_proto_kv_t *kv;

    size_t content_sz = strlen(definition);

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + content_sz);

    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%.16s", "DEFINITION");
    kv->header.obj_sz = htonl(content_sz);

    strncpy((char *) kv->object, definition, content_sz);

    return kv;
}

simple_cap_proto_kv_t *encode_kv_channel(const char *channel) {
    simple_cap_proto_kv_t *kv;

    size_t content_sz = strlen(channel);

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + content_sz);

    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%.16s", "CHANSET");
    kv->header.obj_sz = htonl(content_sz);

    strncpy((char *) kv->object, channel, content_sz);

    return kv;
}

simple_cap_proto_kv_t *encode_kv_channels(char **channels, size_t len) {

    /* Channels are packed into a dictionary in case we need to pack additional
     * data with them in the future */
    const char *key_channels = "channels";

    msgpuck_buffer_t *puckbuffer;

    simple_cap_proto_kv_t *kv;
    size_t content_sz;

    size_t i;

    /* Allocate a chunk per interface as a guess, seems reasonable */
    size_t initial_sz = len * 32;

    /* If we got passed a 0, we're an empty array */
    if (initial_sz == 0)
        initial_sz = 32;

    puckbuffer = mp_b_create_buffer(initial_sz);

    if (puckbuffer == NULL) {
        return NULL;
    }

    mp_b_encode_map(puckbuffer, 1);

    mp_b_encode_str(puckbuffer, key_channels, strlen(key_channels));
    mp_b_encode_array(puckbuffer, len);

    for (i = 0; i < len; i++) {
        mp_b_encode_str(puckbuffer, channels[i], strlen(channels[i]));
    }
    
    content_sz = mp_b_used_buffer(puckbuffer);

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + content_sz);

    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%.16s", "CHANNELS");
    kv->header.obj_sz = htonl(content_sz);

    memcpy(kv->object, mp_b_get_buffer(puckbuffer), content_sz);

    mp_b_free_buffer(puckbuffer);

    return kv;
}

simple_cap_proto_kv_t *encode_kv_chanhop(double rate, char **channels, size_t len) {

    const char *key_channels = "channels";
    const char *key_rate = "rate";

    msgpuck_buffer_t *puckbuffer;

    simple_cap_proto_kv_t *kv;
    size_t content_sz;
    

    size_t i;

    /* Allocate a chunk per interface as a guess, seems reasonable */
    size_t initial_sz = (len * 32) + 32;

    puckbuffer = mp_b_create_buffer(initial_sz);

    if (puckbuffer == NULL) {
        return NULL;
    }

    mp_b_encode_map(puckbuffer, 2);

    mp_b_encode_str(puckbuffer, key_rate, strlen(key_rate));
    mp_b_encode_double(puckbuffer, rate);

    mp_b_encode_str(puckbuffer, key_channels, strlen(key_channels));
    mp_b_encode_array(puckbuffer, len);

    for (i = 0; i < len; i++) {
        mp_b_encode_str(puckbuffer, channels[i], strlen(channels[i]));
    }

    content_sz = mp_b_used_buffer(puckbuffer);

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + content_sz);

    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%.16s", "CHANHOP");
    kv->header.obj_sz = htonl(content_sz);

    memcpy(kv->object, mp_b_get_buffer(puckbuffer), content_sz);

    mp_b_free_buffer(puckbuffer);

    return kv;
}

simple_cap_proto_kv_t *encode_kv_chanhop_complex(double rate, char **channels,
        size_t len, int shuffle, int shuffle_skip, int offset) {

    const char *key_channels = "channels";
    const char *key_rate = "rate";
    const char *key_shuffle = "shuffle";
    const char *key_shuffle_skip = "shuffle_skip";
    const char *key_offset = "offset";

    msgpuck_buffer_t *puckbuffer;

    simple_cap_proto_kv_t *kv;
    size_t content_sz;
    
    size_t i;

    /* Allocate a chunk per channel as a guess, seems reasonable */
    size_t initial_sz = (len * 32) + 256;

    puckbuffer = mp_b_create_buffer(initial_sz);

    if (puckbuffer == NULL) {
        return NULL;
    }

    mp_b_encode_map(puckbuffer, 5);

    mp_b_encode_str(puckbuffer, key_rate, strlen(key_rate));
    mp_b_encode_double(puckbuffer, rate);

    mp_b_encode_str(puckbuffer, key_channels, strlen(key_channels));
    mp_b_encode_array(puckbuffer, len);

    for (i = 0; i < len; i++) {
        mp_b_encode_str(puckbuffer, channels[i], strlen(channels[i]));
    }

    mp_b_encode_str(puckbuffer, key_shuffle, strlen(key_shuffle));
    mp_b_encode_uint(puckbuffer, shuffle);

    mp_b_encode_str(puckbuffer, key_shuffle_skip, strlen(key_shuffle_skip));
    mp_b_encode_uint(puckbuffer, shuffle_skip);

    mp_b_encode_str(puckbuffer, key_offset, strlen(key_offset));
    mp_b_encode_uint(puckbuffer, offset);

    content_sz = mp_b_used_buffer(puckbuffer);

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + content_sz);

    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%.16s", "CHANHOP");
    kv->header.obj_sz = htonl(content_sz);

    memcpy(kv->object, mp_b_get_buffer(puckbuffer), content_sz);

    mp_b_free_buffer(puckbuffer);

    return kv;
}

simple_cap_proto_kv_t *encode_kv_specset(uint64_t start_mhz, uint64_t end_mhz, 
        uint64_t samples_per_freq, uint64_t bin_width, uint8_t amp,
        uint64_t if_amp, uint64_t baseband_amp) {

    const char *key_start = "start_mhz";
    const char *key_end = "end_mhz";
    const char *key_samples = "samples_per_freq";
    const char *key_binwidth = "bin_width";
    const char *key_amp = "amp";
    const char *key_if_amp = "if_amp";
    const char *key_baseband_amp = "baseband_amp";

    msgpuck_buffer_t *puckbuffer;

    simple_cap_proto_kv_t *kv;
    size_t content_sz;
    
    /* Allocate a chunk per channel as a guess, seems reasonable */
    size_t initial_sz = (7 * 32) + 256;

    puckbuffer = mp_b_create_buffer(initial_sz);

    if (puckbuffer == NULL) {
        return NULL;
    }

    mp_b_encode_map(puckbuffer, 7);

    mp_b_encode_str(puckbuffer, key_start, strlen(key_start));
    mp_b_encode_uint(puckbuffer, start_mhz);

    mp_b_encode_str(puckbuffer, key_end, strlen(key_end));
    mp_b_encode_uint(puckbuffer, end_mhz);

    mp_b_encode_str(puckbuffer, key_samples, strlen(key_samples));
    mp_b_encode_uint(puckbuffer, samples_per_freq);

    mp_b_encode_str(puckbuffer, key_binwidth, strlen(key_binwidth));
    mp_b_encode_uint(puckbuffer, bin_width);

    mp_b_encode_str(puckbuffer, key_amp, strlen(key_amp));
    mp_b_encode_uint(puckbuffer, amp);

    mp_b_encode_str(puckbuffer, key_if_amp, strlen(key_if_amp));
    mp_b_encode_uint(puckbuffer, if_amp);

    mp_b_encode_str(puckbuffer, key_baseband_amp, strlen(key_baseband_amp));
    mp_b_encode_uint(puckbuffer, baseband_amp);

    content_sz = mp_b_used_buffer(puckbuffer);

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + content_sz);

    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%.16s", "SPECSET");
    kv->header.obj_sz = htonl(content_sz);

    memcpy(kv->object, mp_b_get_buffer(puckbuffer), content_sz);

    mp_b_free_buffer(puckbuffer);

    return kv;

}

simple_cap_proto_kv_t *encode_kv_message(const char *message, unsigned int flags) {

    const char *key_message = "msg";
    const char *key_flags = "flags";

    msgpuck_buffer_t *puckbuffer;

    simple_cap_proto_kv_t *kv;
    size_t content_sz;

    size_t initial_sz = strlen(message) + 64;

    puckbuffer = mp_b_create_buffer(initial_sz);

    if (puckbuffer == NULL) {
        return NULL;
    }

    mp_b_encode_map(puckbuffer, 2);

    mp_b_encode_str(puckbuffer, key_message, strlen(key_message));
    mp_b_encode_str(puckbuffer, message, strlen(message));

    mp_b_encode_str(puckbuffer, key_flags, strlen(key_flags));
    mp_b_encode_uint(puckbuffer, flags);

    content_sz = mp_b_used_buffer(puckbuffer);

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + content_sz);

    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%.16s", "MESSAGE");
    kv->header.obj_sz = htonl(content_sz);

    memcpy(kv->object, mp_b_get_buffer(puckbuffer), content_sz);

    mp_b_free_buffer(puckbuffer);

    return kv;
}

int validate_simple_cap_proto_header(simple_cap_proto_t *in_packet) {
    /* Extract original checksum */
    uint32_t original_hcsum = ntohl(in_packet->header_checksum);
    uint32_t original_dcsum = ntohl(in_packet->data_checksum);
    uint32_t calc_csum;

    /* Zero csum field in packet */
    in_packet->header_checksum = 0;
    in_packet->data_checksum = 0;

    /* Checksum the header only */
    calc_csum = adler32_csum((uint8_t *) in_packet, sizeof(simple_cap_proto_t));

    if (original_hcsum != calc_csum)
        return -1;

    /* Restore the contents */
    in_packet->header_checksum = htonl(original_hcsum);
    in_packet->data_checksum = htonl(original_dcsum);

    return 1;
}

int validate_simple_cap_proto(simple_cap_proto_t *in_packet) {
    /* Extract original checksum */
    uint32_t original_hcsum = ntohl(in_packet->header_checksum);
    uint32_t original_dcsum = ntohl(in_packet->data_checksum);
    uint32_t calc_csum;

    /* KV validation */
    simple_cap_proto_frame_t *frame = (simple_cap_proto_frame_t *) in_packet;
    unsigned int i;
    size_t kv_pos;
    simple_cap_proto_kv_t *kv;

    /* Zero csum field in packet */
    in_packet->header_checksum = 0;
    in_packet->data_checksum = 0;

    /* Checksum the contents */
    calc_csum = adler32_csum((uint8_t *) in_packet, sizeof(simple_cap_proto_t));

    if (original_hcsum != calc_csum) {
        fprintf(stderr, "debug - hcsum didn't match\n");
        return -1;
    }

    calc_csum = adler32_csum((uint8_t *) in_packet, ntohl(in_packet->packet_sz));

    if (original_dcsum != calc_csum) {
        fprintf(stderr, "debug - dcsum didn't match\n");
        return -1;
    }

    /* Restore the contents */
    in_packet->header_checksum = htonl(original_hcsum);
    in_packet->data_checksum = htonl(original_dcsum);

    if (ntohl(frame->header.num_kv_pairs) != 0 && 
                ntohl(frame->header.packet_sz) - sizeof(simple_cap_proto_t) <
                sizeof(simple_cap_proto_kv_t)) {
        /* invalid packet - it claims to have KV pairs but can't fit one */
        return -1;
    }

    /* Validate the lengths of the KV pairs */
    kv_pos = 0;
    for (i = 0; i < ntohl(frame->header.num_kv_pairs); i++) {
        kv = (simple_cap_proto_kv_t *) &(frame->data[kv_pos]);
        
        /* Is there room for this KV? */
        if (kv_pos + sizeof(simple_cap_proto_t) + ntohl(kv->header.obj_sz) +
                sizeof(simple_cap_proto_kv_t) > ntohl(in_packet->packet_sz)) {
            return -1;
        }

        kv_pos = ntohl(kv->header.obj_sz) + sizeof(simple_cap_proto_kv_t);
    }

    return 1;
}

int get_simple_cap_proto_next_kv(simple_cap_proto_frame_t *in_packet, char **key,
        simple_cap_proto_kv_t **last_kv) {
    /* Size of the packet data portion */
    size_t data_len = ntohl(in_packet->header.packet_sz) - sizeof(simple_cap_proto_t);

    /* Offset into the data frame */
    size_t kv_offt;

    /* Current KV info */
    size_t this_len;
    simple_cap_proto_kv_t *kv;

    /* No KVs at all */
    if (ntohl(in_packet->header.num_kv_pairs == 0)) {
        // fprintf(stderr, "debug - no kvpairs\n");
        *key = NULL;
        *last_kv = NULL;
        return 0;
    }

    if (*last_kv == NULL) {
        // fprintf(stderr, "debug - first KV pair\n");
        /* If last_kv is null, set it to the current KV and that's the one we look at */
        *last_kv = (simple_cap_proto_kv_t *) in_packet->data;
        kv_offt = 0;
    } else {
        if (data_len < sizeof(simple_cap_proto_kv_t)) {
            /* Error that we got to here */
            fprintf(stderr, "ERROR - insufficient space in packet for kv_t\n");
            *key = NULL;
            return -1;
        }

        /* Otherwise find the next KV after last_kv; to do this we need to find the
         * length of last_kv, make sure it's not the last KV in the packet by
         * checking the lengths, and jump to the next one */
        kv = (simple_cap_proto_kv_t *) *last_kv;
        this_len = ntohl(kv->header.obj_sz);

        /* Get the end of this KV by finding the beginning of it in the data
         * field, and adding its length + header size */
        kv_offt = ((uint8_t *) *last_kv - in_packet->data) + 
            sizeof(simple_cap_proto_kv_t) + this_len;

        /* is there no room after this one for another kv? */
        if (data_len < kv_offt + sizeof(simple_cap_proto_kv_t)) {
            *key = NULL;
            *last_kv = NULL;
            return 0;
        }
    }

    /* If there is room, assign it */
    kv = (simple_cap_proto_kv_t *) *last_kv + kv_offt;

    /* Get the new length */
    this_len = ntohl(kv->header.obj_sz);

    /* kv_offt points to the beginning of this kv (which is the one after
     * where we started).  We know it has enough room for the header,
     * does it have enough room for the whole frame? */
    if (data_len < (kv_offt + sizeof(simple_cap_proto_kv_t) + this_len)) {
        fprintf(stderr, "ERROR - insufficient space in packet for kv content\n");
        *key = NULL;
        *last_kv = NULL;
        return -1;
    }

    /* We've got enough room in the packet to hold everything, kv_offt is the
     * start of the next kv, grab the key and return the length */
    *key = kv->header.key;
    *last_kv = kv;
    return this_len;
}

int find_simple_cap_proto_kv(simple_cap_proto_frame_t *in_packet, const char *key,
        simple_cap_proto_kv_t **kv) {

    simple_cap_proto_kv_t *search_kv = NULL;
    int search_kv_len = 0;
    char *search_key;

    /* Iterate over all the KV pairs */
    while ((search_kv_len = get_simple_cap_proto_next_kv(in_packet, &search_key, 
                    &search_kv)) > 0) {
        // fprintf(stderr, "debug - got kv len %d key %s\n", search_kv_len, search_key);
        if (strncasecmp(key, search_key, 16) == 0) {
            *kv = search_kv;
            return search_kv_len;
        }
    }

    *kv = NULL;
    return search_kv_len;
}

