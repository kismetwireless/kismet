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

uint32_t adler32_csum(uint8_t *in_buf, size_t in_len) {
	size_t i;
	uint32_t s1, s2;
	uint8_t *buf = in_buf;
	int CHAR_OFFSET = 0;

	s1 = s2 = 0;
	for (i = 0; i < (in_len - 4); i += 4) {
		s2 += 4 * (s1 + buf[i]) + 3 * buf[i + 1] + 2 * buf[i+2] + buf[i + 3] + 
			10 * CHAR_OFFSET;
		s1 += (buf[i + 0] + buf[i + 1] + buf[i + 2] + buf[i + 3] + 4 * CHAR_OFFSET); 
	}

	for (; i < in_len; i++) {
		s1 += (buf[i] + CHAR_OFFSET); 
        s2 += s1;
	}

	return (s1 & 0xffff) + (s2 << 16);
}

simple_cap_proto_kv_t *encode_simple_cap_proto_kv(char *in_key, uint8_t *in_obj,
        unsigned int in_obj_len) {
    simple_cap_proto_kv_t *kv;

    kv = (simple_cap_proto_kv_t *) malloc(sizeof(simple_cap_proto_kv_t) + in_obj_len);
    if (kv == NULL)
        return NULL;

    snprintf(kv->header.key, 16, "%16s", in_key);
    kv->header.obj_sz = htonl(in_obj_len);

    memcpy(kv->object, in_obj, in_obj_len);

    return kv;
}

simple_cap_proto_t *encode_simple_cap_proto(char *in_type, uint32_t in_seqno,
        simple_cap_proto_kv_t **in_kv_list, unsigned int in_kv_len) {
    simple_cap_proto_t *cp;
    simple_cap_proto_kv_t *kv;
    unsigned int x;
    size_t sz = sizeof(simple_cap_proto_t);
    size_t offt = 0;
    uint32_t csum;

    for (x = 0; x < in_kv_len; x++) {
        kv = in_kv_list[x];
        sz += sizeof(simple_cap_proto_t) + kv->header.obj_sz;
    }

    cp = (simple_cap_proto_t *) malloc(sz);

    if (cp == NULL)
        return NULL;

    cp->signature = htonl(KIS_CAP_SIMPLE_PROTO_SIG);
    cp->checksum = 0;
    cp->sequence_number = htonl(in_seqno);
    snprintf(cp->type, 16, "%16s", in_type);
    cp->packet_sz = htonl((uint32_t) sz);
    cp->num_kv_pairs = htonl(in_kv_len);

    for (x = 0; x < in_kv_len; x++) {
        kv = in_kv_list[x];
        memcpy(cp->data + offt, kv, sizeof(simple_cap_proto_kv_t) + kv->header.obj_sz);
        offt += sizeof(simple_cap_proto_kv_t) + kv->header.obj_sz;
    }

    csum = adler32_csum((uint8_t *) cp, sz);
    cp->checksum = htonl(csum);

    return cp;
}

int pack_kv_capdata(uint8_t **ret_buffer, uint32_t *ret_sz,
        struct timeval in_ts, int in_dlt, uint32_t in_pack_sz, uint8_t *in_pack) {

    const char *key_tv_sec = "tv_sec";
    const char *key_tv_usec = "tv_usec";
    const char *key_dlt = "dlt";
    const char *key_pack_sz = "pack_sz";
    const char *key_packet = "packet";

    msgpuck_buffer_t *puckbuffer;

    // Allocate a fairly generous headroom in our buffer
    puckbuffer = mp_b_create_buffer(in_pack_sz + 256);

    if (puckbuffer == NULL) {
        *ret_buffer = NULL;
        *ret_sz = 0;
        return -1;
    }

    mp_b_encode_map(puckbuffer, 5);

    mp_b_encode_str(puckbuffer, key_tv_sec, strlen(key_tv_sec));
    mp_b_encode_uint(puckbuffer, in_ts.tv_sec);

    mp_b_encode_str(puckbuffer, key_tv_usec, strlen(key_tv_usec));
    mp_b_encode_uint(puckbuffer, in_ts.tv_usec);

    mp_b_encode_str(puckbuffer, key_dlt, strlen(key_dlt));
    mp_b_encode_uint(puckbuffer, in_dlt);

    mp_b_encode_str(puckbuffer, key_pack_sz, strlen(key_pack_sz));
    mp_b_encode_uint(puckbuffer, in_pack_sz);

    mp_b_encode_str(puckbuffer, key_packet, strlen(key_packet));
    mp_b_encode_bin(puckbuffer, (const char *) in_pack, in_pack_sz);

    *ret_sz = mp_b_used_buffer(puckbuffer);
    *ret_buffer = (uint8_t *) mp_b_extract_buffer(puckbuffer);

    return 1;
}

int pack_kv_gps(uint8_t **ret_buffer, uint32_t *ret_sz,
        double in_lat, double in_lon, double in_alt, double in_speed, double in_heading,
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

    // Allocate a fairly generous headroom in our buffer
    puckbuffer = mp_b_create_buffer(1024);

    if (puckbuffer == NULL) {
        *ret_buffer = NULL;
        *ret_sz = 0;
        return -1;
    }

    unsigned int num_fields = 10;

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

    *ret_sz = mp_b_used_buffer(puckbuffer);
    *ret_buffer = (uint8_t *) mp_b_extract_buffer(puckbuffer);

    return 1;
}

int pack_kv_signal(uint8_t **ret_buffer, uint32_t *ret_sz,
        uint32_t signal_dbm, uint32_t signal_rssi, uint32_t noise_dbm,
        uint32_t noise_rssi, double freq_khz, char *channel, double datarate) {

    const char *key_signal_dbm = "signal_dbm";
    const char *key_signal_rssi = "signal_rssi";
    const char *key_noise_dbm = "noise_dbm";
    const char *key_noise_rssi = "noise_rssi";
    const char *key_freq = "freq_khz";
    const char *key_channel = "channel";
    const char *key_datarate = "datarate";

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
        *ret_buffer = NULL;
        *ret_sz = 0;
        return -1;
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

    *ret_sz = mp_b_used_buffer(puckbuffer);
    *ret_buffer = (uint8_t *) mp_b_extract_buffer(puckbuffer);

    return 1;
}

int pack_kv_interfacelist(uint8_t **ret_buffer, uint32_t *ret_sz,
        const char **interfaces, const char **options, size_t len) {

    const char *key_interface = "interface";
    const char *key_flags = "flags";

    msgpuck_buffer_t *puckbuffer;

    size_t i;

    /* Allocate a chunk per interface as a guess, seems reasonable */
    size_t initial_sz = len * 512;

    /* If we got passed a 0, we're an empty array */
    if (initial_sz == 0)
        initial_sz = 32;

    puckbuffer = mp_b_create_buffer(initial_sz);

    if (puckbuffer == NULL) {
        *ret_buffer = NULL;
        *ret_sz = 0;
        return -1;
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

    *ret_sz = mp_b_used_buffer(puckbuffer);
    *ret_buffer = (uint8_t *) mp_b_extract_buffer(puckbuffer);

    return 1;
}

int pack_kv_channels(uint8_t **ret_buffer, uint32_t *ret_sz,
        const char **channels, size_t len) {

    /* Channels are packed into a dictionary in case we need to pack additional
     * data with them in the future */
    const char *key_channels = "channels";

    msgpuck_buffer_t *puckbuffer;

    size_t i;

    /* Allocate a chunk per interface as a guess, seems reasonable */
    size_t initial_sz = len * 32;

    /* If we got passed a 0, we're an empty array */
    if (initial_sz == 0)
        initial_sz = 32;

    puckbuffer = mp_b_create_buffer(initial_sz);

    if (puckbuffer == NULL) {
        *ret_buffer = NULL;
        *ret_sz = 0;
        return -1;
    }

    mp_b_encode_map(puckbuffer, 1);

    mp_b_encode_str(puckbuffer, key_channels, strlen(key_channels));
    mp_b_encode_array(puckbuffer, len);

    for (i = 0; i < len; i++) {
        mp_b_encode_str(puckbuffer, channels[i], strlen(channels[i]));
    }

    *ret_sz = mp_b_used_buffer(puckbuffer);
    *ret_buffer = (uint8_t *) mp_b_extract_buffer(puckbuffer);

    return 1;
}

int pack_kv_chanhop(uint8_t **ret_buffer, uint32_t *ret_sz,
        double rate, const char **channels, size_t len) {

    const char *key_channels = "channels";
    const char *key_rate = "rate";

    msgpuck_buffer_t *puckbuffer;

    size_t i;

    /* Allocate a chunk per interface as a guess, seems reasonable */
    size_t initial_sz = (len * 32) + 32;

    puckbuffer = mp_b_create_buffer(initial_sz);

    if (puckbuffer == NULL) {
        *ret_buffer = NULL;
        *ret_sz = 0;
        return -1;
    }

    mp_b_encode_map(puckbuffer, 2);

    mp_b_encode_str(puckbuffer, key_rate, strlen(key_rate));
    mp_b_encode_double(puckbuffer, rate);

    mp_b_encode_str(puckbuffer, key_channels, strlen(key_channels));
    mp_b_encode_array(puckbuffer, len);

    for (i = 0; i < len; i++) {
        mp_b_encode_str(puckbuffer, channels[i], strlen(channels[i]));
    }

    *ret_sz = mp_b_used_buffer(puckbuffer);
    *ret_buffer = (uint8_t *) mp_b_extract_buffer(puckbuffer);

    return 1;
}

int validate_simple_cap_proto(simple_cap_proto_t *in_packet) {

}

