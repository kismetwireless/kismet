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

#include <stdlib.h>
#include <string.h>

#include "kis_external_packet.h"

/* Blocks are always aligned to 32bit and start at a boundary, so
 * when calculating the padded lengths, they only need the total padded to
 * 32 bit */

size_t ks_proto_v3_subblock_padlen(size_t datalen) {
    return sizeof(kismet_v3_sub_block) + datalen + (datalen % 4);
}

/* Calculate the padded block size of a string block for specified
 * string length */
size_t ks_proto_v3_strblock_padlen(size_t str_length) {
    /* length(u16) + pad(u16) + string(pad 32) */
    return 2 + 2 + str_length + (str_length % 4);
}

size_t ks_proto_v3_msgblock_padlen(size_t str_length) {
    return ks_proto_v3_subblock_padlen(4 + ks_proto_v3_strblock_padlen(str_length));
}

void ks_proto_v3_fill_strblock(void *block_buf, size_t length, char *data) {
    kismet_v3_sub_string *substr = (kismet_v3_sub_string *) block_buf;

    memset(substr, 0, sizeof(kismet_v3_sub_string) + ks_proto_v3_pad(length));

    substr->length = (uint16_t) length;
    substr->pad0 = 0;
    memcpy(substr->data, data, length);
}

