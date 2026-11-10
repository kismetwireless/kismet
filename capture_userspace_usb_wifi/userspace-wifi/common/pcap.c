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

#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include "pcap.h"

#define PCAP_SNAPLEN 65535

struct uwifi_pcap {
    FILE *f;
    /* Writing to stdout for a pipe; flush every packet */
    bool is_stdout;
    pthread_mutex_t lock;
};

static void put_le16(uint8_t *p, uint16_t v) {
    p[0] = v & 0xff;
    p[1] = (uint8_t) (v >> 8);
}

static void put_le32(uint8_t *p, uint32_t v) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (uint8_t) (v >> 24);
}

struct uwifi_pcap *uwifi_pcap_open(const char *path) {
    struct uwifi_pcap *p;
    uint8_t hdr[24];

    if ((p = calloc(1, sizeof(*p))) == NULL)
        return NULL;

    if (strcmp(path, "-") == 0) {
        p->f = stdout;
        p->is_stdout = true;
    } else if ((p->f = fopen(path, "wb")) == NULL) {
        free(p);
        return NULL;
    }

    put_le32(hdr, 0xa1b2c3d4);
    put_le16(hdr + 4, 2);
    put_le16(hdr + 6, 4);
    put_le32(hdr + 8, 0);
    put_le32(hdr + 12, 0);
    put_le32(hdr + 16, PCAP_SNAPLEN);
    put_le32(hdr + 20, UWIFI_DLT_IEEE802_11_RADIO);

    if (fwrite(hdr, sizeof(hdr), 1, p->f) != 1 || fflush(p->f) != 0) {
        fclose(p->f);
        free(p);
        return NULL;
    }

    pthread_mutex_init(&p->lock, NULL);
    return p;
}

int uwifi_pcap_write(struct uwifi_pcap *p, const uint8_t *data, size_t len) {
    uint8_t rec[16];
    struct timeval tv;
    size_t caplen = len > PCAP_SNAPLEN ? PCAP_SNAPLEN : len;
    int r = 0;

    gettimeofday(&tv, NULL);
    put_le32(rec, (uint32_t) tv.tv_sec);
    put_le32(rec + 4, (uint32_t) tv.tv_usec);
    put_le32(rec + 8, (uint32_t) caplen);
    put_le32(rec + 12, (uint32_t) len);

    pthread_mutex_lock(&p->lock);
    if (fwrite(rec, sizeof(rec), 1, p->f) != 1 || fwrite(data, caplen, 1, p->f) != 1 ||
            (p->is_stdout && fflush(p->f) != 0))
        r = -1;
    pthread_mutex_unlock(&p->lock);

    return r;
}

void uwifi_pcap_close(struct uwifi_pcap *p) {
    if (p == NULL)
        return;
    if (p->is_stdout)
        fflush(p->f);
    else
        fclose(p->f);
    pthread_mutex_destroy(&p->lock);
    free(p);
}

struct uwifi_pcap_reader {
    FILE *f;
    bool swapped;
    uint8_t *buf;
};

static uint32_t get_u32(const uint8_t *p, bool swapped) {
    return swapped ? (uint32_t) p[0] << 24 | (uint32_t) p[1] << 16 | (uint32_t) p[2] << 8 | p[3] :
        (uint32_t) p[3] << 24 | (uint32_t) p[2] << 16 | (uint32_t) p[1] << 8 | p[0];
}

struct uwifi_pcap_reader *uwifi_pcap_read_open(const char *path, uint32_t *linktype) {
    struct uwifi_pcap_reader *r;
    uint8_t hdr[24];
    uint32_t magic;

    if ((r = calloc(1, sizeof(*r))) == NULL)
        return NULL;

    if ((r->f = fopen(path, "rb")) == NULL || fread(hdr, sizeof(hdr), 1, r->f) != 1)
        goto fail;

    magic = get_u32(hdr, false);
    if (magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1)
        r->swapped = true;
    else if (magic != 0xa1b2c3d4 && magic != 0xa1b23c4d)
        goto fail;

    *linktype = get_u32(hdr + 20, r->swapped) & 0xffff;

    if ((r->buf = malloc(PCAP_SNAPLEN)) == NULL)
        goto fail;

    return r;

fail:
    if (r->f)
        fclose(r->f);
    free(r);
    return NULL;
}

int uwifi_pcap_read_next(struct uwifi_pcap_reader *r, const uint8_t **data) {
    uint8_t rec[16];
    uint32_t caplen;

    if (fread(rec, sizeof(rec), 1, r->f) != 1)
        return feof(r->f) ? 0 : -1;

    caplen = get_u32(rec + 8, r->swapped);
    if (caplen == 0 || caplen > PCAP_SNAPLEN || fread(r->buf, caplen, 1, r->f) != 1)
        return -1;

    *data = r->buf;
    return (int) caplen;
}

void uwifi_pcap_read_close(struct uwifi_pcap_reader *r) {
    if (r == NULL)
        return;
    fclose(r->f);
    free(r->buf);
    free(r);
}
