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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HAVE_LIBZSTD
#include <zstd.h>
#endif

#ifdef HAVE_LIBLZMA
#include <lzma.h>
#endif

#include "firmware_file.h"

/* Decoder memory limit for xz; linux-firmware uses small dictionaries */
#define FW_FILE_XZ_MEMLIMIT (64 * 1024 * 1024)

size_t fw_file_suffixes(const char *suffixes[FW_FILE_MAX_SUFFIXES]) {
    size_t n = 0;

    suffixes[n++] = "";
#ifdef HAVE_LIBZSTD
    suffixes[n++] = ".zst";
#endif
#ifdef HAVE_LIBLZMA
    suffixes[n++] = ".xz";
#endif

    return n;
}

static bool fw_file_has_suffix(const char *path, const char *suffix) {
    size_t pl = strlen(path), sl = strlen(suffix);
    return pl > sl && strcmp(path + pl - sl, suffix) == 0;
}

static int fw_file_read_raw(const char *path, size_t max_len, uint8_t **data, size_t *len) {
    struct stat st;
    uint8_t *buf;
    size_t got = 0;
    int fd;

    if ((fd = open(path, O_RDONLY)) < 0)
        return -errno;

    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return -EINVAL;
    }

    if (st.st_size <= 0) {
        close(fd);
        return -EINVAL;
    }

    if ((uint64_t) st.st_size > max_len) {
        close(fd);
        return -EFBIG;
    }

    if ((buf = malloc((size_t) st.st_size)) == NULL) {
        close(fd);
        return -ENOMEM;
    }

    while (got < (size_t) st.st_size) {
        ssize_t r = read(fd, buf + got, (size_t) st.st_size - got);

        if (r < 0 && errno == EINTR)
            continue;

        if (r <= 0) {
            free(buf);
            close(fd);
            return -EIO;
        }

        got += (size_t) r;
    }

    close(fd);
    *data = buf;
    *len = got;
    return 0;
}

#if defined(HAVE_LIBZSTD) || defined(HAVE_LIBLZMA)
/* Grows a decompression buffer, doubling up to max_len; -EFBIG once it can't grow */
static int fw_file_grow(uint8_t **buf, size_t *cap, size_t max_len) {
    size_t ncap;
    uint8_t *nb;

    if (*cap >= max_len)
        return -EFBIG;

    ncap = *cap > max_len / 2 ? max_len : *cap * 2;

    if ((nb = realloc(*buf, ncap)) == NULL)
        return -ENOMEM;

    *buf = nb;
    *cap = ncap;
    return 0;
}

static size_t fw_file_initial_cap(size_t in_len, size_t max_len) {
    size_t cap = in_len > max_len / 4 ? max_len : in_len * 4;
    return cap < 65536 ? (max_len < 65536 ? max_len : 65536) : cap;
}
#endif

#ifdef HAVE_LIBZSTD
static int fw_file_unzstd(const uint8_t *in, size_t in_len, size_t max_len,
        uint8_t **data, size_t *len) {
    ZSTD_DCtx *dctx;
    ZSTD_inBuffer ib = { in, in_len, 0 };
    size_t cap = fw_file_initial_cap(in_len, max_len), pos = 0, zr = 1;
    uint8_t *out;
    int r = 0;

    if ((dctx = ZSTD_createDCtx()) == NULL)
        return -ENOMEM;

    if ((out = malloc(cap)) == NULL) {
        ZSTD_freeDCtx(dctx);
        return -ENOMEM;
    }

    /* Every frame in the file, until the input is used and the last frame is complete */
    while (ib.pos < ib.size || zr != 0) {
        ZSTD_outBuffer ob;

        if (pos == cap && (r = fw_file_grow(&out, &cap, max_len)) < 0)
            break;

        ob.dst = out;
        ob.size = cap;
        ob.pos = pos;

        zr = ZSTD_decompressStream(dctx, &ob, &ib);

        if (ZSTD_isError(zr)) {
            r = -EINVAL;
            break;
        }

        /* No progress with room left means the input ends inside a frame */
        if (ob.pos == pos && ib.pos == ib.size && ob.pos < ob.size && zr != 0) {
            r = -EINVAL;
            break;
        }

        pos = ob.pos;
    }

    ZSTD_freeDCtx(dctx);

    if (r == 0 && pos == 0)
        r = -EINVAL;

    if (r < 0) {
        free(out);
        return r;
    }

    *data = out;
    *len = pos;
    return 0;
}
#endif

#ifdef HAVE_LIBLZMA
static int fw_file_unxz(const uint8_t *in, size_t in_len, size_t max_len,
        uint8_t **data, size_t *len) {
    lzma_stream strm = LZMA_STREAM_INIT;
    size_t cap = fw_file_initial_cap(in_len, max_len);
    uint8_t *out;
    int r = 0;

    if (lzma_stream_decoder(&strm, FW_FILE_XZ_MEMLIMIT, LZMA_CONCATENATED) != LZMA_OK)
        return -ENOMEM;

    if ((out = malloc(cap)) == NULL) {
        lzma_end(&strm);
        return -ENOMEM;
    }

    strm.next_in = in;
    strm.avail_in = in_len;
    strm.next_out = out;
    strm.avail_out = cap;

    while (1) {
        lzma_ret lr = lzma_code(&strm, LZMA_FINISH);

        if (lr == LZMA_STREAM_END)
            break;

        /* A stream that can't progress returns LZMA_BUF_ERROR on the next call */
        if (lr == LZMA_OK) {
            if (strm.avail_out == 0) {
                size_t pos = cap;

                if ((r = fw_file_grow(&out, &cap, max_len)) < 0)
                    break;

                strm.next_out = out + pos;
                strm.avail_out = cap - pos;
            }
            continue;
        }

        /* A corrupt or truncated file */
        r = lr == LZMA_MEM_ERROR || lr == LZMA_MEMLIMIT_ERROR ? -ENOMEM : -EINVAL;
        break;
    }

    const size_t out_len = cap - strm.avail_out;
    lzma_end(&strm);

    if (r == 0 && out_len == 0)
        r = -EINVAL;

    if (r < 0) {
        free(out);
        return r;
    }

    *data = out;
    *len = out_len;
    return 0;
}
#endif

int fw_file_read(const char *path, size_t max_len, uint8_t **data, size_t *len) {
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    int r;

    *data = NULL;
    *len = 0;

    if (max_len == 0)
        return -EINVAL;

    if ((r = fw_file_read_raw(path, max_len, &raw, &raw_len)) < 0)
        return r;

    if (fw_file_has_suffix(path, ".zst")) {
#ifdef HAVE_LIBZSTD
        r = fw_file_unzstd(raw, raw_len, max_len, data, len);
#else
        r = -ENOTSUP;
#endif
        free(raw);
        return r;
    }

    if (fw_file_has_suffix(path, ".xz")) {
#ifdef HAVE_LIBLZMA
        r = fw_file_unxz(raw, raw_len, max_len, data, len);
#else
        r = -ENOTSUP;
#endif
        free(raw);
        return r;
    }

    *data = raw;
    *len = raw_len;
    return 0;
}
