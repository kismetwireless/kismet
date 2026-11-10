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

#ifndef __FIRMWARE_FILE_H__
#define __FIRMWARE_FILE_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Many distributions install linux-firmware compressed.  In each firmware directory, a file
 * is looked for as named, then with .zst, then with .xz, for the compressions this build
 * supports, before moving to the next directory, so earlier directories always take
 * precedence. */
#define FW_FILE_MAX_SUFFIXES 3
size_t fw_file_suffixes(const char *suffixes[FW_FILE_MAX_SUFFIXES]);

/* Reads a firmware file, decompressing it if the name ends in .zst or .xz.  The file and
 * the decompressed firmware may each be at most max_len bytes.  Returns 0, or a negative
 * errno: -ENOENT if the file doesn't exist, -EFBIG if it is too large, -EINVAL if it is
 * empty or corrupt, -ENOTSUP if this build can't decompress it.  Free the data with free(). */
int fw_file_read(const char *path, size_t max_len, uint8_t **data, size_t *len);

#ifdef __cplusplus
}
#endif

#endif
