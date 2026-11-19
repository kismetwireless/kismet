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

#ifndef __CAPTURE_ENV_H__
#define __CAPTURE_ENV_H__

/* Datasource sensor readings (KIS_EXTERNAL_V3_KDS_ENVREPORT), sent with
 * cf_send_envreport; the encoder is in capture_framework.c.  Kept apart from
 * capture_framework.h so C++ tests can use it. */

#include <stdint.h>
#include <stddef.h>
#include <sys/time.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One sensor reading of the datasource hardware */
typedef struct {
    /* 1-32 of [A-Za-z0-9_.-], not starting with '.'; the same sensor keeps its id */
    const char *id;
    /* KIS_EXTERNAL_V3_ENV_KIND_* */
    unsigned int kind;
    /* thermal -100..400 C, fan 0..1000000 RPM, battery 0..100 percent */
    double value;
    /* optional, NULL for none; at most 64 characters are sent */
    const char *label;

    /* battery only: KIS_EXTERNAL_V3_ENV_BATT_*; on external power 1 or 0, -1 when
     * unknown; volts, 0 when unknown; seconds remaining, 0 when unknown */
    unsigned int batt_state;
    int ext_power;
    double voltage;
    uint32_t remaining_s;
} cf_env_reading_t;

/* Buffer space for n readings */
size_t cf_env_estimate_len(size_t n);

/* Encode the ENVREPORT content; invalid readings are left out, and at most
 * KIS_EXTERNAL_V3_ENV_MAX_READINGS are written.  Returns the length, 0 if no reading
 * is valid, or -1 if the buffer is too small.  ts may be NULL. */
ssize_t cf_env_encode(char *buf, size_t buf_sz, const cf_env_reading_t *readings, size_t n,
        const struct timeval *ts);

#ifdef __cplusplus
}
#endif

#endif
