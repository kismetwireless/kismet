#include "../config.h"

#ifndef __RADIACODE_H__
#define __RADIACODE_H__

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define RADIA_VID   0x0483
#define RADIA_PID   0xF123

#define RADIA_VS_DATA_BUF		256
#define RADIA_VS_CONFIGURATION	2
#define RADIA_VS_SPECTRUM		512
#define RADIA_VS_ENERGY_CALIB	514
#define RADIA_VS_SPEC_ACCUM		517

/* The protocol sends little-endian IEEE 754 32 bit floats; this code assumes
 * the host float is the same 32 bit format. */

typedef struct {
	uint8_t sequence;

	void *auxdata;
} radiacode_comms_t;

typedef struct {
	uint32_t le_req_len;
	char req_type[2];
	char pad1;
	char sequence;
	char request[0];
} __attribute__ ((packed)) radiacode_request_t; 

/* Execute a radiacode command using one of the backends */
char *radiacode_execute(radiacode_comms_t *comms, 
		char req[2], char *args, size_t args_len,
		ssize_t *ret_len);

/* Implemented per-transport */
char *radiacode_transport_execute(radiacode_comms_t *comms, 
		radiacode_request_t *cmd, size_t len, ssize_t *ret_len);

typedef struct {
	unsigned int boot_major, boot_minor;
	char boot_date[32];
	unsigned int target_major, target_minor;
	char target_date[32];
} radiacode_version_t;

/* Fetch version; caller must free result */
int radiacode_fw_version(radiacode_comms_t *comms, radiacode_version_t *ret_ver);

/* Read a VS block; caller must free result */
char *radiacode_read_request(radiacode_comms_t *comms, uint32_t cmd, ssize_t *ret_len);

/* Data buffer records are a 7 byte header (seq, eid, gid, int32 ts_offset)
 * followed by a record sized by eid/gid.  ts_offset counts in 10ms units. */
#define RADIA_DATA_HDR_LEN		7
#define RADIA_DATA_TS_UNIT_MS	10

/* eid 0 gid 0, '<ffHHHB' */
typedef struct {
	int32_t ts_offset;
	float count_rate;
	float dose_rate;
	/* errors are percent * 10 */
	uint16_t count_rate_err;
	uint16_t dose_rate_err;
	uint16_t flags;
	uint8_t rt_flags;
} radiacode_realtime_t;

/* eid 0 gid 3, '<IfHHH' */
typedef struct {
	uint32_t duration;
	float dose;
	/* temperature is (C * 100) + 2000, charge level is percent * 100 */
	uint16_t temperature;
	uint16_t charge_level;
	uint16_t flags;
} radiacode_raredata_t;

#define RADIA_MAX_RT	32

/* Records from one data buffer read, oldest real-time record first */
typedef struct {
	radiacode_realtime_t rt[RADIA_MAX_RT];
	unsigned int num_rt;

	int have_rare;
	radiacode_raredata_t rare;
} radiacode_data_report_t;

int radiacode_get_data(radiacode_comms_t *comms, radiacode_data_report_t *ret_data);
int radiacode_get_config(radiacode_comms_t *comms, char **config, size_t *config_len);

/* Spectrum header, '<Ifff': duration in seconds then the a0/a1/a2 energy
 * calibration, followed by the channel counts */
#define RADIA_SPECTRUM_HDR_LEN	16

#endif


