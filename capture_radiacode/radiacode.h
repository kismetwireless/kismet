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

/* WARNING
 *
 * In general this code makes some bad assumptions.  It has to assume that it is 
 * on a little-endian system.  It has to assume that floats are 32bits.  
 * 
 * The radiacode devices makes some bad decisions in the binary protocol which
 * are difficult to solve in pure C.  With the assumption that the number of 
 * users for the radiacode is pretty small, for now the code will just roll
 * with those requirements, but it may present a problem in the future.
 */

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

typedef struct {
	/* 
        seq, eid, gid, ts_offset = br.unpack('<BBBi')
        dt = base_time + datetime.timedelta(milliseconds=ts_offset)
	*/
	uint8_t seq;
	uint8_t eid;
	uint8_t gid;
	uint32_t ts_offset_le;

} __attribute__ ((packed)) radiacode_data_header_t;

typedef struct {
	/*
        if eid == 0 and gid == 0:  # GRP_RealTimeData
            count_rate, dose_rate, count_rate_err, dose_rate_err, flags, rt_flags = br.unpack('<ffHHHB')
	 */
	float count_rate_le;
	float dose_rate_le;
	uint16_t count_rate_err_le;
	uint16_t dose_rate_err_le;
	uint16_t flags_le;
	uint8_t rt_flags;
} __attribute__ ((packed)) radiacode_realtimedata_t;

/* Combined report of multiple data report objects */
typedef struct {
	float count_rate;
	float dose_rate;
	uint16_t count_rate_err;
	uint16_t dose_rate_err;
	uint16_t flags;
	uint8_t rt_flags;
} radiacode_data_report_t;

int radiacode_get_data(radiacode_comms_t *comms, radiacode_data_report_t *ret_data); 
int radiacode_get_config(radiacode_comms_t *comms, char **config, size_t *config_len);

typedef struct {
	uint16_t ts_le;
	float a0_le;
	float a1_le;
	float a2_le;
} __attribute__ ((packed)) radiacode_spectrum_header;

#endif


