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

/*
 * Radiacode protocol derived from the published Radiacode Python
 * interface, https://github.com/cdump/radiacode
 */

#include "radiacode.h"
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "../kis_endian.h"

#define min(a,b) \
	({ __typeof__ (a) _a = (a); \
	 __typeof__ (b) _b = (b); \
	 _a < _b ? _a : _b; })

static uint16_t rd_u16(const char *p) {
	uint16_t v;
	memcpy(&v, p, sizeof(v));
	return le16toh(v);
}

static uint32_t rd_u32(const char *p) {
	uint32_t v;
	memcpy(&v, p, sizeof(v));
	return le32toh(v);
}

static float rd_float(const char *p) {
	uint32_t v = rd_u32(p);
	float f;
	memcpy(&f, &v, sizeof(f));
	return f;
}


char *radiacode_execute(radiacode_comms_t *comms, 
		char req[2], char *args, size_t args_len,
		ssize_t *ret_len) {

	radiacode_request_t *tx_req = NULL;
	char *resp = NULL;
	ssize_t resp_sz;

	uint8_t req_seq_no = 0x80 + comms->sequence;
	comms->sequence = (comms->sequence + 1) % 32;

	tx_req = (radiacode_request_t *) malloc(sizeof(radiacode_request_t) + args_len);
	if (tx_req == NULL) {
		*ret_len = -1;
		return NULL;
	}

	memset(tx_req, 0, sizeof(radiacode_request_t) + args_len);

	tx_req->req_type[0] = req[0];
	tx_req->req_type[1] = req[1];
	tx_req->sequence = req_seq_no;
	/* The length in the header does not include the length field */
	tx_req->le_req_len = htole32(sizeof(radiacode_request_t) + args_len - 4);
	if (args_len > 0)
		memcpy(tx_req->request, args, args_len);

	/*
	for (unsigned int x = 0; x < sizeof(radiacode_request_t) + args_len; x++) {
		fprintf(stderr, "%02x ", ((char *) tx_req)[x] & 0xFF);
	}
	fprintf(stderr, "\n");
	*/

	resp = 
		radiacode_transport_execute(comms, tx_req, 
				sizeof(radiacode_request_t) + args_len,
				&resp_sz);

	free(tx_req);

	*ret_len = resp_sz;
	return resp;


	/*
        response = self._connection.execute(full_request)
        resp_header = response.unpack('<4s')[0]
        assert req_header == resp_header, f'req={req_header.hex()} resp={resp_header.hex()}'
        return response
		*/
}

char *radiacode_read_request(radiacode_comms_t *comms, uint32_t cmd, ssize_t *ret_len) {
	char *data = NULL;
	char *rdata = NULL;
	ssize_t data_len = 0;
	uint32_t cmd_le = htole32(cmd);
	size_t offt = 4;
	uint32_t retcode = 0;
	uint32_t retlen = 0;

	data = radiacode_execute(comms, "\x26\x08", (char *) &cmd_le, 4, &data_len);

	if (data == NULL || data_len < 12) {
		if (data != NULL)
			free(data);
		*ret_len = -1;
		return NULL;
	}

	retcode = rd_u32(data + offt);
	offt += 4;

	if (retcode != 1) {
		free(data);
		*ret_len = -1;
		return NULL;
	}

	retlen = rd_u32(data + offt);
	offt += 4;

	/* Hack to apparently work around a newer firmware bug */
	if (retlen != 0 && (size_t) (data_len - offt) == (size_t) retlen + 1 && data[offt + retlen] == 0x00) {
		retlen = retlen - 1;
	}

	if (data_len - offt < retlen) {
		fprintf(stderr, "DEBUG - expected len %u got %lu\n", retlen, data_len - offt);
		free(data);
		*ret_len = -1;
		return NULL;
	}

	/* terminated so text responses (the config block) can be searched safely */
	rdata = (char *) malloc(sizeof(char) * retlen + 1);

	if (rdata == NULL) {
		free(data);
		*ret_len = -1;
		return NULL;
	}

	memcpy(rdata, data + offt, retlen);
	rdata[retlen] = 0;

	free(data);

	*ret_len = retlen;
	return rdata;

}

int radiacode_fw_version(radiacode_comms_t *comms, radiacode_version_t *ret_ver) {
	char *resp;
	ssize_t resp_sz;
	uint8_t str_len;
	size_t resp_offt;

	resp = radiacode_execute(comms, "\x0a\x00", NULL, 0, &resp_sz);

	if (resp == NULL || resp_sz < 9) {
		if (resp != NULL) {
			free(resp);
		}

		return -1;
	}

	memset(ret_ver, 0, sizeof(radiacode_version_t));

	resp_offt = 4;
	ret_ver->boot_minor = rd_u16(resp + resp_offt);
	ret_ver->boot_major = rd_u16(resp + resp_offt + 2);

	resp_offt += 4;
	str_len = resp[resp_offt] & 0xFF;

	/* the string, then the target version and the next length byte */
	if ((size_t) resp_sz < resp_offt + 1 + str_len + 5) {
		free(resp);
		return -1;
	}

	snprintf(ret_ver->boot_date, min(32, str_len + 1), "%.*s", (int) str_len, resp + resp_offt + 1);

	resp_offt += str_len + 1;

	ret_ver->target_minor = rd_u16(resp + resp_offt);
	ret_ver->target_major = rd_u16(resp + resp_offt + 2);

	resp_offt += 4;
	str_len = resp[resp_offt] & 0xFF;

	if ((size_t) resp_sz < resp_offt + 1 + str_len) {
		free(resp);
		return -1;
	}

	snprintf(ret_ver->target_date, min(32, str_len + 1), "%.*s", (int) str_len, resp + resp_offt + 1);

	free(resp);

	/*
	fprintf(stderr, "DEBUG - radiacode boot %u.%u (%s) fw %u.%u (%s)\n",
			ret_ver->boot_major, ret_ver->boot_minor, ret_ver->boot_date, 
			ret_ver->target_major, ret_ver->target_minor, ret_ver->target_date);
			*/


	return 1;

}

/* Size of a data buffer record body, or -1 if the record type is unknown */
static ssize_t radiacode_record_len(uint8_t eid, uint8_t gid, const char *body, size_t avail,
		unsigned int rt_len) {
	/* RealTimeData, RawData, DoseRateDB, RareData, UserData, ScheduleData,
	 * AccelData, Event, RawCountRate, RawDoseRate */
	static const uint8_t eid0_len[] = { 15, 8, 16, 14, 16, 16, 6, 4, 6, 6 };

	if (eid == 0 && gid == 0)
		return rt_len;

	if (eid == 0 && gid < sizeof(eid0_len))
		return eid0_len[gid];

	/* Sample blocks, '<HI' count and interval then fixed size samples */
	if (eid == 1 && gid >= 1 && gid <= 3) {
		static const uint8_t sample_len[] = { 0, 8, 16, 14 };

		if (avail < 6)
			return -1;

		return 6 + (ssize_t) rd_u16(body) * sample_len[gid];
	}

	return -1;
}

/* Parse a data buffer; returns 1 if every record parsed to the end of the
 * buffer, 0 if it stopped at an unknown or truncated record */
static int radiacode_parse_databuf(const char *data, size_t data_len, unsigned int rt_len,
		radiacode_data_report_t *ret_data) {
	size_t offt = 0;

	memset(ret_data, 0, sizeof(radiacode_data_report_t));

	while (offt + RADIA_DATA_HDR_LEN <= data_len) {
		uint8_t eid = (uint8_t) data[offt + 1];
		uint8_t gid = (uint8_t) data[offt + 2];
		int32_t ts_offset = (int32_t) rd_u32(data + offt + 3);
		const char *body = data + offt + RADIA_DATA_HDR_LEN;
		size_t avail = data_len - offt - RADIA_DATA_HDR_LEN;
		ssize_t rec_len = radiacode_record_len(eid, gid, body, avail, rt_len);

		if (rec_len < 0 || (size_t) rec_len > avail)
			return 0;

		if (eid == 0 && gid == 0) {
			radiacode_realtime_t *rt;

			/* Keep the newest records if a backlog overflows the report */
			if (ret_data->num_rt == RADIA_MAX_RT) {
				memmove(&ret_data->rt[0], &ret_data->rt[1],
						sizeof(radiacode_realtime_t) * (RADIA_MAX_RT - 1));
				ret_data->num_rt--;
			}

			rt = &ret_data->rt[ret_data->num_rt++];

			rt->ts_offset = ts_offset;
			rt->count_rate = rd_float(body);
			rt->dose_rate = rd_float(body + 4);
			rt->count_rate_err = rd_u16(body + 8);
			rt->dose_rate_err = rd_u16(body + 10);
			rt->flags = rd_u16(body + 12);
			rt->rt_flags = (uint8_t) body[14];
		} else if (eid == 0 && gid == 3) {
			ret_data->have_rare = 1;
			ret_data->rare.duration = rd_u32(body);
			ret_data->rare.dose = rd_float(body + 4);
			ret_data->rare.temperature = rd_u16(body + 8);
			ret_data->rare.charge_level = rd_u16(body + 10);
			ret_data->rare.flags = rd_u16(body + 12);
		}

		offt += RADIA_DATA_HDR_LEN + rec_len;
	}

	return offt == data_len ? 1 : 0;
}

int radiacode_get_data(radiacode_comms_t *comms, radiacode_data_report_t *ret_data) {
	char *data = NULL;
	ssize_t data_len;
	unsigned int rt_len = comms->rt_len != 0 ? comms->rt_len : RADIA_RT_LEN_OLD;
	unsigned int alt_len = rt_len == RADIA_RT_LEN_OLD ? RADIA_RT_LEN_NEW : RADIA_RT_LEN_OLD;
	radiacode_data_report_t alt_report;

	data = radiacode_read_request(comms, RADIA_VS_DATA_BUF, &data_len);

	if (data == NULL) {
		memset(ret_data, 0, sizeof(radiacode_data_report_t));
		return -ENOMEM;
	}

	/* If the buffer doesn't parse cleanly with the expected real-time record
	 * size but does with the other, firmware changed it; switch.  Otherwise
	 * keep the records parsed before the problem. */
	if (radiacode_parse_databuf(data, (size_t) data_len, rt_len, ret_data) == 0 &&
			radiacode_parse_databuf(data, (size_t) data_len, alt_len, &alt_report) == 1) {
		comms->rt_len = alt_len;
		memcpy(ret_data, &alt_report, sizeof(radiacode_data_report_t));
	}

	free(data);

	return (ret_data->num_rt > 0 || ret_data->have_rare) ? 1 : 0;
}

int radiacode_get_config(radiacode_comms_t *comms, char **config, size_t *config_len) {
	ssize_t data_len;

	*config = radiacode_read_request(comms, RADIA_VS_CONFIGURATION, &data_len);

	if (*config == NULL || data_len <= 0) {
		free(*config);
		*config = NULL;
		return -ENOMEM;
	}

	*config_len = data_len;

	return 1;
}

