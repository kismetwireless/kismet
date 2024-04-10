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
 * interface, https://github.com/cdump/radiacode.git
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


char *radiacode_execute(radiacode_comms_t *comms, 
		char req[2], char *args, size_t args_len,
		ssize_t *ret_len) {

	radiacode_request_t *tx_req = NULL;
	char *resp = NULL;
	ssize_t resp_sz;

	uint8_t req_seq_no = 0x80 + comms->sequence;
	comms->sequence = (comms->sequence + 1) % 32;

	tx_req = (radiacode_request_t *) malloc(sizeof(radiacode_request_t) + args_len);
	memset(tx_req, 0, sizeof(radiacode_request_t) + args_len);

	tx_req->req_type[0] = req[0];
	tx_req->req_type[1] = req[1];
	tx_req->sequence = req_seq_no;
	/* The length in the header does not include the length field */
	tx_req->le_req_len = htole32(sizeof(radiacode_request_t) + args_len - 4);
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

	if (data_len < 12) {
		if (data != NULL) {
			free(data);
			*ret_len = -1;
			return NULL;
		}
	}

	retcode = le32toh(*((uint32_t *) ((uint8_t *) data + offt)));
	offt += 4;

	if (retcode != 1) {
		free(data);
		*ret_len = -1;
		return NULL;
	}

	retlen = le32toh(*((uint32_t *) ((uint8_t *) data + offt)));
	offt += 4;

	/* Hack to apparently work around a newer firmware bug */
	if (retlen != 0 && data_len - offt == retlen + 1 && data[offt + retlen] == 0x00) {
		retlen = retlen - 1;
	}

	if (data_len - offt < retlen) {
		fprintf(stderr, "DEBUG - expected len %u got %lu\n", retlen, data_len - offt);
		free(data);
		*ret_len = -1;
		return NULL;
	}

	rdata = (char *) malloc(sizeof(char) * retlen);
	memcpy(rdata, data + offt, retlen);

	if (rdata == NULL) {
		free(data);
		*ret_len = -1;
		return NULL;
	}

	free(data);

	*ret_len = retlen;
	return rdata;

#if 0
        r = self.execute(b'\x26\x08', struct.pack('<I', int(command_id)))
        retcode, flen = r.unpack('<II')
        assert retcode == 1, f'{command_id}: got retcode {retcode}'
        # HACK: workaround for new firmware bug(?)
        if r.size() == flen + 1 and r._data[-1] == 0x00:
            r._data = r._data[:-1]
        # END OF HACK
        assert r.size() == flen, f'{command_id}: got size {r.size()}, expect {flen}'
        return r
#endif

}

int radiacode_fw_version(radiacode_comms_t *comms, radiacode_version_t *ret_ver) {
	char *resp;
	ssize_t resp_sz;
	uint8_t str_len;
	size_t resp_offt;

	resp = radiacode_execute(comms, "\x0a\x00", NULL, 0, &resp_sz);

	if (resp_sz < 8) {
		if (resp != NULL) {
			free(resp);
		}

		return -1;
	}

	memset(ret_ver, 0, sizeof(radiacode_version_t));

	resp_offt = 4;
	ret_ver->boot_minor = le16toh(*((uint16_t *) ((uint8_t *) resp + resp_offt)));
	ret_ver->boot_major = le16toh(*((uint16_t *) ((uint8_t *) resp + resp_offt + 2)));

	resp_offt += 4;
	str_len = resp[resp_offt] & 0xFF;

	if (resp_sz < resp_offt + str_len) {
		if (resp != NULL) {
			free(resp);
		}

		return -1;
	}

	snprintf(ret_ver->boot_date, min(32, str_len + 1), "%s", resp + resp_offt + 1);

	resp_offt += str_len + 1;

	ret_ver->target_minor = le16toh(*((uint16_t *) &resp[resp_offt]));
	ret_ver->target_major = le16toh(*((uint16_t *) &resp[resp_offt + 2]));

	resp_offt += 4;
	str_len = resp[resp_offt] & 0xFF;

	if (resp_sz < resp_offt + str_len) {
		if (resp != NULL) {
			free(resp);
		}

		return -1;
	}

	snprintf(ret_ver->target_date, min(32, str_len + 1), "%s", resp + resp_offt + 1);

	/*
	fprintf(stderr, "DEBUG - radiacode boot %u.%u (%s) fw %u.%u (%s)\n",
			ret_ver->boot_major, ret_ver->boot_minor, ret_ver->boot_date, 
			ret_ver->target_major, ret_ver->target_minor, ret_ver->target_date);
			*/


	return 1;

#if 0
    def fw_version(self) -> tuple[tuple[int, int, str], tuple[int, int, str]]:
        r = self.execute(b'\x0a\x00')
        boot_minor, boot_major = r.unpack('<HH')
        boot_date = r.unpack_string()
        target_minor, target_major = r.unpack('<HH')
        target_date = r.unpack_string()
        assert r.size() == 0
        return ((boot_major, boot_minor, boot_date), (target_major, target_minor, target_date.strip('\x00')))
#endif
}

int radiacode_get_data(radiacode_comms_t *comms, radiacode_data_report_t *ret_data) {
	char *data = NULL;
	ssize_t data_len;
	size_t offt = 0;
	radiacode_data_header_t *data_hdr = NULL;
	radiacode_realtimedata_t *rt_data = NULL;

	data = radiacode_read_request(comms, RADIA_VS_DATA_BUF, &data_len);

	if (data == NULL) {
		return -ENOMEM;
	}

	while (offt + sizeof(radiacode_data_header_t) < data_len) {
		data_hdr = (radiacode_data_header_t *) (data + offt);
		offt += sizeof(radiacode_data_header_t);

		if (data_hdr->eid == 0 && data_hdr->gid == 0) {
			if (offt + sizeof(radiacode_realtimedata_t) > data_len) {
				free(data);
				return -1;
			}

			rt_data = (radiacode_realtimedata_t *) (data + offt);

			/* TODO fix on BE systems */
			ret_data->count_rate = rt_data->count_rate_le;
			ret_data->dose_rate = rt_data->dose_rate_le;
			ret_data->count_rate_err = le16toh(rt_data->count_rate_err_le);
			ret_data->dose_rate_err = le16toh(rt_data->dose_rate_err_le);
			ret_data->rt_flags = rt_data->rt_flags;
		}

		/* TODO - process other reports like raw data */

		break;
	}

	free(data);
	return 1;
}

int radiacode_get_config(radiacode_comms_t *comms, char **config, size_t *config_len) {
	ssize_t data_len;

	*config = radiacode_read_request(comms, RADIA_VS_CONFIGURATION, &data_len);

	if (*config == NULL || data_len <= 0) {
		return -ENOMEM;
	}

	*config_len = data_len;

	return 1;
}

