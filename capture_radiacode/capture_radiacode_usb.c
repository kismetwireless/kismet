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
 * This datasource interfaces with the Radiacode geiger counter
 * https://www.radiacode.com/
 *
 * This datasource uses libusb to interface & requires a usb 
 * connection.
 *
 */

#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../capture_framework.h"
#include "../config.h"
#include "../simple_ringbuf_c.h"
#include "../kis_endian.h"

#include "radiacode.h"

#include <libusb-1.0/libusb.h>

typedef struct {
    libusb_context *usb_ctx;
    libusb_device_handle *usb_handle;
    libusb_device *matched_dev;

    char *name;
    char *interface;
    char *capif;

	unsigned int devno, busno;

    kis_capture_handler_t *caph;

	radiacode_comms_t comms;

	char *config;
	size_t config_len;

	int spectrum_version;
} local_radiacode_t;

/* Search for a value in a block of newline-delimited text */
int find_config_val(const char *val, const char *data, size_t data_len, 
		char **ret_val, ssize_t *ret_len) {
	const size_t val_len = strlen(val);
	const char *end = data + data_len;
	const char *line = data;

	while (line < end) {
		const char *nlpos = memchr(line, '\n', end - line);
		const char *line_end = nlpos != NULL ? nlpos : end;

		if ((size_t) (line_end - line) > val_len && memcmp(line, val, val_len) == 0 &&
				line[val_len] == '=') {
			*ret_val = (char *) line + val_len + 1;
			*ret_len = line_end - (line + val_len + 1);
			return 1;
		}

		if (nlpos == NULL)
			break;

		line = nlpos + 1;
	}

    return -1;
}

char *radiacode_transport_execute(radiacode_comms_t *comms, 
		radiacode_request_t *cmd, size_t len, ssize_t *ret_len) {

	local_radiacode_t *localrad = (local_radiacode_t *) comms->auxdata;

	int r, i;
	int txamt;
	char errstr[STATUS_MAX];
	const unsigned int timeout = 500;

	char rbuf[256];

	char *rdata = NULL;
	uint32_t resp_len = 0;
	uint32_t resp_read = 0;

	if ((r = libusb_bulk_transfer(localrad->usb_handle, 0x01, 
					(unsigned char *) cmd, len, &txamt, timeout)) != 0) {
		snprintf(errstr, STATUS_MAX, "%s failed to write command to usb: %s",
				localrad->name, libusb_strerror((enum libusb_error) r));

		fprintf(stderr, "%s\n", errstr);

		cf_send_message(localrad->caph, errstr, MSGFLAG_ERROR);
		*ret_len = -1;
		return NULL;
	}

	/* Read the result of the command, which will include the length of the full
	 * response which we will then need to allocate and read */
	errstr[0] = 0;
	for (i = 0; i < 5; i++) {
		if ((r = libusb_bulk_transfer(localrad->usb_handle, 0x81, 
						(unsigned char *) rbuf, 256, &txamt, timeout)) < 0) {
			/* Save the last error code */
			snprintf(errstr, STATUS_MAX, "%s failed to read results from usb: %s",
					localrad->name, libusb_strerror((enum libusb_error) r));
		} else {
			errstr[0] = 0;
			break;
		}

		usleep(1000);
	}

	if (strlen(errstr) != 0) {
		cf_send_message(localrad->caph, errstr, MSGFLAG_ERROR);
		*ret_len = -1;
		return NULL;
	}

	if (txamt < 4) {
		snprintf(errstr, STATUS_MAX, "%s failed to read full response from usb: "
				"result too short for command response", localrad->name);
		cf_send_message(localrad->caph, errstr, MSGFLAG_ERROR);
		*ret_len = -1;
		return NULL;
	}

	memcpy(&resp_len, rbuf, sizeof(resp_len));
	resp_len = le32toh(resp_len);

	/* responses are spectra and config text, a few KB */
	if (resp_len > 1024 * 1024) {
		snprintf(errstr, STATUS_MAX, "%s invalid USB response length (%u)",
				localrad->name, resp_len);
		cf_send_message(localrad->caph, errstr, MSGFLAG_ERROR);
		*ret_len = -1;
		return NULL;
	}

	rdata = (char *) malloc(sizeof(char) * resp_len);

	if (rdata == NULL) {
		snprintf(errstr, STATUS_MAX, "%s failed to allocate buffer for USB response (%u): out of memory",
				localrad->name, resp_len);
		cf_send_message(localrad->caph, errstr, MSGFLAG_ERROR);
		*ret_len = -1;
		return NULL;
	}

	/* Copy what came with the length, then read the rest */
	resp_read = (uint32_t) (txamt - 4);
	if (resp_read > resp_len)
		resp_read = resp_len;

	memcpy(rdata, rbuf + 4, resp_read);

	while (resp_read < resp_len) {
		if ((r = libusb_bulk_transfer(localrad->usb_handle, 0x81,
						(unsigned char *) rdata + resp_read, resp_len - resp_read, 
						&txamt, timeout)) != 0) {
			snprintf(errstr, STATUS_MAX, "%s failed to read results from usb: %s",
					localrad->name, libusb_strerror((enum libusb_error) r));
			cf_send_message(localrad->caph, errstr, MSGFLAG_ERROR);
			free(rdata);
			*ret_len = -1;
			return NULL;
		}

		/* an empty read never advances and would spin forever */
		if (txamt <= 0) {
			snprintf(errstr, STATUS_MAX, "%s failed to read results from usb: empty transfer",
					localrad->name);
			cf_send_message(localrad->caph, errstr, MSGFLAG_ERROR);
			free(rdata);
			*ret_len = -1;
			return NULL;
		}

		resp_read = resp_read + txamt;
	}

	*ret_len = resp_len;
	return rdata;

}

/* One Radiacode found on the bus */
typedef struct {
    libusb_device *dev;
    unsigned int busno, devno;
    char serial[64];
} radia_usb_dev_t;

typedef enum {
    RADIA_SPEC_ANY,
    RADIA_SPEC_INDEX,
    RADIA_SPEC_BUSDEV,
    RADIA_SPEC_SERIAL,
} radia_spec_type_t;

typedef struct {
    radia_spec_type_t type;
    unsigned int index, busno, devno;
    char serial[64];
} radia_spec_t;

static int radia_serial_char(char c) {
    return isalnum((unsigned char) c) || c == '-' || c == '_' || c == '.';
}

/* Parse 'radiacode', 'radiacode-N', 'radiacode-BUS-DEV', or 'radiacode-SERIAL',
 * with an optional '-usb' after 'radiacode' */
static int parse_radia_interface(const char *iface, radia_spec_t *spec) {
    const char *p;
    size_t len, i;
    int all_digits = 1, dashes = 0;
    unsigned long v;

    memset(spec, 0, sizeof(radia_spec_t));

    if (strncmp(iface, "radiacode", 9) != 0)
        return -1;

    p = iface + 9;

    if (strncmp(p, "-usb", 4) == 0 && (p[4] == 0 || p[4] == '-'))
        p += 4;

    if (*p == 0) {
        spec->type = RADIA_SPEC_ANY;
        return 1;
    }

    if (*p != '-')
        return -1;

    p++;
    len = strlen(p);

    if (len == 0 || len >= sizeof(spec->serial))
        return -1;

    for (i = 0; i < len; i++) {
        if (!radia_serial_char(p[i]))
            return -1;

        if (p[i] == '-')
            dashes++;
        else if (!isdigit((unsigned char) p[i]))
            all_digits = 0;
    }

    if (all_digits && dashes == 0 && len <= 3) {
        spec->type = RADIA_SPEC_INDEX;
        spec->index = (unsigned int) strtoul(p, NULL, 10);
        return 1;
    }

    if (all_digits && dashes == 1 && p[0] != '-' && p[len - 1] != '-' && len <= 7) {
        v = strtoul(p, NULL, 10);
        spec->busno = (unsigned int) v;
        v = strtoul(strchr(p, '-') + 1, NULL, 10);
        spec->devno = (unsigned int) v;
        spec->type = RADIA_SPEC_BUSDEV;
        return 1;
    }

    spec->type = RADIA_SPEC_SERIAL;
    memcpy(spec->serial, p, len);
    spec->serial[len] = 0;
    return 1;
}

/* Read the USB serial number; left empty if it can't be read or holds
 * anything unsafe for an interface name */
static void read_radia_serial(libusb_device *dev, uint8_t idx, char *out, size_t out_sz) {
    libusb_device_handle *h;
    unsigned char buf[64];
    int r, i;

    out[0] = 0;

    if (idx == 0 || libusb_open(dev, &h) != 0)
        return;

    r = libusb_get_string_descriptor_ascii(h, idx, buf, sizeof(buf));
    libusb_close(h);

    if (r <= 0 || (size_t) r >= out_sz)
        return;

    for (i = 0; i < r; i++) {
        if (!radia_serial_char((char) buf[i]))
            return;
    }

    memcpy(out, buf, r);
    out[r] = 0;
}

/* List attached Radiacodes; each holds a device reference, release with
 * free_radia_devs */
static ssize_t find_radia_devs(libusb_context *ctx, radia_usb_dev_t **ret_devs) {
    libusb_device **list = NULL;
    radia_usb_dev_t *devs;
    ssize_t cnt, i, n = 0;

    *ret_devs = NULL;

    cnt = libusb_get_device_list(ctx, &list);
    if (cnt < 0)
        return -1;

    devs = (radia_usb_dev_t *) calloc(cnt > 0 ? cnt : 1, sizeof(radia_usb_dev_t));
    if (devs == NULL) {
        libusb_free_device_list(list, 1);
        return -1;
    }

    for (i = 0; i < cnt; i++) {
        struct libusb_device_descriptor desc;

        if (libusb_get_device_descriptor(list[i], &desc) < 0)
            continue;

        if (desc.idVendor != RADIA_VID || desc.idProduct != RADIA_PID)
            continue;

        devs[n].dev = libusb_ref_device(list[i]);
        devs[n].busno = libusb_get_bus_number(list[i]);
        devs[n].devno = libusb_get_device_address(list[i]);
        read_radia_serial(list[i], desc.iSerialNumber, devs[n].serial, sizeof(devs[n].serial));
        n++;
    }

    libusb_free_device_list(list, 1);

    *ret_devs = devs;
    return n;
}

static void free_radia_devs(radia_usb_dev_t *devs, ssize_t n) {
    ssize_t i;

    if (devs == NULL)
        return;

    for (i = 0; i < n; i++)
        libusb_unref_device(devs[i].dev);

    free(devs);
}

/* Index of the device a spec names, -1 for none, -2 if 'radiacode' alone
 * matches more than one */
static ssize_t match_radia_dev(const radia_spec_t *spec, const radia_usb_dev_t *devs, ssize_t n) {
    ssize_t i;

    switch (spec->type) {
        case RADIA_SPEC_ANY:
            if (n == 1)
                return 0;
            return n == 0 ? -1 : -2;
        case RADIA_SPEC_INDEX:
            return (ssize_t) spec->index < n ? (ssize_t) spec->index : -1;
        case RADIA_SPEC_BUSDEV:
            for (i = 0; i < n; i++) {
                if (devs[i].busno == spec->busno && devs[i].devno == spec->devno)
                    return i;
            }
            return -1;
        case RADIA_SPEC_SERIAL:
            for (i = 0; i < n; i++) {
                if (strcmp(devs[i].serial, spec->serial) == 0)
                    return i;
            }
            return -1;
    }

    return -1;
}

/* Interface names use the serial, which survives the device moving to a new
 * USB address on reset or replug */
static void radia_dev_name(const radia_usb_dev_t *dev, char *buf, size_t buf_sz) {
    if (dev->serial[0] != 0)
        snprintf(buf, buf_sz, "radiacode-usb-%s", dev->serial);
    else
        snprintf(buf, buf_sz, "radiacode-usb-%u-%u", dev->busno, dev->devno);
}

static char *radia_dev_uuid(const radia_usb_dev_t *dev, char *definition) {
    char *placeholder;
    int placeholder_len;
    char buf[64];
    uint32_t base = adler32_csum((unsigned char *) "kismet_cap_radiacode_usb",
            strlen("kismet_cap_radiacode_usb")) & 0xFFFFFFFF;

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0)
        return strndup(placeholder, placeholder_len);

    if (dev->serial[0] != 0)
        snprintf(buf, sizeof(buf), "%08X-0000-0000-0000-0000%08X", base,
                adler32_csum((unsigned char *) dev->serial, strlen(dev->serial)) & 0xFFFFFFFF);
    else
        snprintf(buf, sizeof(buf), "%08X-0000-0000-0000-%06X%06X", base,
                dev->busno, dev->devno);

    return strdup(buf);
}

static int radia_init_usb(local_radiacode_t *localrad, char *msg) {
    if (localrad->usb_ctx != NULL)
        return 1;

    if (libusb_init(&localrad->usb_ctx) < 0) {
        localrad->usb_ctx = NULL;
        snprintf(msg, STATUS_MAX, "radiacode: could not initialize libusb");
        return -1;
    }

    return 1;
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno,
    char *definition, char *msg, char **uuid,
    cf_params_interface_t **ret_interface,
    cf_params_spectrum_t **ret_spectrum) {
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char cap_if[96];
    radia_spec_t spec;
    radia_usb_dev_t *devs = NULL;
    ssize_t num_devs, m;
    int r;

    local_radiacode_t *localrad = (local_radiacode_t *) caph->userdata;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);
    if (interface == NULL)
        return 0;

    r = parse_radia_interface(interface, &spec);
    free(interface);

    if (r < 0) {
        snprintf(msg, STATUS_MAX, "Expected a radiacode interface, skipping");
        return 0;
    }

    if (radia_init_usb(localrad, msg) < 0)
        return 0;

    num_devs = find_radia_devs(localrad->usb_ctx, &devs);
    if (num_devs < 0) {
        snprintf(msg, STATUS_MAX, "Unable to iterate USB devices");
        return 0;
    }

    m = match_radia_dev(&spec, devs, num_devs);

    if (m == -1) {
        snprintf(msg, STATUS_MAX, "No matching Radiacode USB device found");
        free_radia_devs(devs, num_devs);
        return 0;
    }

    /* More than one for a plain 'radiacode'; claim it so opening can say
     * which names to use */
    if (m >= 0) {
        radia_dev_name(&devs[m], cap_if, sizeof(cap_if));
        (*ret_interface)->capif = strdup(cap_if);
        (*ret_interface)->hardware = strdup("radiacode-usb");
        *uuid = radia_dev_uuid(&devs[m], definition);
    }

    free_radia_devs(devs, num_devs);

    return 1;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno, char *msg,
                  cf_params_list_interface_t ***interfaces) {
    radia_usb_dev_t *devs = NULL;
    ssize_t num_devs, i;
    char devname[96];

    local_radiacode_t *localrad = (local_radiacode_t *) caph->userdata;

    *interfaces = NULL;

    if (radia_init_usb(localrad, msg) < 0)
        return 0;

    num_devs = find_radia_devs(localrad->usb_ctx, &devs);

    if (num_devs <= 0) {
        free_radia_devs(devs, num_devs < 0 ? 0 : num_devs);
        return 0;
    }

    *interfaces =
        (cf_params_list_interface_t **) calloc(num_devs, sizeof(cf_params_list_interface_t *));

    if (*interfaces == NULL) {
        free_radia_devs(devs, num_devs);
        return 0;
    }

    for (i = 0; i < num_devs; i++) {
        (*interfaces)[i] =
            (cf_params_list_interface_t *) calloc(1, sizeof(cf_params_list_interface_t));

        if ((*interfaces)[i] == NULL)
            break;

        radia_dev_name(&devs[i], devname, sizeof(devname));
        (*interfaces)[i]->interface = strdup(devname);
        (*interfaces)[i]->flags = NULL;
        (*interfaces)[i]->hardware = strdup("radiacode-usb");
    }

    free_radia_devs(devs, num_devs);

    return (int) i;
}

int open_usb_device(kis_capture_handler_t *caph, char *errstr) {
    int r;
    local_radiacode_t *localrad = (local_radiacode_t *) caph->userdata;
	char *resp;
	ssize_t resp_len;

	char sinkbuf[256];
	int sink_len;
	int i;

    /* Try to open it */
    r = libusb_open(localrad->matched_dev, &localrad->usb_handle);
    if (r < 0) {
        snprintf(errstr, STATUS_MAX, "Unable to open Radiacode USB interface: %s", 
                libusb_strerror((enum libusb_error) r));
        return -1;
    }

    if (libusb_kernel_driver_active(localrad->usb_handle, 0)) {
		snprintf(errstr, STATUS_MAX, "Radiacode %s appears to be claimed by a kernel driver, "
				"attempting to detach.", localrad->name);
		cf_send_message(caph, errstr, MSGFLAG_INFO);

        r = libusb_detach_kernel_driver(localrad->usb_handle, 0); 

        if (r < 0) {
            snprintf(errstr, STATUS_MAX, "Unable to open Radiacode USB interface, "
                    "could not disconnect kernel drivers: %s",
                    libusb_strerror((enum libusb_error) r));
            return -1;
        }
    }

	/* With a reset command, the radiacode usb stack appears to have a chance of crashing
	 * until disconnected and power cycled.  Unfortunately, without the reset, it appears to
	 * frequently fail and ignore startup commands entirely.  */
	libusb_reset_device(localrad->usb_handle);

    /* config */
    r = libusb_set_configuration(localrad->usb_handle, 1);
    if (r < 0) {
        snprintf(errstr, STATUS_MAX,
                 "Unable to open Radiacode USB interface; could not set USB configuration.");
        return -1;
    }

    /* Try to claim it */
    r = libusb_claim_interface(localrad->usb_handle, 0);
    if (r < 0) {
        if (r == LIBUSB_ERROR_BUSY) {
            /* Try to detach the kernel driver */
            r = libusb_detach_kernel_driver(localrad->usb_handle, 0);
            if (r < 0) {
                snprintf(errstr, STATUS_MAX, "Unable to open Radiacode USB interface, and unable "
                        "to disconnect existing driver: %s", 
                        libusb_strerror((enum libusb_error) r));
                return -1;
            }
        } else {
            snprintf(errstr, STATUS_MAX, "Unable to open Radiacode USB interface: %s",
                    libusb_strerror((enum libusb_error) r));
            return -1;
        }
    }

	/* It appears the radiacode needs to sink all pending io on open before
	 * issuing commands, spin burning data until we time out */
	for (i = 0; i < 1000; i++) {
		r = libusb_bulk_transfer(localrad->usb_handle, 0x81,
				(unsigned char *) sinkbuf, 256, &sink_len, 500);
		if (r != 0) {
			break;
		}
	}
			
	resp =
		radiacode_execute(&localrad->comms, 
				"\x07\x00", 
				"\x01\xff\x12\xff", 4, &resp_len);

	if (resp == NULL) {
		snprintf(errstr, STATUS_MAX, "Unable to initialize Radiacode USB device");
		return -1;
	}

	free(resp);
	resp = NULL;

	radiacode_version_t version;
	if (radiacode_fw_version(&localrad->comms, &version) < 0) {
		snprintf(errstr, STATUS_MAX, "Unable to fetch the firmware version");
		return -1;
	}

	if (version.target_major < 4 || (version.target_major == 4 && version.target_minor < 8)) {
		snprintf(errstr, STATUS_MAX, "Old firmware version (%u.%u) found; please update the Radiacode device to at "
                "least 4.8 using the phone app.", version.target_major, version.target_minor);
		return -1;
	} else {
		if (strcmp(localrad->name, localrad->capif) == 0)
			snprintf(errstr, STATUS_MAX, "%s Radiacode running firmware %u.%u",
					localrad->name, version.target_major, version.target_minor);
		else
			snprintf(errstr, STATUS_MAX, "%s Radiacode %s running firmware %u.%u",
					localrad->name, localrad->capif,
					version.target_major, version.target_minor);
		cf_send_message(localrad->caph, errstr, MSGFLAG_INFO);
	}

	r = radiacode_get_config(&localrad->comms, &localrad->config, &localrad->config_len);
	if (r < 0) {
		snprintf(errstr, STATUS_MAX, "%s Radiacode failed to fetch "
				"device configuration block", localrad->name);
		return -1;
	}

	r = find_config_val("SpecFormatVersion", localrad->config, localrad->config_len,
			&resp, &resp_len);
	if (r >= 0 && resp_len > 0) {
		localrad->spectrum_version = resp[0] - '0';
		// fprintf(stderr, "DEBUG - specformatversion %d\n", localrad->spectrum_version);
	}

    return 1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
    char *msg, uint32_t *dlt, char **uuid,
    cf_params_interface_t **ret_interface,
    cf_params_spectrum_t **ret_spectrum) {
    char *placeholder;
    int placeholder_len;
    char cap_if[96];
    radia_spec_t spec;
    radia_usb_dev_t *devs = NULL;
    ssize_t num_devs, m, i;
    size_t msg_len;
    int r;

    local_radiacode_t *localrad = (local_radiacode_t *) caph->userdata;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }

    localrad->interface = strndup(placeholder, placeholder_len);
    if (localrad->interface == NULL) {
        snprintf(msg, STATUS_MAX, "Unable to allocate interface");
        return -1;
    }

    if (parse_radia_interface(localrad->interface, &spec) < 0) {
        snprintf(msg, STATUS_MAX, "Malformed radiacode interface, expected 'radiacode', "
                "'radiacode-usb-SERIAL', 'radiacode-usb-#', or 'radiacode-usb-BUS-DEV'");
        return -1;
    }

    if (radia_init_usb(localrad, msg) < 0)
        return -1;

    num_devs = find_radia_devs(localrad->usb_ctx, &devs);
    if (num_devs < 0) {
        snprintf(msg, STATUS_MAX, "Unable to iterate USB devices"); 
        return -1;
    }

    m = match_radia_dev(&spec, devs, num_devs);

    if (m == -2) {
        msg_len = (size_t) snprintf(msg, STATUS_MAX, "Found %zd Radiacode devices, pick one "
                "by serial number:", num_devs);

        for (i = 0; i < num_devs && msg_len < STATUS_MAX; i++) {
            radia_dev_name(&devs[i], cap_if, sizeof(cap_if));
            msg_len += (size_t) snprintf(msg + msg_len, STATUS_MAX - msg_len, " %s", cap_if);
        }

        free_radia_devs(devs, num_devs);
        return -1;
    }

    if (m < 0) {
        snprintf(msg, STATUS_MAX, "Unable to find Radiacode USB device");
        free_radia_devs(devs, num_devs);
        return -1;
    }

    localrad->matched_dev = libusb_ref_device(devs[m].dev);
    localrad->busno = devs[m].busno;
    localrad->devno = devs[m].devno;

    radia_dev_name(&devs[m], cap_if, sizeof(cap_if));
    *uuid = radia_dev_uuid(&devs[m], definition);

    free_radia_devs(devs, num_devs);

    localrad->capif = strdup(cap_if);

    if ((placeholder_len = cf_find_flag(&placeholder, "name", definition)) > 0) {
        localrad->name = strndup(placeholder, placeholder_len);
    } else {
        localrad->name = strdup(cap_if);
    }

    if (localrad->capif == NULL || localrad->name == NULL || *uuid == NULL) {
        snprintf(msg, STATUS_MAX, "Unable to allocate Radiacode interface");
        return -1;
    }

    (*ret_interface)->capif = strdup(localrad->capif);
    (*ret_interface)->hardware = strdup("radiacode-usb");

    r = open_usb_device(caph, msg);

    /* the open handle holds its own reference */
    libusb_unref_device(localrad->matched_dev);
    localrad->matched_dev = NULL;

    if (r < 0) {
        return -1;
	}

    if (spec.type == RADIA_SPEC_BUSDEV && strcmp(localrad->capif, localrad->interface) != 0) {
        snprintf(msg, STATUS_MAX, "%s Radiacode USB addresses change when the device resets or "
                "is plugged in again; use '%s' to find this device reliably",
                localrad->name, localrad->capif);
        cf_send_message(caph, msg, MSGFLAG_INFO);
        msg[0] = 0;
    }

    return 1;
}

static int send_radia_json(kis_capture_handler_t *caph, struct timeval tv, const char *json) {
    local_radiacode_t *localrad = (local_radiacode_t *) caph->userdata;
    char errstr[STATUS_MAX];
    int r;

    while (1) {
        r = cf_send_json(caph, NULL, 0, NULL, NULL, tv, "radiacode", (char *) json);

        if (r < 0) {
            snprintf(errstr, STATUS_MAX, "%s unable to send JSON frame.", localrad->name);
            cf_send_error(caph, 0, errstr);
            return -1;
        } else if (r == 0) {
            cf_handler_wait_ringbuffer(caph);
            continue;
        }

        return 1;
    }
}

static struct timeval radia_tv_add_ms(struct timeval base, int64_t ms) {
    int64_t usec = (int64_t) base.tv_sec * 1000000 + base.tv_usec + ms * 1000;
    struct timeval tv;

    tv.tv_sec = usec / 1000000;
    tv.tv_usec = usec % 1000000;

    return tv;
}

void capture_thread(kis_capture_handler_t *caph) {
    local_radiacode_t *localrad = (local_radiacode_t *) caph->userdata;
    char errstr[STATUS_MAX];

    radiacode_data_report_t data_report;
    char json[1024];

    int r;
    unsigned int i;
    struct timeval now, tv;

    /* Real-time records count in device time; tie it to the host clock so
     * one-per-second records land one per second, not bunched on poll times */
    struct timeval anchor_tv;
    int32_t anchor_ts = 0;
    int have_anchor = 0;
    int64_t drift_ms;

    while (1) {
        if (caph->spindown) {
            break;
        }

        r = radiacode_get_data(&localrad->comms, &data_report);
        if (r < 0) {
            snprintf(errstr, STATUS_MAX, "%s error fetching data from Radiacode device",
                    localrad->name);
            cf_send_message(caph, errstr, MSGFLAG_ERROR);
            break;
        }

        gettimeofday(&now, NULL);

        if (data_report.num_rt > 0) {
            int32_t newest = data_report.rt[data_report.num_rt - 1].ts_offset;

            if (have_anchor) {
                tv = radia_tv_add_ms(anchor_tv,
                        ((int64_t) newest - anchor_ts) * RADIA_DATA_TS_UNIT_MS);
                drift_ms = ((int64_t) tv.tv_sec - now.tv_sec) * 1000 +
                    ((int64_t) tv.tv_usec - now.tv_usec) / 1000;

                if (drift_ms > 2000 || drift_ms < -2000)
                    have_anchor = 0;
            }

            if (!have_anchor) {
                anchor_tv = now;
                anchor_ts = newest;
                have_anchor = 1;
            }
        }

        for (i = 0; i < data_report.num_rt; i++) {
            radiacode_realtime_t *rt = &data_report.rt[i];

            if (!isfinite(rt->count_rate) || !isfinite(rt->dose_rate))
                continue;

            snprintf(json, sizeof(json), "{"
                    "\"cps\": %.9g, "
                    "\"sv\": %.9g, "
                    "\"cps_err\": %u, "
                    "\"sv_err\": %u"
                    "}",
                    rt->count_rate, rt->dose_rate,
                    rt->count_rate_err, rt->dose_rate_err);

            tv = radia_tv_add_ms(anchor_tv,
                    ((int64_t) rt->ts_offset - anchor_ts) * RADIA_DATA_TS_UNIT_MS);

            if (send_radia_json(caph, tv, json) < 0)
                goto spindown;
        }

        if (data_report.have_rare && isfinite(data_report.rare.dose)) {
            snprintf(json, sizeof(json), "{"
                    "\"dose_total\": %.9g, "
                    "\"dose_duration\": %u, "
                    "\"temperature\": %u, "
                    "\"charge\": %u"
                    "}",
                    data_report.rare.dose, data_report.rare.duration,
                    data_report.rare.temperature, data_report.rare.charge_level);

            if (send_radia_json(caph, now, json) < 0)
                goto spindown;
        }

        usleep(500000);
    }

spindown:
    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_radiacode_t localrad = {
        .caph = NULL,
        .name = NULL,
        .interface = NULL,
        .capif = NULL,
        .matched_dev = NULL,
		.usb_ctx = NULL,
		.usb_handle = NULL,
		.config = NULL,
		.config_len = 0,
		.spectrum_version = 0,
    };

	memset(&localrad.comms, 0, sizeof(radiacode_comms_t));
	localrad.comms.auxdata = &localrad;

	int r;

    kis_capture_handler_t *caph = cf_handler_init("radiacode-usb");

    if (caph == NULL) {
        fprintf(stderr,
            "FATAL: Could not allocate basic handler data, your system "
            "is very low on RAM or something is wrong.\n");
        return -1;
    }

    localrad.caph = caph;

    cf_handler_set_userdata(caph, &localrad);
	cf_handler_set_listdevices_cb(caph, list_callback);
    cf_handler_set_open_cb(caph, open_callback);
    cf_handler_set_probe_cb(caph, probe_callback); /**/
    cf_handler_set_capture_cb(caph, capture_thread);

    r = cf_handler_parse_opts(caph, argc, argv);
    if (r == 0) {
        return 0;
    } else if (r < 0) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    /* Support remote capture by launching the remote loop */
    cf_handler_remote_capture(caph);

    /* Jail our ns */
    cf_jail_filesystem(caph);

    /* Strip our privs */
    cf_drop_most_caps(caph);

    cf_handler_loop(caph);

    cf_handler_shutdown(caph);

    if (localrad.usb_ctx != NULL) {
        libusb_exit(localrad.usb_ctx);
    }

    return 0;
}
