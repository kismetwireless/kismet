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
 * https://www.radiacode.
 *
 * This datasource uses libusb to interface & requires a usb 
 * connection.
 *
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
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

#define BUFFER_SIZE 2048

typedef struct {
    libusb_context *usb_ctx;
    libusb_device_handle *usb_handle;
    libusb_device *matched_dev;

    char *name;
    char *interface;

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
	char *termpos, *nlpos;

	termpos = strstr(data, val);

	while ((size_t) (termpos - data) < (data_len - strlen(val) - 1)) {
		if (termpos != data && termpos[-1] != '\n') {
			termpos = strstr(termpos + 1, val);
			continue;
		}

		if (termpos[strlen(val)] != '=') {
			termpos = strstr(termpos + 1, val);
			continue;
		}

        nlpos = strstr(termpos, "\n");

        *ret_val = termpos + strlen(val) + 1;
        *ret_len = (size_t) (nlpos - termpos) - strlen(val) - 1;
        return 1;
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

	resp_len = le32toh(*((uint32_t *) rbuf));

	rdata = (char *) malloc(sizeof(char) * resp_len);

	if (rdata == NULL) {
		snprintf(errstr, STATUS_MAX, "%s failed to allocate buffer for USB response (%u): out of memory",
				localrad->name, resp_len);
		cf_send_message(localrad->caph, errstr, MSGFLAG_ERROR);
		*ret_len = -1;
		return NULL;
	}

	/* If the entire response already fits */
	if (resp_len < (256 - 4)) {
		memcpy(rdata, rbuf + 4, resp_len);
		*ret_len = resp_len;
		return rdata;
	}

	/* Copy the first chunk, then iterate over the rest */
	memcpy(rdata, rbuf + 4, (256 - 4));
	resp_read = (256 - 4);

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

		resp_read = resp_read + txamt;
	}

	*ret_len = resp_len;
	return rdata;

#if 0
        self._device.write(0x1, request)

        trials = 0
        max_trials = 3
        while trials < max_trials:  # repeat until non-zero lenght data received
            data = self._device.read(0x81, 256, timeout=self._timeout_ms).tobytes()
            if len(data) != 0:
                break
            else:
                trials += 1
        if trials >= max_trials:
            raise MultipleUSBReadFailure(str(trials) + ' USB Read Failures in sequence')

        response_length = struct.unpack_from('<I', data)[0]
        data = data[4:]

        while len(data) < response_length:
            r = self._device.read(0x81, response_length - len(data)).tobytes()
            data += r

        return BytesBuffer(data)
#endif
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno,
    char *definition, char *msg, char **uuid,
    cf_params_interface_t **ret_interface,
    cf_params_spectrum_t **ret_spectrum) {
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char errstr[STATUS_MAX];
    char *device = NULL;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    int x;
    int busno = -1, devno = -1;

    libusb_device **libusb_devs = NULL;
    ssize_t libusb_devices_cnt = 0;
    int r;

    int matched_device = 0;
    int num_device = 0;

	local_radiacode_t *localrad = (local_radiacode_t *) caph->userdata;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    if (strstr(interface, "radiacode-usb") != interface) {
        free(interface);
        return 0;
    }

	x = sscanf(interface, "radiacode-usb-%d-%d", &busno, &devno);
	if (x != 2) {
		busno = -1;
		x = sscanf(interface, "radiacode-usb-%d", &devno);

		if (x != 1)
			devno = -1;
	}
	free(interface);

	if (busno == -1 && devno == -1) {
		return 0;
	}

    libusb_devices_cnt = libusb_get_device_list(localrad->usb_ctx, &libusb_devs);

    if (libusb_devices_cnt < 0) {
        return 0;
    }

    for (ssize_t i = 0; i < libusb_devices_cnt; i++) {
        struct libusb_device_descriptor dev;

        r = libusb_get_device_descriptor(libusb_devs[i], &dev);

        if (r < 0) {
            continue;
        }

        if (dev.idVendor == RADIA_VID && dev.idProduct == RADIA_PID) {
            if (busno >= 0) {
                if (busno == libusb_get_bus_number(libusb_devs[i]) &&
                        devno == libusb_get_device_address(libusb_devs[i])) {
                    matched_device = 1;
                    break;
                }
            } else {
                if (num_device == devno) {
                    busno = libusb_get_bus_number(libusb_devs[i]);
                    devno = libusb_get_device_address(libusb_devs[i]);
                    matched_device = 1;
                    break;
                }
                num_device++;
            }
        }
    }

    libusb_free_device_list(libusb_devs, 1);

    if (!matched_device) {
        return 0;
    }

    /* Make a spoofed, but consistent, UUID based on the adler32 of the
     * interface name and the serial device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%06X%06X",
                adler32_csum((unsigned char *) "kismet_cap_radiacode_usb", 
                    strlen("kismet_cap_radiacode_usb")) & 0xFFFFFFFF,
                busno, devno);
        *uuid = strdup(errstr);
    }

    free(device);

    return 1;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno, char *msg,
                  cf_params_list_interface_t ***interfaces) {
    /* Basic list of devices */
    typedef struct radia_list {
        char *device;
        struct radia_list *next;
    } radia_list_t;

    radia_list_t *devs = NULL;
    size_t num_devs = 0;
    libusb_device **libusb_devs = NULL;
    ssize_t libusb_devices_cnt = 0;
    int r;
    char devname[32];
    unsigned int i;

    local_radiacode_t *localrad = (local_radiacode_t *) caph->userdata;
    libusb_devices_cnt = libusb_get_device_list(localrad->usb_ctx, &libusb_devs);

    if (libusb_devices_cnt < 0) {
        return 0;
    }

    for (ssize_t i = 0; i < libusb_devices_cnt; i++) {
        struct libusb_device_descriptor dev;

        r = libusb_get_device_descriptor(libusb_devs[i], &dev);

        if (r < 0) {
            continue;
        }

        if (dev.idVendor == RADIA_VID && dev.idProduct == RADIA_PID) {
            snprintf(devname, 32, "radiacode-usb-%u-%u", 
					libusb_get_bus_number(libusb_devs[i]),
					libusb_get_device_address(libusb_devs[i]));

            radia_list_t *d = (radia_list_t *) malloc(sizeof(radia_list_t));
            num_devs++;
            d->device = strdup(devname);
            d->next = devs;
            devs = d;
        }
    }

    libusb_free_device_list(libusb_devs, 1);

    if (num_devs == 0) {
        *interfaces = NULL;
        return 0;
    }

    *interfaces =
        (cf_params_list_interface_t **) malloc(sizeof(cf_params_list_interface_t *) * num_devs);

    i = 0;

    while (devs != NULL) {
        radia_list_t *td = devs->next;
        (*interfaces)[i] =
            (cf_params_list_interface_t *) malloc(sizeof(cf_params_list_interface_t));
        memset((*interfaces)[i], 0, sizeof(cf_params_list_interface_t));

        (*interfaces)[i]->interface = devs->device;
        (*interfaces)[i]->flags = NULL;
        (*interfaces)[i]->hardware = strdup("radiacode-usb");

        free(devs);
        devs = td;

        i++;
    }

    return num_devs;
}

int open_usb_device(kis_capture_handler_t *caph, char *errstr) {
    int r;
    local_radiacode_t *localrad = (local_radiacode_t *) caph->userdata;
	char *resp;
	ssize_t resp_len;

	char sinkbuf[256];
	int sink_len;

    /* Try to open it */
    r = libusb_open(localrad->matched_dev, &localrad->usb_handle);
    if (r < 0) {
        snprintf(errstr, STATUS_MAX, "Unable to open Radiacode USB interface: %s", 
                libusb_strerror((enum libusb_error) r));
        return -1;
    }

    if (libusb_kernel_driver_active(localrad->usb_handle, 0)) {
		snprintf(errstr, STATUS_MAX, "Radiacode %s %u/%u appears to be claimed by a kernel driver, "
				"attempting to detatch.", localrad->name, localrad->busno, localrad->devno);
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
	 * issueing commands, spin burning data until we time out */
	while (1) {
		r = libusb_bulk_transfer(localrad->usb_handle, 0x81,
				(unsigned char *) sinkbuf, 256, &sink_len, 500);
		if (r == LIBUSB_ERROR_TIMEOUT) {
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

	if (version.target_major < 4 || version.target_minor < 8) {
		snprintf(errstr, STATUS_MAX, "Old firmware version (%u.%u) found; please update the Radiacode device to at "
                "least 4.8 using the phone app.", version.target_major, version.target_minor);
		return -1;
	} else {
		snprintf(errstr, STATUS_MAX, "%s %03d/%03d Radiacode running firmware %u.%u", 
				localrad->name, localrad->busno, localrad->devno,
				version.target_major, version.target_minor);
		cf_send_message(localrad->caph, errstr, MSGFLAG_INFO);
	}

	r = radiacode_get_config(&localrad->comms, &localrad->config, &localrad->config_len);
	if (r < 0) {
		snprintf(errstr, STATUS_MAX, "%s %03d/%03d Radiacode failed to fetch "
				"device configuration block\n", 
				localrad->name, localrad->busno, localrad->devno);
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
    char errstr[STATUS_MAX];

    int x;
    int busno = -1, devno = -1;

    libusb_device **libusb_devs = NULL;
    ssize_t libusb_devices_cnt = 0;
    int r;

    int matched_device = 0;
    int num_device = 0;
    char cap_if[32];
    
    ssize_t i;

    local_radiacode_t *localrad = (local_radiacode_t *) caph->userdata;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }

    localrad->interface = strndup(placeholder, placeholder_len);

    /* Look for the interface type */
    if (strstr(localrad->interface, "radiacode-usb") != localrad->interface) {
        snprintf(msg, STATUS_MAX, "Unable to find radiacode interface"); 
        return -1;
    }

    /* Look for interface-bus-dev */
    x = sscanf(localrad->interface, "radiacode-usb-%d-%d", &busno, &devno);

    /* Look for interface-# */
    if (x != 2) {
        busno = -1;
        x = sscanf(localrad->interface, "radiacode-usb-%d", &devno);

        if (x != 1)
            devno = -1;
    }

    if (devno == -1 && busno == -1) {
        snprintf(msg, STATUS_MAX, "Malformed radiacode interface, expected 'radiacode-#' or "
                "'radiacode-bus#-dev#'"); 
        return -1;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "name", definition)) > 0) {
        localrad->name = strndup(placeholder, placeholder_len);
    } else {
        localrad->name = strdup(localrad->interface);
    }

    libusb_devices_cnt = libusb_get_device_list(localrad->usb_ctx, &libusb_devs);
    if (libusb_devices_cnt < 0) {
        snprintf(msg, STATUS_MAX, "Unable to iterate USB devices"); 
        return -1;
    }

    for (i = 0; i < libusb_devices_cnt; i++) {
        struct libusb_device_descriptor dev;

        r = libusb_get_device_descriptor(libusb_devs[i], &dev);

        if (r < 0) {
            continue;
        }

        if (dev.idVendor == RADIA_VID && dev.idProduct == RADIA_PID) {
            if (busno >= 0) {
                if (busno == libusb_get_bus_number(libusb_devs[i]) &&
                        devno == libusb_get_device_address(libusb_devs[i])) {
                    matched_device = 1;
                    localrad->matched_dev = libusb_devs[i];
                    break;
                }
            } else {
                if (num_device == devno) {
                    matched_device = 1;
                    busno = libusb_get_bus_number(libusb_devs[i]);
                    devno = libusb_get_device_address(libusb_devs[i]);
                    localrad->matched_dev = libusb_devs[i];
                    break;
                }

                num_device++;
            }
        }
    }

    libusb_free_device_list(libusb_devs, 1);

    if (!matched_device) {
        snprintf(msg, STATUS_MAX, "Unable to find Radiacode USB device");
        return -1;
    }

    snprintf(cap_if, 32, "radiacode-usb-%u-%u", busno, devno);

    localrad->devno = devno;
    localrad->busno = busno;

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%06X%06X",
                adler32_csum((unsigned char *) "kismet_cap_radiacode_usb", 
                    strlen("kismet_cap_radiacode_usb")) & 0xFFFFFFFF,
                busno, devno);
        *uuid = strdup(errstr);
    }

    (*ret_interface)->capif = strdup(cap_if);
    (*ret_interface)->hardware = strdup("radiacode-usb");

    r = open_usb_device(caph, msg);

    if (r < 0) {
        return -1;
	}

    return 1;
}

/* Run a standard glib mainloop inside the capture thread */
void capture_thread(kis_capture_handler_t *caph) {
    local_radiacode_t *localrad = (local_radiacode_t *) caph->userdata;
    char errstr[STATUS_MAX];

    radiacode_data_report_t data_report;
    char json[1024];

    int r;
    struct timeval tv;

    int fail = 0;

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

        // fprintf(stderr, "DEBUG - got CPS %f SV %f\n", data_report.count_rate, data_report.dose_rate);

        snprintf(json, 1024, "{"
                "\"cps\": %f, "
                "\"sv\": %f, "
                "\"cps_err\": %u,"
                "\"sv_err\": %u"
                "}",
                data_report.count_rate,
                data_report.dose_rate,
                data_report.count_rate_err,
                data_report.dose_rate_err);

        gettimeofday(&tv, NULL);

        while (1) {
            r = cf_send_json(caph, NULL, 0, NULL, NULL, tv, "radiacode", (char *) json);

            if (r < 0) {
                snprintf(errstr, STATUS_MAX, "%s unable to send JSON frame.", localrad->name);
                fprintf(stderr, "%s", errstr);
                cf_send_error(caph, 0, errstr);
                fail = 1;
                break;
            } else if (r == 0) {
                cf_handler_wait_ringbuffer(caph);
                continue;
            } else {
                break;
            }
        }

        if (fail) {
            break;
        }

        usleep(750000);
    }

    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_radiacode_t localrad = {
        .caph = NULL,
        .name = NULL,
        .interface = NULL,
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

	r = libusb_init(&localrad.usb_ctx);
	if (r < 0) {
		fprintf(stderr, "FATAL:  Could not initialize libusb\n");
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

    libusb_exit(localrad.usb_ctx);

    return 0;
}
