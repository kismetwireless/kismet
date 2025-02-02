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
 * This datasource interfaces with the TCP service on the ANTSDR running a
 * DJI DroneID demodulation
 *
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../capture_framework.h"
#include "../config.h"
#include "../kis_endian.h"

#define BUFFER_SIZE 2048

typedef struct {
    char *name;

    char *interface;

    char *host;
    unsigned int port;

    kis_capture_handler_t *caph;

    int client_fd;

} local_droneid_t;

int is_valid_utf8(const char* string, size_t len) {
    const unsigned char * bytes = (const unsigned char *) string;
    size_t pos = 0;
    unsigned int cp;
    int num;

    while (*bytes != 0x00 && pos < len) {
        pos++;

        if ((*bytes & 0x80) == 0x00) {
            cp = (*bytes & 0x7F);
            num = 1;
        } else if ((*bytes & 0xE0) == 0xC0) {
            cp = (*bytes & 0x1F);
            num = 2;
        } else if ((*bytes & 0xF0) == 0xE0) {
            cp = (*bytes & 0x0F);
            num = 3;
        } else if ((*bytes & 0xF8) == 0xF0) {
            cp = (*bytes & 0x07);
            num = 4;
        } else {
            return 0;
        }

        bytes += 1;
        for (int i = 1; i < num; ++i) {
            if ((*bytes & 0xC0) != 0x80) {
                return 0;
            }
            cp = (cp << 6) | (*bytes & 0x3F);
            bytes += 1;
        }

        if ((cp > 0x10FFFF) || ((cp >= 0xD800) && (cp <= 0xDFFF)) ||
            ((cp <= 0x007F) && (num != 1)) ||
            ((cp >= 0x0080) && (cp <= 0x07FF) && (num != 2)) ||
            ((cp >= 0x0800) && (cp <= 0xFFFF) && (num != 3)) ||
            ((cp >= 0x10000) && (cp <= 0x1FFFFF) && (num != 4)))
            return 0;
    }

    return 1;
}

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno,
    char *definition, char *msg, char **uuid,
    cf_params_interface_t **ret_interface,
    cf_params_spectrum_t **ret_spectrum) {

    char *placeholder = NULL;
    int placeholder_len;

    char *host = NULL;
    int host_len;

    char *interface;
    char errstr[STATUS_MAX];
    char *device = NULL;

    uint32_t hp_csum = 0;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    if (strstr(interface, "antsdr-droneid") != interface) {
        free(interface);
        return 0;
    }

	free(interface);

    if ((host_len = cf_find_flag(&host, "host", definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "antsdr-droneid requires a host= field "
                "in the capture definition with the address of the antsdr "
                "device");
        return 0;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "port", definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "antsdr-droneid requires a port= field "
                "in the capture definition with the TCP port of the antsdr "
                "droneid service");
        return 0;
    }

    hp_csum = adler32_csum((unsigned char *) host, host_len);
    hp_csum = adler32_append_csum((unsigned char *) placeholder, placeholder_len, hp_csum); 

    /* Make a spoofed, but consistent, UUID based on the adler32 of the
     * interface name and the serial device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-0000%08X",
                adler32_csum((unsigned char *) "kismet_cap_antsdr_droneid", 
                    strlen("kismet_cap_antsdr_droneid")) & 0xFFFFFFFF,
                hp_csum);
        *uuid = strdup(errstr);
    }

    free(device);

    return 1;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno, char *msg,
                  cf_params_list_interface_t ***interfaces) {
    return 0;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
    char *msg, uint32_t *dlt, char **uuid,
    cf_params_interface_t **ret_interface,
    cf_params_spectrum_t **ret_spectrum) {
    char *placeholder;
    int placeholder_len;
    char errstr[STATUS_MAX];

    char cap_if[32];
    uint32_t hp_csum;

    struct hostent *connect_host;
    struct sockaddr_in client_sock, local_sock;
    int sock_flags;

    local_droneid_t *localdrone = (local_droneid_t *) caph->userdata;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }

    localdrone->interface = strndup(placeholder, placeholder_len);

    /* Look for the interface type */
    if (strstr(localdrone->interface, "antsdr-droneid") != localdrone->interface) {
        snprintf(msg, STATUS_MAX, "Did not match antsdr-droneid interface name"); 
        return -1;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "name", definition)) > 0) {
        localdrone->name = strndup(placeholder, placeholder_len);
    } else {
        localdrone->name = strdup(localdrone->interface);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "host", definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "antsdr-droneid requires a host= field "
                "in the capture definition with the address of the antsdr "
                "device");
        return -1;
    }

    localdrone->host = strndup(placeholder, placeholder_len);

    if ((placeholder_len = cf_find_flag(&placeholder, "port", definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "antsdr-droneid requires a port= field "
                "in the capture definition with the TCP port of the antsdr "
                "droneid service");
        return -1;
    }

    if (sscanf(placeholder, "%u", &localdrone->port) != 1) {
        snprintf(msg, STATUS_MAX, "antsdr-droneid requires a port= field "
                "in the capture definition with the TCP port of the antsdr "
                "droneid service; invalid port provided");
        return -1;
    }

    hp_csum = adler32_csum((unsigned char *) localdrone->host, strlen(localdrone->host));
    hp_csum = adler32_append_csum((unsigned char *) placeholder, placeholder_len, hp_csum); 

    /* Make a spoofed, but consistent, UUID based on the adler32 of the
     * interface name and the serial device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-0000%08X",
                adler32_csum((unsigned char *) "kismet_cap_antsdr_droneid", 
                    strlen("kismet_cap_antsdr_droneid")) & 0xFFFFFFFF,
                hp_csum);
        *uuid = strdup(errstr);
    }

    snprintf(cap_if, 32, "antsdr-droneid-%u", hp_csum);

    (*ret_interface)->capif = strdup(cap_if);
    (*ret_interface)->hardware = strdup("antsdr-droneid");

    if ((connect_host = gethostbyname(localdrone->host)) == NULL) {
        snprintf(msg, STATUS_MAX, "%s could not resolve hostname '%s' for "
                "antsdr connection\n", localdrone->name, localdrone->host);
        return -1;
    }

    memset(&client_sock, 0, sizeof(client_sock));
    client_sock.sin_family = connect_host->h_addrtype;
    memcpy((char *) &(client_sock.sin_addr.s_addr), connect_host->h_addr_list[0],
            connect_host->h_length);
    client_sock.sin_port = htons(localdrone->port);

    if ((localdrone->client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        snprintf(msg, STATUS_MAX, "Could not connect to remote host '%s:%u': %s",
                localdrone->host, localdrone->port, strerror(errno));
        return -1;
    }

    memset(&local_sock, 0, sizeof(local_sock));
    local_sock.sin_family = AF_INET;
    local_sock.sin_addr.s_addr = htonl(INADDR_ANY);
    local_sock.sin_port = htons(0);

    if (bind(localdrone->client_fd, (struct sockaddr *) &local_sock, sizeof(local_sock)) < 0) {
        snprintf(msg, STATUS_MAX, "Could not connect to remote host '%s:%u': %s",
                localdrone->host, localdrone->port, strerror(errno));
        close(localdrone->client_fd);
        return -1;
    }

    if (connect(localdrone->client_fd, (struct sockaddr *) &client_sock, sizeof(client_sock)) < 0) {
        snprintf(msg, STATUS_MAX, "Could not connect to remote host '%s:%u': %s",
                localdrone->host, localdrone->port, strerror(errno));
        close(localdrone->client_fd);
        return -1;
    }

    sock_flags = fcntl(localdrone->client_fd, F_GETFL, 0);
    fcntl(localdrone->client_fd, F_SETFL, sock_flags | FD_CLOEXEC);

    return 1;
}

/* Run a standard glib mainloop inside the capture thread */
void capture_thread(kis_capture_handler_t *caph) {
    local_droneid_t *localdrone = (local_droneid_t *) caph->userdata;
    char errstr[STATUS_MAX];

    /* Little endian frame header struct from antsdr */
    struct antsdr_frame {
        uint16_t header;
        uint8_t packet_type;
        uint16_t length;
        char data[0];
    } __attribute__ ((packed));

    /* Little endian binary struct from antsdr; doubles assumed to be
     * little endian 8 bytes */
    struct antsdr_droneid {
        char serial[64];
        char device_type[64];
        uint8_t device_type_8;
        double app_lat;
        double app_lon;
        double drone_lat;
        double drone_lon;
        double height;
        double altitude;
        double home_lat;
        double home_lon;
        double freq;
        double speed_e;
        double speed_n;
        double speed_u;
        uint32_t rssi;
    } __attribute__ ((packed));

    const ssize_t tcp_buf_max = 4096;
    char tcp_buf[tcp_buf_max];

    char json[2048];

    int r;
    struct timeval tv;

    int fail = 0;

    ssize_t amt_read;

    struct antsdr_frame *ant_frame;
    struct antsdr_droneid *ant_droneid;

    uint8_t pkt_type;
    size_t pkt_len;

    while (1) {
        if (caph->spindown) {
            break;
        }

        /* read the header */
        amt_read = recv(localdrone->client_fd, tcp_buf, sizeof(struct antsdr_frame), 0);

        if (amt_read <= 0) {
            if (errno && errno != EINTR && errno != EAGAIN) {
                snprintf(errstr, STATUS_MAX, "%s tcp connection error: %s",
                        localdrone->name, strerror(errno));
                cf_send_message(caph, errstr, MSGFLAG_ERROR);
                break;
            }

            continue;
        }

        ant_frame = (struct antsdr_frame *) tcp_buf;

        if (ant_frame->length + sizeof(struct antsdr_frame) > tcp_buf_max) {
            snprintf(errstr, STATUS_MAX, "%s tcp connection error: impossibly large droneid report",
                    localdrone->name);
            cf_send_message(caph, errstr, MSGFLAG_ERROR);
            break;
        }

        pkt_len = ant_frame->length;
        pkt_type = ant_frame->packet_type;

        /* Read the rest of the packet */
        amt_read = recv(localdrone->client_fd, tcp_buf, pkt_len, 0);

        if (amt_read <= 0) {
            if (errno && errno != EINTR && errno != EAGAIN) {
                snprintf(errstr, STATUS_MAX, "%s tcp connection error: %s",
                        localdrone->name, strerror(errno));
                cf_send_message(caph, errstr, MSGFLAG_ERROR);
                break;
            }

            continue;
        }

        /* Only handle 0x1 */
        if (pkt_type != 0x01) {
            continue;
        }

        ant_droneid = (struct antsdr_droneid *) tcp_buf;

        /* Possibly 'encrypted' droneid has invalid data and 
         * presents as non-utf8 string data, for now reject 
         * it. */
        if (!is_valid_utf8(ant_droneid->serial, 64) ||
                !is_valid_utf8(ant_droneid->device_type, 64)) {
            continue;
        }

        snprintf(json, 2048, "{"
                "\"serial_number\": \"%.64s\","
                "\"device_type\": \"%.64s\","
                "\"device_type_8\": %d,"
                "\"app_lat\": %f,"
                "\"app_lon\": %f,"
                "\"drone_lat\": %f,"
                "\"drone_lon\": %f,"
                "\"drone_height\": %f,"
                "\"drone_alt\": %f,"
                "\"home_lat\": %f,"
                "\"home_lon\": %f,"
                "\"freq\": %f,"
                "\"speed_e\": %f,"
                "\"speed_n\": %f,"
                "\"speed_u\": %f,"
                "\"rssi\": %u"
                "}",
                ant_droneid->serial,
                ant_droneid->device_type,
                ant_droneid->device_type_8,
                ant_droneid->app_lat,
                ant_droneid->app_lon,
                ant_droneid->drone_lat,
                ant_droneid->drone_lon,
                ant_droneid->height,
                ant_droneid->altitude,
                ant_droneid->home_lat,
                ant_droneid->home_lon,
                ant_droneid->freq,
                ant_droneid->speed_e,
                ant_droneid->speed_n,
                ant_droneid->speed_u,
                ant_droneid->rssi);

        gettimeofday(&tv, NULL);

        while (1) {
            r = cf_send_json(caph, NULL, 0,
                    NULL, NULL, tv,
                    "antsdr-droneid", (char *) json);


            if (r < 0) {
                snprintf(errstr, STATUS_MAX, "%s unable to send JSON frame.", localdrone->name);
                fprintf(stderr, "ERROR: %s", errstr);
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
    }

    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_droneid_t localdrone = {
        .caph = NULL,
        .name = NULL,
        .interface = NULL,
        .client_fd = -1,
    };

    kis_capture_handler_t *caph = cf_handler_init("antsdr-droneid");

    if (caph == NULL) {
        fprintf(stderr,
            "FATAL: Could not allocate basic handler data, your system "
            "is very low on RAM or something is wrong.\n");
        return -1;
    }

    localdrone.caph = caph;

    cf_handler_set_userdata(caph, &localdrone);
	cf_handler_set_listdevices_cb(caph, list_callback);
    cf_handler_set_open_cb(caph, open_callback);
    cf_handler_set_probe_cb(caph, probe_callback); /**/
    cf_handler_set_capture_cb(caph, capture_thread);

    int r = cf_handler_parse_opts(caph, argc, argv);
    if (r == 0) {
        return 0;
    } else if (r < 0) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    /* Support remote capture by launching the remote loop */
    cf_handler_remote_capture(caph);

    /* Jail */
    cf_jail_filesystem(caph);

    /* Strip our privs */
    cf_drop_most_caps(caph);

    cf_handler_loop(caph);

    cf_handler_shutdown(caph);


    return 0;
}
