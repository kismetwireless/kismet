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

/* capture_rtl433
 *
 * Capture binary which spawns the rtl433 tool and forwards JSON output from 
 * it into the Kismet capture chain
 *
 */

#include <getopt.h>
#include <pthread.h>
#include <fcntl.h>

/* According to POSIX.1-2001, POSIX.1-2008 */
#include <sys/select.h>

/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <errno.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>

#include <config.h>
#include <simple_datasource_proto.h>
#include <capture_framework.h>

#include <rtl-sdr.h>

typedef struct {
    pid_t rtl433_pid;

    FILE *rtl433_stdout;

    unsigned int rtlnum;

    double frequency;
} local_rtl433_t;

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid, simple_cap_proto_frame_t *frame,
        cf_params_interface_t **ret_interface, 
        cf_params_spectrum_t **ret_spectrum) {

    char errstr[STATUS_MAX];

    char *placeholder = NULL;
    int placeholder_len;

    char *rtlname = NULL;
    unsigned int rtlnum = 0;

    *uuid = NULL;

    struct stat sbuf;

    *ret_spectrum = NULL;
    *ret_interface = NULL;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface"); 
        return 0;
    }

    rtlname = strndup(placeholder, placeholder_len);

    if (strcmp(rtlname, "rtl433") == 0) {
        rtlnum = 0;
    } else if (sscanf(rtlname, "rtl433-%u", &rtlnum) != 1) {
        return 0;
    }

    if (rtlnum >= rtlsdr_get_device_count())
        return 0;

    *ret_interface = cf_params_interface_new();
    *ret_spectrum = NULL;

    (*ret_interface)->chanset = NULL;
    (*ret_interface)->channels = NULL;
    (*ret_interface)->channels_len = 0;


    /* Kluge a UUID out of the name */
    snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-0000%08X",
            adler32_csum((unsigned char *) "kismet_cap_rtl433", 
                strlen("kismet_cap_rtl433")) & 0xFFFFFFFF,
            adler32_csum((unsigned char *) rtlname, 
                strlen(rtlname)) & 0xFFFFFFFF);
    *uuid = strdup(errstr);

    return 1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid, simple_cap_proto_frame_t *frame,
        cf_params_interface_t **ret_interface, 
        cf_params_spectrum_t **ret_spectrum) {
    char *placeholder = NULL;
    int placeholder_len;

    char *rtlname = NULL;
    unsigned int rtlnum = 0;
    char *freq;

    local_rtl433_t *local_rtl = (local_rtl433_t *) caph->userdata;

    char errstr[STATUS_MAX] = "";

    *ret_interface = cf_params_interface_new();
    *ret_spectrum = NULL;

    *uuid = NULL;
    // User-defined DLT; we don't report packets with actual DLTs
    *dlt = 147;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface"); 
        return 0;
    }

    rtlname = strndup(placeholder, placeholder_len);

    if (strcmp(rtlname, "rtl433") == 0) {
        rtlnum = 0;
    } else if (sscanf(rtlname, "rtl433-%u", &rtlnum) != 1) {
        return 0;
    }

    if (rtlnum >= rtlsdr_get_device_count()) {
        snprintf(msg, STATUS_MAX, "Could not find RTLSDR with index %u", rtlnum);
        return -1;
    }

    if ((placeholder_len =
                cf_find_flag(&placeholder, "frequency", definition)) > 0) {
        frequency = strndup(placeholder, placeholder_len);

        local_rtl433->frequency = cf_parse_frequency(frequency);

        free(frequency);

        if (local_rtl433_t->frequency == 0) {
            snprintf(msg, STATUS_MAX, "Could not parse frequency= option");
            return -1;
        }

        /* rtl_433 takes frequency in hz */
        local_rtl433->frequency *= 1000;
    }

    *ret_interface = cf_params_interface_new();
    *ret_spectrum = NULL;

    (*ret_interface)->chanset = NULL;
    (*ret_interface)->channels = NULL;
    (*ret_interface)->channels_len = 0;

    /* Kluge a UUID out of the name */
    snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-0000%08X",
            adler32_csum((unsigned char *) "kismet_cap_rtl433", 
                strlen("kismet_cap_rtl433")) & 0xFFFFFFFF,
            adler32_csum((unsigned char *) rtlname, 
                strlen(rtlname)) & 0xFFFFFFFF);
    *uuid = strdup(errstr);



    /* Succesful open with no channel, hop, or chanset data */
    snprintf(msg, STATUS_MAX, "Opened pcapfile '%s' for playback", pcapfname);

    if ((placeholder_len = cf_find_flag(&placeholder, "realtime", definition)) > 0) {
        if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            snprintf(errstr, PCAP_ERRBUF_SIZE, 
                    "Pcapfile '%s' will replay in realtime", pcapfname);
            cf_send_message(caph, errstr, MSGFLAG_INFO);
            local_pcap->realtime = 1;
        }
    }

    return 1;
}

void pcap_dispatch_cb(u_char *user, const struct pcap_pkthdr *header,
        const u_char *data)  {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) user;
    local_pcap_t *local_pcap = (local_pcap_t *) caph->userdata;
    int ret;
    unsigned long delay_usec = 0;

    /* If we're doing 'realtime' playback, delay accordingly based on the
     * previous packet. 
     *
     * Because we're in our own thread, we can block as long as we want - this
     * simulates blocking IO for capturing from hardware, too.
     */
    if (local_pcap->realtime) {
        if (local_pcap->last_ts.tv_sec == 0 && local_pcap->last_ts.tv_usec == 0) {
            delay_usec = 0;
        } else {
            /* Catch corrupt pcaps w/ inconsistent times */
            if (header->ts.tv_sec < local_pcap->last_ts.tv_sec) {
                delay_usec = 0;
            } else {
                delay_usec = (header->ts.tv_sec - local_pcap->last_ts.tv_sec) * 1000000L;
            }

            if (header->ts.tv_usec < local_pcap->last_ts.tv_usec) {
                delay_usec += (1000000L - local_pcap->last_ts.tv_usec) + 
                    header->ts.tv_usec;
            } else {
                delay_usec += header->ts.tv_usec - local_pcap->last_ts.tv_usec;
            }

        }

        local_pcap->last_ts.tv_sec = header->ts.tv_sec;
        local_pcap->last_ts.tv_usec = header->ts.tv_usec;

        if (delay_usec != 0) {
            usleep(delay_usec);
        }
    }

    /* Try repeatedly to send the packet; go into a thread wait state if
     * the write buffer is full & we'll be woken up as soon as it flushes
     * data out in the main select() loop */
    while (1) {
        if ((ret = cf_send_data(caph, 
                        NULL, NULL, NULL,
                        header->ts, 
                        header->caplen, (uint8_t *) data)) < 0) {
            pcap_breakloop(local_pcap->pd);
            cf_send_error(caph, "unable to send DATA frame");
            cf_handler_spindown(caph);
        } else if (ret == 0) {
            /* Go into a wait for the write buffer to get flushed */
            // fprintf(stderr, "debug - pcapfile - dispatch_cb - no room in write buffer - waiting for it to have more space\n");
            cf_handler_wait_ringbuffer(caph);
            continue;
        } else {
            break;
        }
    }
}

void capture_thread(kis_capture_handler_t *caph) {
    local_pcap_t *local_pcap = (local_pcap_t *) caph->userdata;
    char errstr[PCAP_ERRBUF_SIZE];
    char *pcap_errstr;

    pcap_loop(local_pcap->pd, -1, pcap_dispatch_cb, (u_char *) caph);

    pcap_errstr = pcap_geterr(local_pcap->pd);

    snprintf(errstr, PCAP_ERRBUF_SIZE, "Pcapfile '%s' closed: %s", 
            local_pcap->pcapfname, 
            strlen(pcap_errstr) == 0 ? "end of pcapfile reached" : pcap_errstr );

    cf_send_error(caph, errstr);
    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_rtl433_t local_rtl433 = {
        .rtl433_pid = -1,
        .rtl433_stdout = NULL,
        .rtlnum = 0
    };

    kis_capture_handler_t *caph = cf_handler_init("pcapfile");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &local_pcap);

    /* Set the callback for opening a pcapfile */
    cf_handler_set_open_cb(caph, open_callback);

    /* Set the callback for probing an interface */
    cf_handler_set_probe_cb(caph, probe_callback);

    /* Set the capture thread */
    cf_handler_set_capture_cb(caph, capture_thread);

    if (cf_handler_parse_opts(caph, argc, argv) < 1) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    cf_handler_loop(caph);

    cf_handler_free(caph);

    return 1;
}

