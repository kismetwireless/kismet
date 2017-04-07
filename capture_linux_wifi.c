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

/* capture_linux_wifi
 *
 * Capture binary, written in pure c, which interfaces via the Kismet capture
 * protocol and feeds packets from, and is able to control, a wireless card on 
 * Linux, using either the old iwconfig IOCTL interface (deprecated) or the
 * modern nl80211 netlink interface.
 *
 * The communications channel is a file descriptor pair, passed via command
 * line arguments, --in-fd= and --out-fd=
 *
 * We parse additional options from the source definition itself, such as a DLT
 * override, once we open the protocol
 *
 * The packets undergo as little processing as possible and are passed to Kismet
 * to process the DLT.
 *
 * This binary needs to run as root to be able to control and capture from
 * the interface - it will drop privileges as soon as possible once it has
 * configured the interface.
 *
 * If an error occurs, it will not be possible to re-escalate privileges; the
 * source will have to be re-opened.  Any error which prevents configuring 
 * the interface or requires re-opening the capture is therefor considered a fatal
 * error.
 *
 */

#include <pcap.h>
#include <getopt.h>
#include <pthread.h>
#include <fcntl.h>

/* According to POSIX.1-2001, POSIX.1-2008 */
#include <sys/select.h>

/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include <unistd.h>
#include <errno.h>

#include <arpa/inet.h>

#include "config.h"
#include "simple_datasource_proto.h"
#include "capture_framework.h"

#include "interface_control.h"
#include "wireless_control.h"
#include "linux_netlink_control.h"

typedef struct {
    pcap_t *pd;

    char *interface;
    char *cap_interface;

    int datalink_type;
    int override_dlt;
} local_wifi_t;

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition) {
    char *placeholder = NULL;
    int placeholder_len;

    char *pcapfname = NULL;

    struct stat sbuf;

    char errstr[PCAP_ERRBUF_SIZE] = "";

    return 1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition) {
    char *placeholder = NULL;
    int placeholder_len;


    return 1;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno) {
    DIR *devdir;
    struct dirent *devfile;
    char errstr[STATUS_MAX];

    int ret;

    /* Basic list of devices */
    typedef struct wifi_list {
        char *device;
        char *flags;
        struct wifi_list *next;
    } wifi_list_t; 

    wifi_list_t *devs = NULL;
    size_t num_devs = 0;

    char **devices = NULL;
    char **flags = NULL;
    unsigned int i;

    if ((devdir = opendir("/sys/class/net/")) == NULL) {
        fprintf(stderr, "debug - no /sys/class/net dir?\n");

        return cf_send_listresp(caph, seqno, 1, NULL, NULL, NULL, 0);
    }

    /* Look at the files in the sys dir and see if they're wi-fi */
    while ((devfile = readdir(devdir)) != NULL) {
        /* if we can get the current channel with simple iwconfig ioctls
         * it's definitely a wifi device; even mac80211 devices respond 
         * to it */
        if (iwconfig_get_channel(devfile->d_name, errstr) > 0) {
            wifi_list_t *d = (wifi_list_t *) sizeof(wifi_list_t);
            fprintf(stderr, "debug - found wireless device %s\n", devfile->d_name);
            num_devs++;
            d->device = strdup(devfile->d_name);
            d->flags = NULL;
            d->next = devs;
            devs = d;
        }
    }

    closedir(devdir);

    if (num_devs == 0) {
        return cf_send_listresp(caph, seqno, 1, NULL, NULL, NULL, 0);
    }

    devices = (char **) malloc(sizeof(char *) * num_devs);
    flags = (char **) malloc(sizeof(char *) * num_devs);

    i = 0;
    while (devs != NULL) {
        wifi_list_t *td = devs->next;
        devices[i] = devs->device;
        flags[i] = devs->flags;

        free(devs);
        devs = td;

        i++;
    }

    ret = cf_send_listresp(caph, seqno, 1, NULL, devices, flags, num_devs);

    for (i = 0; i < num_devs; i++) {
        if (devices[i] != NULL)
            free(devices[i]);
        if (flags[i] != NULL)
            free(flags[i]);
    }

    free(devices);
    free(flags);

    return 1;
}

void pcap_dispatch_cb(u_char *user, const struct pcap_pkthdr *header,
        const u_char *data)  {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) user;
    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;
    int ret;

    /* Try repeatedly to send the packet; go into a thread wait state if
     * the write buffer is full & we'll be woken up as soon as it flushes
     * data out in the main select() loop */
    while (1) {
        if ((ret = cf_send_data(caph, 
                        NULL, NULL, NULL,
                        header->ts, local_wifi->datalink_type,
                        header->caplen, (uint8_t *) data)) < 0) {
            fprintf(stderr, "debug - linux_wifi - cf_send_data failed\n");
            pcap_breakloop(local_wifi->pd);
            cf_send_error(caph, "unable to send DATA frame");
            cf_handler_spindown(caph);
        } else if (ret == 0) {
            /* Go into a wait for the write buffer to get flushed */
            cf_handler_wait_ringbuffer(caph);
            continue;
        } else {
            break;
        }
    }
}

void capture_thread(kis_capture_handler_t *caph) {
    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;
    char errstr[PCAP_ERRBUF_SIZE];
    char *pcap_errstr;

    fprintf(stderr, "debug - pcap_loop\n");

    pcap_loop(local_wifi->pd, -1, pcap_dispatch_cb, (u_char *) caph);

    pcap_errstr = pcap_geterr(local_wifi->pd);

    snprintf(errstr, PCAP_ERRBUF_SIZE, "Interface '%s' closed: %s", 
            local_wifi->cap_interface, 
            strlen(pcap_errstr) == 0 ? "interface closed" : pcap_errstr );

    fprintf(stderr, "debug - %s\n", errstr);

    cf_send_error(caph, errstr);
    cf_handler_spindown(caph);

    fprintf(stderr, "debug - pcapfile - capture thread finishing\n");
}

int main(int argc, char *argv[]) {
    local_wifi_t local_wifi = {
        .pd = NULL,
        .interface = NULL,
        .cap_interface = NULL,
        .datalink_type = -1,
        .override_dlt = -1,
    };

    char errstr[STATUS_MAX];
    char **channels;
    unsigned int channels_len, i;

    int ret;

    ret = mac80211_get_chanlist("wlan0", errstr, &channels, &channels_len);

    if (ret < 0) {
        printf("oops: %s\n", errstr);
    }

    for (i = 0; i < channels_len; i++) {
        printf("channel '%s'\n", channels[i]);
        free(channels[i]);
    }

    free(channels);

    return 0;

    /* Remap stderr so we can log debugging to a file */
    FILE *sterr;
    sterr = fopen("capture_linux_wifi.stderr", "a");
    dup2(fileno(sterr), STDERR_FILENO);

    fprintf(stderr, "CAPTURE_LINUX_WIFI launched on pid %d\n", getpid());

    kis_capture_handler_t *caph = cf_handler_init();

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    if (cf_handler_parse_opts(caph, argc, argv) < 1) {
        fprintf(stderr, "FATAL: Missing command line parameters.\n");
        return -1;
    }

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &local_wifi);

    /* Set the callback for opening  */
    cf_handler_set_open_cb(caph, open_callback);

    /* Set the callback for probing an interface */
    cf_handler_set_probe_cb(caph, probe_callback);

    /* Set the capture thread */
    cf_handler_set_capture_cb(caph, capture_thread);

    cf_handler_loop(caph);

    fprintf(stderr, "FATAL: Exited main select() loop, waiting to be killed\n");

    cf_handler_free(caph);

    while (1) {
        sleep(1);
    }

    return 1;
}

