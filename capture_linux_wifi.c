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
 * the interface - and it needs to continue running as root to be able to control
 * the channels.
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
#include "linux_wireless_control.h"
#include "linux_netlink_control.h"

#include "wifi_ht_channels.h"

/* State tracking, put in userdata */
typedef struct {
    pcap_t *pd;

    char *interface;
    char *cap_interface;

    int datalink_type;
    int override_dlt;

    /* Do we use mac80211 controls or basic ioctls */
    int use_mac80211;

    /* Cached mac80211 controls */
    void *mac80211_handle;
    void *mac80211_cache;
    void *mac80211_family;

    /* Number of sequential errors setting channel */
    unsigned int seq_channel_failure;
} local_wifi_t;

/* Linux Wi-Fi Channels:
 *
 * Wi-Fi can use multiple channel widths and encodings which need to be
 * accounted for.
 *
 * Channel formats:
 *
 * XXW5         Channel/frequency XX, custom 5MHz channel
 * XXW10        Channel/frequency XX, custom 10MHz channel
 * XX           Channel/frequency XX, non-HT standard 20MHz channel
 * XXHT40+      Channel/frequency XX, HT40+ channel
 * XXHT40-      Channel/frequency XX, HT40- channel
 * XXVHT80      Channel/frequency XX, VHT 80MHz channel.  Upper pair automatically
 *              derived from channel definition table
 * XXVHT160     Channel/frequency XX, VHT 160MHz channel.  Upper pair automatically
 *              derived from channel definition table
 *
 * XXVHT80-YY   Channel/frequency XX, VHT 80MHz channel, upper pair specified
 * XXVHT160-YY  Channel/frequency XX, VHT 160MHz channel, upper pair specified
 *
 * 5, 10, HT, and VHT channels require mac80211 drivers; the old wireless IOCTLs do
 * not support the needed attributes.
 */

/* Local interpretation of a channel; this lets us parse the string definitions
 * into a faster non-parsed version, once. */
typedef struct {
    /* For stock 20mhz channels, center freq is set to channel and 
     * chan_type is set to 0/NL80211_CHAN_NO_HT
     *
     * For ht40 channels we set only the center freq/chan and the type 
     * is set to NL80211_CHAN_HT40MINUS/HT40PLUS
     *
     * For vht80 and vht160, center freq is set, chan_type is set to 0,
     * chan_width is set accordingly to one of NL80211_CHAN_WIDTH_, and
     * center_freq1 is set to the corresponding vht center frequency.
     *
     * If 'unusual_center1' is true, the center_freq1 was not derived
     * automatically; this is relevant only when printing
     *
     * For sub-20mhz channels, chan_type is set to 0, chan_width is set 
     * accordingly from NL80211_CHAN_WIDTH_5/10, and center_freq1 is 0.
     */
    unsigned int control_freq;
    unsigned int chan_type;
    unsigned int chan_width;
    unsigned int unusual_center1;
    unsigned int center_freq1;
    unsigned int center_freq2;
} local_channel_t;

/* Convert a string into a local interpretation; allocate ret_localchan.
 *
 * Returns:
 * -1   Error parsing channel, ret_localchan will be NULL
 *  0   Success
 */
int local_channel_from_str(kis_capture_handler_t *caph, char *chanstr, 
        local_channel_t **ret_localchan) {
    unsigned int parsechan, parse_center1;
    char parsetype[16];
    int r;
    unsigned int ci;
    char errstr[STATUS_MAX];

    r = sscanf(chanstr, "%u%16[^-]-%u", &parsechan, parsetype, &parse_center1);

    if (r <= 0) {
        *ret_localchan = NULL;
        return -1;
    }

    *ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
    memset(*ret_localchan, 0, sizeof(local_channel_t));

    if (r == 1) {
        (*ret_localchan)->control_freq = parsechan;
        return 0;
    }

    if (r >= 2) {
        (*ret_localchan)->control_freq = parsechan;

        if (strcasecmp(parsetype, "w5") == 0) {
            (*ret_localchan)->chan_width = NL80211_CHAN_WIDTH_5;
        } else if (strcasecmp(parsetype, "w10") == 0) {
            (*ret_localchan)->chan_width = NL80211_CHAN_WIDTH_10;
        } else if (strcasecmp(parsetype, "ht40-") == 0) {
            (*ret_localchan)->chan_type = NL80211_CHAN_HT40MINUS;

            /* Search for the ht channel record */
            for (ci = 0; ci < MAX_WIFI_HT_CHANNEL; ci++) {
                if (wifi_ht_channels[ci].chan == parsechan || 
                        wifi_ht_channels[ci].freq == parsechan) {

                    if ((wifi_ht_channels[ci].flags & WIFI_HT_HT40MINUS) == 0) {
                        snprintf(errstr, STATUS_MAX, "requested channel %u as a HT40- "
                                "channel; this does not appear to be a valid channel "
                                "for 40MHz operation.", parsechan);
                        cf_send_message(caph, errstr, MSGFLAG_INFO);
                    }

                }
            }
        } else if (strcasecmp(parsetype, "ht40+") == 0) {
            (*ret_localchan)->chan_type = NL80211_CHAN_HT40PLUS;

            /* Search for the ht channel record */
            for (ci = 0; ci < sizeof(wifi_ht_channels) / 
                    sizeof (wifi_channel); ci++) {
                if (wifi_ht_channels[ci].chan == parsechan || 
                        wifi_ht_channels[ci].freq == parsechan) {

                    if ((wifi_ht_channels[ci].flags & WIFI_HT_HT40PLUS) == 0) {
                        snprintf(errstr, STATUS_MAX, "requested channel %u as a HT40+ "
                                "channel; this does not appear to be a valid channel "
                                "for 40MHz operation.", parsechan);
                        cf_send_message(caph, errstr, MSGFLAG_INFO);
                    }

                }
            }
        } else if (strcasecmp(parsetype, "vht80") == 0) {
            (*ret_localchan)->chan_width = NL80211_CHAN_WIDTH_80;

            /* Do we have a hardcoded 80mhz freq pair? */
            if (r == 3) {
                (*ret_localchan)->center_freq1 = parse_center1;
                (*ret_localchan)->unusual_center1 = 1;
            } else {
                /* Search for the vht channel record to find the 80mhz center freq */
                for (ci = 0; ci < sizeof(wifi_ht_channels) / 
                        sizeof (wifi_channel); ci++) {
                    if (wifi_ht_channels[ci].chan == parsechan || 
                            wifi_ht_channels[ci].freq == parsechan) {

                        if ((wifi_ht_channels[ci].flags & WIFI_HT_HT80) == 0) {
                            snprintf(errstr, STATUS_MAX, "requested channel %u as a "
                                    "VHT80 channel; this does not appear to be a valid "
                                    "channel for 80MHz operation, skipping channel", 
                                    parsechan);
                            cf_send_message(caph, errstr, MSGFLAG_ERROR);
                            free(*ret_localchan);
                            *ret_localchan = NULL;
                            return -1;
                        }

                        (*ret_localchan)->center_freq1 = wifi_ht_channels[ci].freq80;
                    }
                }
            }
        } else if (strcasecmp(parsetype, "vht160") == 0) {
            (*ret_localchan)->chan_width = NL80211_CHAN_WIDTH_160;

            /* Do we have a hardcoded 80mhz freq pair? */
            if (r == 3) {
                (*ret_localchan)->center_freq1 = parse_center1;
                (*ret_localchan)->unusual_center1 = 1;
            } else {
                /* Search for the vht channel record to find the 160mhz center freq */
                for (ci = 0; ci < sizeof(wifi_ht_channels) / 
                        sizeof (wifi_channel); ci++) {
                    if (wifi_ht_channels[ci].chan == parsechan || 
                            wifi_ht_channels[ci].freq == parsechan) {

                        if ((wifi_ht_channels[ci].flags & WIFI_HT_HT160) == 0) {
                            snprintf(errstr, STATUS_MAX, "requested channel %u as a "
                                    "VHT160 channel; this does not appear to be a "
                                    "valid channel for 160MHz operation, skipping "
                                    "channel", parsechan);
                            cf_send_message(caph, errstr, MSGFLAG_ERROR);
                            free(*ret_localchan);
                            *ret_localchan = NULL;
                        }

                        (*ret_localchan)->center_freq1 = wifi_ht_channels[ci].freq160;
                    }
                }
            }
        } else {
            /* otherwise return it as a basic channel; we don't know what to do */
            snprintf(errstr, STATUS_MAX, "unable to parse attributes on channel "
                    "'%s', treating as standard non-HT channel.", chanstr);
            cf_send_message(caph, errstr, MSGFLAG_INFO);
        }

    }

    return 0;
}

/* Convert a local interpretation of a channel back info a string;
 * 'chanstr' should hold at least STATUS_MAX characters; we'll never use
 * that many but it lets us do some cheaty stuff and re-use errstrs */
void local_channel_to_str(local_channel_t *chan, char *chanstr) {
    /* Basic channel with no HT/VHT */
    if (chan->chan_type == 0 && chan->chan_width == 0) {
        snprintf(chanstr, STATUS_MAX, "%u", chan->control_freq);
    } else if (chan->chan_type == NL80211_CHAN_HT40MINUS) {
        snprintf(chanstr, STATUS_MAX, "%uHT40-", chan->control_freq);
    } else if (chan->chan_type == NL80211_CHAN_HT40PLUS) {
        snprintf(chanstr, STATUS_MAX, "%uHT40+", chan->control_freq);
    } else {
        /* We've got some channel width; work with them */
        switch (chan->chan_width) {
            case NL80211_CHAN_WIDTH_5:
                snprintf(chanstr, STATUS_MAX, "%uW5", chan->control_freq);
                break;
            case NL80211_CHAN_WIDTH_10:
                snprintf(chanstr, STATUS_MAX, "%uW10", chan->control_freq);
                break;
            case NL80211_CHAN_WIDTH_80:
                if (chan->unusual_center1) {
                    snprintf(chanstr, STATUS_MAX, "%uVHT80-%u",
                            chan->control_freq, chan->center_freq1);
                } else {
                    snprintf(chanstr, STATUS_MAX, "%uVHT80", chan->control_freq);
                }
                break;
            case NL80211_CHAN_WIDTH_160:
                if (chan->unusual_center1) {
                    snprintf(chanstr, STATUS_MAX, "%uVHT160-%u",
                            chan->control_freq, chan->center_freq1);
                } else {
                    snprintf(chanstr, STATUS_MAX, "%uVHT160", chan->control_freq);
                }
                break;
            default:
                /* Just put the basic freq if we can't figure out what to do */
                snprintf(chanstr, STATUS_MAX, "%u", chan->control_freq);
                break;
        }
    }
}


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

/* Channel control callback; actually set a channel.  Determines if our
 * custom channel needs a VHT frequency set. */
int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan) {
    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;
    local_channel_t *channel = (local_channel_t *) privchan;
    int r;
    char errstr[STATUS_MAX];
    char err[STATUS_MAX];

    if (local_wifi->use_mac80211 == 0) {
        if ((r = iwconfig_set_channel(local_wifi->interface, 
                        channel->control_freq, errstr)) < 0) {
            /* Sometimes tuning a channel fails; this is only a problem if we fail
             * to tune a channel a bunch of times.  Spit out a tuning error at first;
             * if we continually fail, if we have a seqno we're part of a CONFIGURE
             * command and we send a configresp, otherwise send an error */
            if (local_wifi->seq_channel_failure < 10) {
                snprintf(err, STATUS_MAX, "Could not set channel; ignoring error and "
                        "continuing (%s)", errstr);
                cf_send_message(caph, err, MSGFLAG_ERROR);
                return 0;
            } else {
                snprintf(err, STATUS_MAX, "Repeated failure to set channel: %s",
                        errstr);

                if (seqno != 0) {
                    cf_send_configresp(caph, seqno, 0, err);
                } else {
                    cf_send_error(caph, err);
                }

                return -1;
            }
        } else {
            if (seqno != 0) {
                /* Send a config response with a reconstituted channel if we're
                 * configuring the interface; re-use errstr as a buffer */
                local_channel_to_str(channel, errstr);
                cf_send_configresp_channel(caph, seqno, 1, NULL, errstr);
            }
        }

        return 0;
    } else {
        /* Otherwise we're using mac80211 which means we need to figure out
         * what kind of channel we're setting */
        if (channel->chan_width != 0) {
            /* An explicit channel width means we need to use _set_freq to set
             * a control freq, a width, and possibly an extended center frequency
             * for VHT */


        }

    }
   
    return 0;
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

    fprintf(stderr, "debug - linux wifi - capture thread finishing\n");
}

int main(int argc, char *argv[]) {
    local_wifi_t local_wifi = {
        .pd = NULL,
        .interface = NULL,
        .cap_interface = NULL,
        .datalink_type = -1,
        .override_dlt = -1,
        .use_mac80211 = 1,
        .mac80211_cache = NULL,
        .mac80211_handle = NULL,
        .mac80211_family = NULL,
        .seq_channel_failure = 0,
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

