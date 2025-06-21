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

/* capture_osx_corewlan_wifi
 *
 * Capture binary, written in a combination of pure c and objective c
 *
 * This talks to the corewlan API to get the available interfaces
 *
 */

#include <pcap.h>
#include <getopt.h>
#include <pthread.h>
#include <fcntl.h>

#include <sched.h>

/* According to POSIX.1-2001, POSIX.1-2008 */
#include <sys/select.h>

/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include <unistd.h>
#include <errno.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <ifaddrs.h>

#include "../config.h"

#include "../capture_framework.h"
#include "../interface_control.h"
#include "../wifi_ht_channels.h"

#import <Foundation/Foundation.h>
#import <CoreWLAN/CoreWLAN.h>

#define MAX_PACKET_LEN  8192

@interface CoreWLANHolder : NSObject
@property (retain) CWInterface *interface;
@property (retain) NSArray<CWChannel *> *channels;
@end
@implementation CoreWLANHolder
@end

/* State tracking, put in userdata */
typedef struct {
    pcap_t *pd;

    char *interface;
    char *cap_interface;

    int datalink_type;
    int override_dlt;

    /* Number of sequential errors setting channel */
    unsigned int seq_channel_failure;

    CoreWLANHolder *cw_holder;

} local_wifi_t;

int corewlan_find_channel(local_wifi_t *localwifi, int channel, int width) {
    int len = [[localwifi->cw_holder channels] count];
    int i;

    for (i = 0; i < len; i++) {
        CWChannel *c = [localwifi->cw_holder channels][i];

        if ([c channelNumber] == channel && [c channelWidth] == width) {
            return i;
        }
    }

    return -1;
}

int corewlan_set_channel(local_wifi_t *local_wifi, int pos) {
    CWChannel *c = [local_wifi->cw_holder channels][pos];
    CWInterface *i = [local_wifi->cw_holder interface];
    NSError *anyerror;
    BOOL r;

    if (c == NULL) {
        return -1;
    }

    r = [i setWLANChannel:c
            error: &anyerror];

    if (!r) {
        return -1;
    }

    return 1;
}

/*
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
 * We're not sure yet how to talk all these formats in OSX; more development to come;
 * for now, we do our best
 *
 */

/* Local interpretation of a channel; this lets us parse the string definitions
 * into a faster non-parsed version, once. For OSX we need to track the original
 * channel object in swift because we can't reconstitute it */
typedef struct {
    unsigned int channel;
    unsigned int width;
    int pos;
} local_channel_t;

#define DARWIN_CHANWIDTH_UNKNOWN    0
#define DARWIN_CHANWIDTH_20MHZ      1
#define DARWIN_CHANWIDTH_40MHZ      2
#define DARWIN_CHANWIDTH_80MHZ      3
#define DARWIN_CHANWIDTH_160MHZ    4

/* Convert a string into a local interpretation; allocate ret_localchan.
 */
void *chantranslate_callback(kis_capture_handler_t *caph, const char *chanstr) {
    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;
    local_channel_t *ret_localchan = NULL;
    unsigned int parsechan, parse_center1;
    char parsetype[16];
    char mod;
    int r, pos;
    char errstr[STATUS_MAX];

    /* Match HT40+ and HT40- */
    r = sscanf(chanstr, "%uHT40%c", &parsechan, &mod);

    if (r == 2) {
        pos = corewlan_find_channel(local_wifi, parsechan, DARWIN_CHANWIDTH_40MHZ);

        if (pos < 0) {
            snprintf(errstr, STATUS_MAX, "unable to find supported channel %s", chanstr);
            cf_send_message(caph, errstr, MSGFLAG_ERROR);
            return NULL;
        }

        ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
        memset(ret_localchan, 0, sizeof(local_channel_t));

        /* We set the width and let OSX figure it out */
        (ret_localchan)->channel = parsechan;
        (ret_localchan)->width = DARWIN_CHANWIDTH_40MHZ;
        (ret_localchan)->pos = pos;

        return ret_localchan;
    }


    /* otherwise parse VHTXX, WXX, and VHTXX-YYY */
    r = sscanf(chanstr, "%u%15[^-]-%u", &parsechan, parsetype, &parse_center1);

    if (r <= 0) {
        snprintf(errstr, STATUS_MAX, "unable to parse any channel information from "
                "channel string '%s'", chanstr);
        cf_send_message(caph, errstr, MSGFLAG_ERROR);
        return NULL;
    }

    if (r == 1) {
        pos = corewlan_find_channel(local_wifi, parsechan, DARWIN_CHANWIDTH_20MHZ);

        if (pos < 0) {
            snprintf(errstr, STATUS_MAX, "unable to find supported channel %s", chanstr);
            cf_send_message(caph, errstr, MSGFLAG_ERROR);
            return NULL;
        }

        ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
        memset(ret_localchan, 0, sizeof(local_channel_t));

        ret_localchan->channel = parsechan;
        ret_localchan->width = DARWIN_CHANWIDTH_20MHZ;
        ret_localchan->pos = pos;

        return ret_localchan;
    }

    if (r >= 2) {
        ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
        memset(ret_localchan, 0, sizeof(local_channel_t));

        ret_localchan->channel = parsechan;

        if (strcasecmp(parsetype, "vht80") == 0) {
            pos = corewlan_find_channel(local_wifi, parsechan, DARWIN_CHANWIDTH_80MHZ);

            if (pos < 0) {
                free(ret_localchan);
                snprintf(errstr, STATUS_MAX, "unable to find supported channel %s", chanstr);
                cf_send_message(caph, errstr, MSGFLAG_ERROR);
                return NULL;
            }

            ret_localchan->width = DARWIN_CHANWIDTH_80MHZ;
            ret_localchan->pos = pos;
        } else if (strcasecmp(parsetype, "vht160") == 0) {
            pos = corewlan_find_channel(local_wifi, parsechan, DARWIN_CHANWIDTH_160MHZ);

            if (pos < 0) {
                free(ret_localchan);
                snprintf(errstr, STATUS_MAX, "unable to find supported channel %s", chanstr);
                cf_send_message(caph, errstr, MSGFLAG_ERROR);
                return NULL;
            }

            ret_localchan->width = DARWIN_CHANWIDTH_160MHZ;
            ret_localchan->pos = pos;
        } else {
            free(ret_localchan);
            snprintf(errstr, STATUS_MAX, "unable to parse channel %s", chanstr);
            cf_send_message(caph, errstr, MSGFLAG_ERROR);
            return NULL;
        }

    }

    return ret_localchan;
}

/* Convert a local interpretation of a channel back info a string;
 * 'chanstr' should hold at least STATUS_MAX characters; we'll never use
 * that many but it lets us do some cheaty stuff and re-use errstrs */
void local_channel_to_str(local_channel_t *chan, char *chanstr) {
    /* Basic channel with no HT/VHT */
    switch (chan->width) {
        case DARWIN_CHANWIDTH_UNKNOWN:
        case DARWIN_CHANWIDTH_20MHZ:
        case DARWIN_CHANWIDTH_40MHZ:
            snprintf(chanstr, STATUS_MAX, "%u", chan->channel);
            break;
        case DARWIN_CHANWIDTH_80MHZ:
            snprintf(chanstr, STATUS_MAX, "%uVHT80", chan->channel);
            break;
        case DARWIN_CHANWIDTH_160MHZ:
            snprintf(chanstr, STATUS_MAX, "%uVHT160", chan->channel);
            break;
    }
}

int populate_chanlist(local_wifi_t *local_wifi, char *interface, char *msg, char ***chanlist,
        size_t *chanlist_sz) {
    char conv_chan[16];
    int num_chans;
    CWChannel *c;
    int ci;

    [local_wifi->cw_holder setChannels:[[[local_wifi->cw_holder interface] supportedWLANChannels] allObjects]];
    num_chans = [[local_wifi->cw_holder channels] count];

    if (num_chans <= 0) {
        *chanlist = NULL;
        *chanlist_sz = 0;

        return -1;
    }

    /* Now we build our list and do it all again */
    *chanlist = (char **) malloc(sizeof(char *) * num_chans);
    *chanlist_sz = num_chans;

    for (ci = 0; ci < num_chans; ci++) {
        c = [local_wifi->cw_holder channels][ci];

        switch ([c channelWidth]) {
            case DARWIN_CHANWIDTH_UNKNOWN:
            case DARWIN_CHANWIDTH_20MHZ:
                snprintf(conv_chan, 16, "%ld", [c channelNumber]);
                (*chanlist)[ci] = strdup(conv_chan);
                break;
            case DARWIN_CHANWIDTH_40MHZ:
                /* Make sure we can set ht80 */
                if ([c channelNumber] > 0 && [c channelNumber] < MAX_WIFI_HT_CHANNEL) {
                    if (wifi_ht_channels[[c channelNumber]].flags & WIFI_HT_HT40MINUS) {
                        snprintf(conv_chan, 16, "%ldHT40-", [c channelNumber]);
                    } else {
                        snprintf(conv_chan, 16, "%ldHT40+", [c channelNumber]);
                    }

                    (*chanlist)[ci] = strdup(conv_chan);
                }
                (*chanlist)[ci] = strdup(conv_chan);
                break;
            case DARWIN_CHANWIDTH_80MHZ:
                snprintf(conv_chan, 16, "%ldVHT80", [c channelNumber]);
                (*chanlist)[ci] = strdup(conv_chan);
                break;
            case DARWIN_CHANWIDTH_160MHZ:
                snprintf(conv_chan, 16, "%ldVHT160", [c channelNumber]);
                (*chanlist)[ci] = strdup(conv_chan);
                break;
            default:
                printf("unknown channel\n");
                (*chanlist)[ci] = NULL;
                break;
        }
    }

    return 1;
}

/* Channel control callback; actually set a channel.  Determines if our
 * custom channel needs a VHT frequency set. */
int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan,
        char *msg) {
    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;
    local_channel_t *channel = (local_channel_t *) privchan;
    char errstr[STATUS_MAX];
    char chanstr[STATUS_MAX];

    if (privchan == NULL) {
        return 0;
    }

    if (corewlan_set_channel(local_wifi, channel->pos) < 0) {
        local_channel_to_str(channel, chanstr);
        snprintf(msg, STATUS_MAX, "failed to set channel %s: %s",
                chanstr, errstr);

        if (seqno == 0) {
            cf_send_error(caph, 0, msg);
        }

        return -1;
    }

    return 1;
}


int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    int ret, i;
    char errstr[STATUS_MAX];
    int found_interface = 0;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    uint8_t hwaddr[6];

    NSArray<CWInterface *> *cw_interfaces =
        [[CWWiFiClient sharedWiFiClient] interfaces];

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* Look for the interface */
    for (i = 0; i < [cw_interfaces count]; i++) {
        if (strcmp([[cw_interfaces[i] interfaceName] UTF8String], interface) == 0) {
            [local_wifi->cw_holder setInterface:cw_interfaces[i]];
            found_interface = 1;
            break;
        }
    }

    if (!found_interface) {
        free(interface);
        return 0;
    }

    /* get the mac address; this should be standard for anything */
    if (ifconfig_get_hwaddr(interface, errstr, hwaddr) < 0) {
        free(interface);
        return 0;
    }

    ret = populate_chanlist(local_wifi, interface, errstr, &((*ret_interface)->channels),
            &((*ret_interface)->channels_len));

    free(interface);

    if (ret < 0)
        return 0;

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name
     * and the mac address of the device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strdup(placeholder);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%02X%02X%02X%02X%02X%02X",
                adler32_csum((unsigned char *) "kismet_cap_osx_corewlan_wifi",
                    strlen("kismet_cap_osx_corewlan_wifi")) & 0xFFFFFFFF,
                hwaddr[0] & 0xFF, hwaddr[1] & 0xFF, hwaddr[2] & 0xFF,
                hwaddr[3] & 0xFF, hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);
        *uuid = strdup(errstr);
    }

    return 1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {

    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;

    char *placeholder = NULL;
    int placeholder_len;

    uint8_t hwaddr[6];

    char errstr[STATUS_MAX];
    char pcap_errstr[PCAP_ERRBUF_SIZE] = "";

    *uuid = NULL;
    *dlt = 0;

    *ret_interface = cf_params_interface_new();
    *ret_spectrum = NULL;

    int ret, i, found_interface = 0;

    char *localchanstr = NULL;
    local_channel_t *localchan = NULL;

    NSArray<CWInterface *> *cw_interfaces =
        [[CWWiFiClient sharedWiFiClient] interfaces];

    /* Clean up any existing local state on open; we can get re-opened if we're a
     * remote source */
    if (local_wifi->interface) {
        free(local_wifi->interface);
        local_wifi->interface = NULL;
    }

    if (local_wifi->cap_interface) {
        free(local_wifi->cap_interface);
        local_wifi->cap_interface = NULL;
    }

    if (local_wifi->pd != NULL) {
        pcap_close(local_wifi->pd);
        local_wifi->pd = NULL;
    }

    /* Start processing the open */

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }

    local_wifi->interface = strndup(placeholder, placeholder_len);

    /* Look for the interface */
    for (i = 0; i < [cw_interfaces count]; i++) {
        if (strcmp([[cw_interfaces[i] interfaceName] UTF8String], local_wifi->interface) == 0) {
            [local_wifi->cw_holder setInterface:cw_interfaces[i]];
            found_interface = 1;
            break;
        }
    }

    if (!found_interface) {
        snprintf(msg, STATUS_MAX, "Unable to find interface %s via the OSX CoreWLAN system",
            local_wifi->interface);
        return -1;
    }

    /* get the mac address; this should be standard for anything */
    if (ifconfig_get_hwaddr(local_wifi->interface, errstr, hwaddr) < 0) {
        snprintf(msg, STATUS_MAX, "Could not fetch interface address from '%s': %s",
                local_wifi->interface, errstr);
        return -1;
    }

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name
     * and the mac address of the device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strdup(placeholder);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%02X%02X%02X%02X%02X%02X",
                adler32_csum((unsigned char *) "kismet_cap_osx_corewlan_wifi",
                    strlen("kismet_cap_osx_corewlan_wifi")) & 0xFFFFFFFF,
                hwaddr[0] & 0xFF, hwaddr[1] & 0xFF, hwaddr[2] & 0xFF,
                hwaddr[3] & 0xFF, hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);
        *uuid = strdup(errstr);
    }

    local_wifi->cap_interface = strdup(local_wifi->interface);

    /* Bring up the cap interface no matter what */
    if (ifconfig_interface_up(local_wifi->cap_interface, errstr) != 0) {
        snprintf(msg, STATUS_MAX, "Could not bring up capture interface '%s', "
                "check 'dmesg' for possible errors while loading firmware: %s",
                local_wifi->cap_interface, errstr);
        return -1;
    }

    ret = populate_chanlist(local_wifi, local_wifi->cap_interface, errstr,
            &((*ret_interface)->channels), &((*ret_interface)->channels_len));

    if (ret < 0) {
        snprintf(msg, STATUS_MAX, "Could not get list of channels from capture "
                "interface '%s' on '%s': %s", local_wifi->cap_interface,
                local_wifi->interface, errstr);
        return -1;
    }

    [[local_wifi->cw_holder interface] disassociate];

    /* Open the pcap */
    local_wifi->pd = pcap_create(local_wifi->cap_interface, pcap_errstr);

    if (local_wifi->pd == NULL || strlen(pcap_errstr) != 0) {
        snprintf(msg, STATUS_MAX, "Could not open capture interface '%s' on '%s' "
                "as a pcap capture: %s", local_wifi->cap_interface,
                local_wifi->interface, pcap_errstr);
        return -1;
    }

    if (pcap_can_set_rfmon(local_wifi->pd)) {
        printf("think we can set monitor\n");
    } else {
        printf("don't think we can set monitor\n");
    }


    if (pcap_set_rfmon(local_wifi->pd, 1) < 0) {
        printf("set rfmon failed\n");
/*
        snprintf(msg, STATUS_MAX,
                "Could not enable monitor mode on interface '%s'",
                local_wifi->interface);
        return -1;
*/
    }

    pcap_set_promisc(local_wifi->pd, 1);
    pcap_set_snaplen(local_wifi->pd, MAX_PACKET_LEN);
    pcap_set_timeout(local_wifi->pd, 1000);

    pcap_activate(local_wifi->pd);

    local_wifi->datalink_type = pcap_datalink(local_wifi->pd);
    *dlt = local_wifi->datalink_type;

    snprintf(msg, STATUS_MAX, "OSX Wi-Fi capturing from interface '%s'",
            local_wifi->interface);

    if ((placeholder_len =
                cf_find_flag(&placeholder, "channel", definition)) > 0) {
        localchanstr = strndup(placeholder, placeholder_len);

        localchan =
            (local_channel_t *) chantranslate_callback(caph, localchanstr);

        free(localchanstr);

        if (localchan == NULL) {
            snprintf(msg, STATUS_MAX,
                    "Could not parse channel= option provided in source "
                    "definition");
            return -1;
        }

        local_channel_to_str(localchan, errstr);
        (*ret_interface)->chanset = strdup(errstr);

        snprintf(errstr, STATUS_MAX, "Setting initial channel to %s",
                (*ret_interface)->chanset);
        cf_send_message(caph, errstr, MSGFLAG_INFO);

        if (chancontrol_callback(caph, 0, localchan, msg) < 0) {
            return -1;
        }
    }

    (*ret_interface)->capif = strdup(local_wifi->cap_interface);
    (*ret_interface)->hardware = strdup("osxcorewlan");

    return 1;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno,
        char *msg, cf_params_list_interface_t ***interfaces) {

    NSArray<CWInterface *> *cw_interfaces =
        [[CWWiFiClient sharedWiFiClient] interfaces];

    int num_corewlan_devs;
    int di;

	num_corewlan_devs = [cw_interfaces count];

    if (num_corewlan_devs <= 0)
        return 0;

    *interfaces =
        (cf_params_list_interface_t **) malloc(sizeof(cf_params_list_interface_t *) *
                num_corewlan_devs);

    for (di = 0; di < num_corewlan_devs; di++) {
        (*interfaces)[di] = (cf_params_list_interface_t *) malloc(sizeof(cf_params_list_interface_t));
        memset((*interfaces)[di], 0, sizeof(cf_params_list_interface_t));

        (*interfaces)[di]->interface = strdup([[cw_interfaces[di] interfaceName] UTF8String]);
        (*interfaces)[di]->flags = NULL;
        (*interfaces)[di]->hardware = strdup("osxcorewlan");
    }

    return num_corewlan_devs;
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
        if ((ret = cf_send_data(caph, NULL, 0,
                        NULL, NULL, header->ts, local_wifi->datalink_type,
                        header->len, header->caplen, (uint8_t *) data)) < 0) {
            pcap_breakloop(local_wifi->pd);
            cf_send_error(caph, 0, "unable to send DATA frame");
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
    char iferrstr[STATUS_MAX];
    int ifflags = 0, ifret;

    /* Simple capture thread: since we don't care about blocking and
     * channel control is managed by the channel hopping thread, all we have
     * to do is enter a blocking pcap loop */

    pcap_loop(local_wifi->pd, -1, pcap_dispatch_cb, (u_char *) caph);

    pcap_errstr = pcap_geterr(local_wifi->pd);

    snprintf(errstr, PCAP_ERRBUF_SIZE, "Interface '%s' closed: %s",
            local_wifi->cap_interface,
            strlen(pcap_errstr) == 0 ? "interface closed" : pcap_errstr );

    cf_send_error(caph, 0, errstr);

    ifret = ifconfig_get_flags(local_wifi->cap_interface, iferrstr, &ifflags);

    if (ifret < 0 || !(ifflags & IFF_UP)) {
        snprintf(errstr, PCAP_ERRBUF_SIZE, "Interface '%s' no longer appears to be up; "
                "This can happen when it is unplugged, or another service like DHCP or "
                "has taken over and shut it down on us.", local_wifi->cap_interface);
        cf_send_error(caph, 0, errstr);
    }

    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_wifi_t local_wifi = {
        .pd = NULL,
        .interface = NULL,
        .cap_interface = NULL,
        .datalink_type = -1,
        .override_dlt = -1,
        .seq_channel_failure = 0,
        .cw_holder = NULL
    };

#if 0
    /* Remap stderr so we can log debugging to a file */
    FILE *sterr;
    sterr = fopen("/tmp/capture_linux_wifi.stderr", "a");
    dup2(fileno(sterr), STDERR_FILENO);
    dup2(fileno(sterr), STDOUT_FILENO);
#endif

    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

    CoreWLANHolder *holder = [CoreWLANHolder alloc];
    local_wifi.cw_holder = holder;

    kis_capture_handler_t *caph = cf_handler_init("osxcorewlanwifi");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &local_wifi);

    /* Set the callback for opening  */
    cf_handler_set_open_cb(caph, open_callback);

    /* Set the callback for probing an interface */
    cf_handler_set_probe_cb(caph, probe_callback);

    /* Set the list callback */
    cf_handler_set_listdevices_cb(caph, list_callback);

    /* Set the translation cb */
    cf_handler_set_chantranslate_cb(caph, chantranslate_callback);

    /* Set the control cb */
    cf_handler_set_chancontrol_cb(caph, chancontrol_callback);

    /* Set the capture thread */
    cf_handler_set_capture_cb(caph, capture_thread);

    /* Set a channel hop spacing of 4 to get the most out of 2.4 overlap;
     * it does nothing and hurts nothing on 5ghz */
    cf_handler_set_hop_shuffle_spacing(caph, 4);

    if (cf_handler_parse_opts(caph, argc, argv) < 1) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    /* Support remote capture by launching the remote loop */
    cf_handler_remote_capture(caph);

#if 0
    /* Jail our ns */
    if (cf_jail_filesystem(caph) < 1) {
        fprintf(stderr, "DEBUG - Couldn't jail filesystem\n");
    }

    /* Strip our privs */
    if (cf_drop_most_caps(caph) < 1) {
        fprintf(stderr, "DEBUG - Didn't drop some privs\n");
    }
#endif

    cf_handler_loop(caph);

    cf_handler_shutdown(caph);

    cf_handler_free(caph);

    [pool drain];

    return 1;
}

