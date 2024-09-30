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

#include "config.h"
#include "simple_ringbuf_c.h"
#include <pthread.h>
#include <sys/select.h>

#ifdef SYS_LINUX
#define _GNU_SOURCE 1
#endif

#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdbool.h>
#include <signal.h>

#ifdef HAVE_CAPABILITY
#include <sys/capability.h>
#include <sys/prctl.h>
#include <pwd.h>
#include <grp.h>
#endif

#ifdef SYS_LINUX
#include <linux/sched.h>
#include <sched.h>
#include <sys/mount.h>
#endif

#include "capture_framework.h"
#include "kis_external_packet.h"
#include "kis_endian.h"
#include "remote_announcement.h"

#include "kismet.pb-c.h"
#include "datasource.pb-c.h"

#include "version.h"

int unshare(int);

uint32_t adler32_append_csum(uint8_t *in_buf, size_t in_len, uint32_t cs) {
    size_t i;
    uint32_t ls1 = cs & 0xFFFF;
    uint32_t ls2 = (cs >> 16) & 0xFFFF;

    const uint32_t *buf = (const uint32_t *) in_buf;
	const uint8_t *sub_buf = NULL;

    if (in_len < 4)
        return 0;

    for (i = 0; i < (in_len - 4); i += 4, buf++) {
        ls2 += (4 * (ls1 + ((*buf) & 0xFF))) + 
            (3 * ((*buf >> 8) & 0xFF)) +
            (2 * ((*buf >> 16) & 0xFF)) + 
            ((*buf >> 24) & 0xFF);

        ls1 += ((*buf >> 24) & 0xFF) +
            ((*buf >> 16) & 0xFF) +
            ((*buf >> 8) & 0xFF) +
            ((*buf) & 0xFF);
    }

    switch (in_len - i) {
        case 4:
            ls1 += ((*buf) & 0xFF);
            ls2 += ls1;
            ls1 += ((*buf >> 8) & 0xFF);
            ls2 += ls1;
            ls1 += ((*buf >> 16) & 0xFF);
            ls2 += ls1;
            ls1 += ((*buf >> 24) & 0xFF);
            ls2 += ls1;
            break;
        case 3:
			sub_buf = (uint8_t *) buf;
            // ls1 += ((*buf) & 0xFF);
			ls1 += sub_buf[0];
            ls2 += ls1;
            // ls1 += ((*buf >> 8) & 0xFF);
			ls1 += sub_buf[1];
            ls2 += ls1;
            // ls1 += ((*buf >> 16) & 0xFF);
			ls1 += sub_buf[2];
            ls2 += ls1;
            break;
        case 2:
			sub_buf = (uint8_t *) buf;
            // ls1 += ((*buf) & 0xFF);
			ls1 += sub_buf[0];
            ls2 += ls1;
            // ls1 += ((*buf >> 8) & 0xFF);
			ls1 += sub_buf[1];
            ls2 += ls1;
            break;
        case 1:
			sub_buf = (uint8_t *) buf;
            // ls1 += ((*buf) & 0xFF);
			ls1 += sub_buf[0];
            ls2 += ls1;
            break;
    }

    return (ls1 & 0xffff) + (ls2 << 16);
}

uint32_t adler32_csum(uint8_t *in_buf, size_t in_len) {
    return adler32_append_csum(in_buf, in_len, 0);
}

int cf_parse_interface(char **ret_interface, char *definition) {
    char *colonpos;

    colonpos = strstr(definition, ":");

    *ret_interface = definition;

    /* If there is no : separator, the entire line is the interface and there
     * are no flags. */
    if (colonpos == NULL) {
        return strlen(definition);
    }

    /* Otherwise return until the separator */
    return (colonpos - definition);
}

int cf_find_flag(char **ret_value, const char *flag, char *definition) {
    char *colonpos, *flagpos, *comma, *equals, *quote, *equote;

    colonpos = strstr(definition, ":");

    /* If there is no : separator, the entire line is the interface, return NULL
     * and 0 */
    if (colonpos == NULL) {
        *ret_value = NULL;
        return 0;
    }

    flagpos = colonpos + 1;

    while ((size_t) (flagpos - definition) < strlen(definition)) {
        equals = strstr(flagpos, "=");

        /* If we have a flag with no =value that's an error */
        if (equals == NULL) {
            *ret_value = NULL;
            return -1;
        }

        /* Compare the flag */
        if (strncasecmp(flag, flagpos, (equals - flagpos)) == 0 &&
                strlen(flag) == (equals - flagpos)) {
            /* Find the next comma */
            comma = strstr(equals, ",");
            /* Find the next quote */
            quote = strstr(equals, "\"");

            /* If it's null we're the last flag, so use the total length after
             * the equals as the value */
            if (comma == NULL && quote == NULL) {
                *ret_value = equals + 1;
                return strlen(equals) - 1;
            }

            /* If we've got a quote inside the string, before the terminating comma,
             * find the next quote and return that as the length */
            if (quote != NULL) {
                if ((comma != NULL && quote < comma) || comma == NULL) {
                    equote = strstr(quote + 1, "\"");
                    *ret_value = quote + 1;
                    return (equote - (quote + 1));
                } else {
                    /* */
                }
            }

            /* Otherwise return until the next comma */
            *ret_value = equals + 1;
            return (comma - (equals + 1));
        }

        /* Otherwise find the next comma */
        comma = strstr(flagpos, ",");
        /* Find the next quote */
        quote = strstr(equals, "\"");

        /* No comma, no more flags, nothing to find */
        if (comma == NULL && quote == NULL) {
            *ret_value = NULL;
            return 0;
        }

        /* If we have a quote */
        if (quote != NULL) {
            /* And it contains the current flag */
            if ((comma != NULL && quote < comma) || comma == NULL) {
                /* Jump to the end of the quote */
                equote = strstr(quote + 1, "\"");

                /* Find a trailing comma */
                comma = strstr(equote, ",");

                /* bail if this was the last */
                if (comma == NULL) {
                    *ret_value = NULL;
                    return 0;
                }
            }
        }

        /* Jump past the flagpos */
        flagpos = comma + 1;
    }

    *ret_value = NULL;
    return 0;
}


int cf_count_flag(const char *flag, char *definition) {
    int n_flags = 0;
    char *placeholder = NULL;
    char *last_holder = definition;
    int len;

    do {
        len = cf_find_flag(&placeholder, flag, last_holder);

        if (len == 0 || placeholder == NULL)
            break;

        n_flags++;
        last_holder = placeholder + len;
    } while (placeholder != NULL);

    return n_flags;
}


int cf_split_list(char *in_str, size_t in_sz, char in_split, char ***ret_splitlist, 
        size_t *ret_splitlist_sz) {

    char *start = in_str;
    char *end = in_str;
    size_t num_fields = 0;

    *ret_splitlist = NULL;
    *ret_splitlist_sz = 0;

    /* Count all the fields */
    while ((size_t) (end - in_str) <= in_sz) {
        if (*start == in_split)
            start++;

        if (*end == in_split || *end == 0 || end == in_str + in_sz) {
            if (end != start) {
                num_fields++;
            }

            start = end + 1;
            end = start;
        }

        end++;
    }

    if (num_fields == 1) {
        *ret_splitlist = (char **) malloc(sizeof(char *));

        if (*ret_splitlist == NULL)
            return -1;

        (*ret_splitlist)[0] = strndup(in_str, in_sz);
        *ret_splitlist_sz = 1;
        return 0;
    }

    *ret_splitlist = (char **) malloc(sizeof(char *) * num_fields);

    start = in_str;
    end = in_str;

    *ret_splitlist_sz = num_fields;

    num_fields = 0;
    while ((size_t) (end - in_str) <= in_sz && num_fields <= *ret_splitlist_sz) {
        if (*start == in_split)
            start++;

        if (*end == in_split || *end == 0 || end == in_str + in_sz) {
            if (end != start) {
                (*ret_splitlist)[num_fields++] = strndup(start, end - start);
            }

            start = end + 1;
            end = start;
        }

        end++;
    }

    return 0;
}

size_t cf_append_unique_chans(char **in_list1, size_t in_list1_sz,
        char **in_list2, size_t in_list2_sz, char ***ret_list) {
    size_t max_sz = in_list1_sz + in_list2_sz;
    size_t i, n, offt;
    int skip = 0;

    if (max_sz == 0) {
        *ret_list = NULL;
        return 0;
    }

    /* Make a max-size list; we only lose a few char* sizes so we don't care */
    *ret_list = (char **) malloc(sizeof(char *) * max_sz);

    if (*ret_list == NULL)
        return 0;

    /* dupe all of the first list */
    for (i = 0; i < in_list1_sz; i++) {
        (*ret_list)[i] = strdup(in_list1[i]);
    }

    offt = in_list1_sz;

    /* Dupe uniques of the second list */
    for (i = 0; i < in_list2_sz; i++) {
        skip = 0;
        for (n = 0; n < in_list1_sz; n++) {
            if (strcasecmp(in_list1[n], in_list2[i]) == 0) {
                skip = 1;
                break;
            }
        }

        if (skip)
            continue;

        (*ret_list)[offt++] = strdup(in_list2[i]);
    }

    return offt;
}

kis_capture_handler_t *cf_handler_init(const char *in_type) {
    kis_capture_handler_t *ch;
    pthread_mutexattr_t mutexattr;

    ch = (kis_capture_handler_t *) malloc(sizeof(kis_capture_handler_t));

    if (ch == NULL)
        return NULL;

    ch->last_ping = time(0);
    ch->seqno = 1;

    ch->capsource_type = strdup(in_type);

    ch->remote_capable = 1;

    ch->remote_host = NULL;
    ch->remote_port = 0;

    ch->use_tcp = 0;
    ch->use_ipc = 0;
    ch->use_ws = 0;

#ifdef HAVE_LIBWEBSOCKETS
    ch->lwscontext = NULL;
    ch->lwsvhost = NULL;
    ch->lwsprotocol = NULL;
    ch->lwsring = NULL;
    ch->lwstail = 0;
    ch->lwsclientwsi = NULL;
    ch->lwsestablished = 0;
    ch->lwsusessl = 0;
    ch->lwssslcapath = NULL;
    ch->lwsuri = NULL;
    ch->lwsuuid = NULL;
#endif

	ch->announced_uuid = NULL;

    ch->cli_sourcedef = NULL;

    ch->in_fd = -1;
    ch->out_fd = -1;
    ch->tcp_fd = -1;

    /* Disable retry by default */
    ch->remote_retry = 0;

    /* Disable daemon mode by default */
    ch->daemonize = 0;

    /* Zero the GPS */
    ch->gps_fixed_lat = 0;
    ch->gps_fixed_lon = 0;
    ch->gps_fixed_alt = 0;
    ch->gps_name = NULL;

    ch->in_ringbuf = NULL;
    ch->out_ringbuf = NULL;

    ch->ipc_list = NULL;

    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(ch->out_ringbuf_lock), &mutexattr);

    pthread_cond_init(&(ch->out_ringbuf_flush_cond), NULL);
    pthread_mutex_init(&(ch->out_ringbuf_flush_cond_mutex), NULL);

    ch->shutdown = 0;
    ch->spindown = 0;

    pthread_mutex_init(&(ch->handler_lock), &mutexattr);

    ch->listdevices_cb = NULL;
    ch->probe_cb = NULL;
    ch->open_cb = NULL;
    ch->unknown_cb = NULL;

    ch->chantranslate_cb = NULL;
    ch->chanfree_cb = NULL;
    ch->chancontrol_cb = NULL;

    ch->spectrumconfig_cb = NULL;

    ch->capture_cb = NULL;

    ch->userdata = NULL;

    ch->capture_running = 0;
    ch->hopping_running = 0;

    ch->channel = NULL;
    ch->channel_hop_list = NULL;
    ch->custom_channel_hop_list = NULL;
    ch->channel_hop_list_sz = 0;
    ch->channel_hop_shuffle = 0;
    ch->channel_hop_shuffle_spacing = 1;
    ch->channel_hop_failure_list = NULL;
    ch->channel_hop_failure_list_sz = 0;
    ch->max_channel_hop_rate = 0;

    ch->verbose = 0;

    return ch;
}

#ifdef HAVE_LIBWEBSOCKETS
static const struct lws_protocols kismet_lws_protocols[] = {
    {"kismet-remote", ws_remotecap_broker, 0, 0},
    {NULL, NULL, 0, 0}
};
#endif

void cf_set_remote_capable(kis_capture_handler_t *caph, int in_capable) {
    caph->remote_capable = in_capable;
}

void cf_handler_free(kis_capture_handler_t *caph) {
    size_t szi;

    if (caph == NULL)
        return;

    pthread_mutex_lock(&(caph->handler_lock));
    pthread_mutex_lock(&(caph->out_ringbuf_lock));

    if (caph->in_fd >= 0)
        close(caph->in_fd);

    if (caph->out_fd >= 0)
        close(caph->out_fd);

    if (caph->remote_host)
        free(caph->remote_host);

    if (caph->capsource_type)
        free(caph->capsource_type);

    if (caph->cli_sourcedef)
        free(caph->cli_sourcedef);

    if (caph->tcp_fd >= 0)
        close(caph->tcp_fd);

    if (caph->in_ringbuf != NULL)
        kis_simple_ringbuf_free(caph->in_ringbuf);

    if (caph->out_ringbuf != NULL)
        kis_simple_ringbuf_free(caph->out_ringbuf);

    for (szi = 0; szi < caph->channel_hop_list_sz; szi++) {
        if (caph->channel_hop_list[szi] != NULL)
            free(caph->channel_hop_list[szi]);

        if (caph->chanfree_cb != NULL) {
            (*(caph->chanfree_cb))(caph->custom_channel_hop_list[szi]);
        } else if (caph->custom_channel_hop_list[szi] != NULL) {
            free(caph->custom_channel_hop_list[szi]);
        }
    }

    if (caph->channel_hop_list != NULL)
        free(caph->channel_hop_list);

    if (caph->custom_channel_hop_list != NULL)
        free(caph->custom_channel_hop_list);

    if (caph->capture_running) {
        pthread_cancel(caph->capturethread);
        caph->capture_running = 0;
    }

    if (caph->hopping_running) {
        pthread_cancel(caph->hopthread);
        caph->hopping_running = 0;
    }

    pthread_cancel(caph->signalthread);

    pthread_mutex_destroy(&(caph->out_ringbuf_lock));
    pthread_mutex_destroy(&(caph->handler_lock));
}

cf_params_interface_t *cf_params_interface_new() {
    cf_params_interface_t *cpi = 
        (cf_params_interface_t *) malloc(sizeof(cf_params_interface_t));
    memset(cpi, 0, sizeof(cf_params_interface_t));

    return cpi;
}

void cf_params_interface_free(cf_params_interface_t *pi) {
    if (pi->capif != NULL)
        free(pi->capif);

    if (pi->chanset != NULL)
        free(pi->chanset);

    if (pi->channels != NULL) {
        size_t x = 0;
        for (x = 0; x < pi->channels_len; x++) {
            free(pi->channels[x]);
        }
        free(pi->channels);
    }

    free(pi);
}

cf_params_spectrum_t *cf_params_spectrum_new() {
    cf_params_spectrum_t *cps =
        (cf_params_spectrum_t *) malloc(sizeof(cf_params_spectrum_t));
    memset(cps, 0, sizeof(cf_params_spectrum_t));
    return cps;
}

void cf_params_spectrum_free(cf_params_spectrum_t *si) {
    free(si);
}

void cf_handler_shutdown(kis_capture_handler_t *caph) {
    cf_ipc_t *ipc; 

    if (caph == NULL)
        return;

    pthread_mutex_lock(&(caph->handler_lock));
    caph->shutdown = 1;

    /* Kill any IPC */
    ipc = caph->ipc_list;

    while (ipc != NULL) {
        cf_ipc_signal(caph, ipc, SIGKILL);
        cf_ipc_free(caph, ipc);
    }

    /* Kill the capture thread */
    if (caph->capture_running) {
        pthread_cancel(caph->capturethread);
        caph->capture_running = 0;
    }

    pthread_mutex_unlock(&(caph->handler_lock));
}

void cf_handler_spindown(kis_capture_handler_t *caph) {
    if (caph == NULL)
        return;

    pthread_mutex_lock(&(caph->handler_lock));
    caph->spindown = 1;
    pthread_mutex_unlock(&(caph->handler_lock));
}

void cf_handler_assign_hop_channels(kis_capture_handler_t *caph, char **stringchans,
        void **privchans, size_t chan_sz, double rate, int shuffle, int shuffle_spacing, 
        int offset) {
    size_t szi;

    /*
    fprintf(stderr, "debug - assign hop channels\n"); 
    for (szi = 0; szi < chan_sz; szi++) {
        fprintf(stderr, "debug - channel %s priv %p\n", stringchans[szi], privchans[szi]);
    }
    */

    pthread_mutex_lock(&(caph->handler_lock));

    /* Purge any existing data */
    for (szi = 0; szi < caph->channel_hop_list_sz; szi++) {
        if (caph->channel_hop_list[szi] != NULL)
            free(caph->channel_hop_list[szi]);

        if (caph->chanfree_cb != NULL) {
            (*(caph->chanfree_cb))(caph->custom_channel_hop_list[szi]);
        } else if (caph->custom_channel_hop_list[szi] != NULL) {
            free(caph->custom_channel_hop_list[szi]);
        }
    }

    if (caph->channel_hop_list) 
        free(caph->channel_hop_list);
    if (caph->custom_channel_hop_list)
        free(caph->custom_channel_hop_list);

    caph->channel_hop_list = stringchans;
    caph->custom_channel_hop_list = privchans;
    caph->channel_hop_list_sz = chan_sz;

    if (caph->max_channel_hop_rate != 0 && rate < caph->max_channel_hop_rate)
        caph->channel_hop_rate = caph->max_channel_hop_rate;
    else
        caph->channel_hop_rate = rate;

    caph->channel_hop_shuffle = shuffle;
    caph->channel_hop_shuffle_spacing = shuffle_spacing;
    caph->channel_hop_offset = offset;

    if (caph->channel_hop_shuffle && caph->channel_hop_shuffle_spacing && chan_sz != 0) {
        /* To find a proper randomization number, take the length of the channel
         * list, divide by the preferred skipping distance.
         *
         * We then need to find the closest number to the skipping distance that
         * is not a factor of the maximum so that we get full coverage.
         */

        if (caph->channel_hop_shuffle_spacing > chan_sz)
            caph->channel_hop_shuffle_spacing = 1;

        while ((chan_sz % (chan_sz / caph->channel_hop_shuffle_spacing)) == 0) {
            if (caph->channel_hop_shuffle_spacing >= chan_sz - 1) {
                caph->channel_hop_shuffle_spacing = 1;
                break;
            }
            caph->channel_hop_shuffle_spacing++;
        }
    }

    pthread_mutex_unlock(&(caph->handler_lock));

    /* Launch the channel hop thread (cancelling any current channel hopping) */
    cf_handler_launch_hopping_thread(caph);
}

void cf_handler_set_hop_shuffle_spacing(kis_capture_handler_t *caph, int spacing) {
    pthread_mutex_lock(&(caph->handler_lock));

    caph->channel_hop_shuffle_spacing = spacing;

    /* Set the shuffle hop; the channel hop thread will pick it up on its own if it
     * needs to */
    if (caph->channel_hop_shuffle && caph->channel_hop_shuffle_spacing &&
            caph->channel_hop_list_sz != 0) {
        while ((caph->channel_hop_list_sz % (caph->channel_hop_list_sz / 
                        caph->channel_hop_shuffle_spacing)) == 0) {
            if (caph->channel_hop_shuffle_spacing >= caph->channel_hop_list_sz - 1) {
                caph->channel_hop_shuffle_spacing = 1;
                break;
            }
        caph->channel_hop_shuffle_spacing++;
        }
    }

    pthread_mutex_unlock(&(caph->handler_lock));
}

void cf_handler_list_devices(kis_capture_handler_t *caph) {
    cf_params_list_interface_t **interfaces = NULL;

    /* Callback ret */
    int cbret = -1;

    /* Status buffer */
    char msgstr[STATUS_MAX];

    unsigned int i;

    msgstr[0] = 0;

    if (caph->listdevices_cb == NULL) {
        fprintf(stderr, "%s does not support listing available devices, sorry!\n",
                caph->capsource_type);
        return;
    }

    cbret = (*(caph->listdevices_cb))(caph, 0, msgstr, &interfaces);

    if (strlen(msgstr) != 0 && caph->verbose) {
        if (cbret <= 0)
            fprintf(stderr, "ERROR: %s\n", msgstr);
        else
            fprintf(stderr, "INFO: %s\n", msgstr);
    }

    if (cbret <= 0) {
        fprintf(stderr, "%s - No supported data sources found...\n", caph->capsource_type);
        return;
    }

    fprintf(stderr, "%s supported data sources:\n", caph->capsource_type);

    if (cbret > 0) {
        for (i = 0; i < (size_t) cbret; i++) {
            if (interfaces[i] != NULL) {
                fprintf(stderr, "    %s", interfaces[i]->interface);

                if (interfaces[i]->flags != NULL) {
                    fprintf(stderr, ":%s", interfaces[i]->flags);
                }

                if (interfaces[i]->hardware != NULL) {
                    fprintf(stderr, " (%s)", interfaces[i]->hardware);
                }
                
                fprintf(stderr, "\n");

                if (interfaces[i]->interface != NULL)
                    free(interfaces[i]->interface);
                if (interfaces[i]->flags != NULL)
                    free(interfaces[i]->flags);
                if (interfaces[i]->hardware != NULL)
                    free(interfaces[i]->hardware);

                free(interfaces[i]);
            }

        }

        free(interfaces);
    }
}

int cf_handler_parse_opts(kis_capture_handler_t *caph, int argc, char *argv[]) {
    int option_idx;

    optind = 0;
    opterr = 0;
    option_idx = 0;

    char parse_hname[513];
    unsigned int parse_port;

    int retry = 1;
    int daemon = 0;
	int autodetect = 0;

    static struct option longopt[] = {
        { "in-fd", required_argument, 0, 1 },
        { "out-fd", required_argument, 0, 2 },
        { "connect", required_argument, 0, 3 },
        { "source", required_argument, 0, 4 },
        { "disable-retry", no_argument, 0, 5 },
        { "daemonize", no_argument, 0, 6 },
        { "list", no_argument, 0, 7 },
        { "fixed-gps", required_argument, 0, 8 },
        { "gps-name", required_argument, 0, 9 },
        { "host", required_argument, 0, 10 },
        { "autodetect", optional_argument, 0, 11 },
        { "tcp", no_argument, 0, 12 },
        { "ssl", no_argument, 0, 13},
        { "user", required_argument, 0, 14},
        { "password", required_argument, 0, 15},
        { "apikey", required_argument, 0, 16},
        { "endpoint", required_argument, 0, 17},
        { "ssl-certificate", required_argument, 0, 18},
        { "help", no_argument, 0, 'h'},
        { "version", no_argument, 0, 'v'},
        { 0, 0, 0, 0 }
    };

    char *gps_arg = NULL;
    int pr;
#ifdef HAVE_LIBWEBSOCKETS
    char *user = NULL, *password = NULL, *token = NULL, *endp_arg = NULL;
    char uri[1024];
#endif

    int ret = 0;

    while (1) {
        int r = getopt_long(argc, argv, "vh-", longopt, &option_idx);

        if (r < 0)
            break;

        if (r == 'v') {
            printf("%s.%s.%s-%s\n", VERSION_MAJOR, VERSION_MINOR, VERSION_TINY, VERSION_GIT_COMMIT);
            return 0;
        } else if (r == 'h') {
            ret = -2;
            goto cleanup;
        } else if (r == 1) {
            if (sscanf(optarg, "%d", &(caph->in_fd)) != 1) {
                fprintf(stderr, "FATAL: Unable to parse incoming file descriptor\n");
                ret = -1;
                goto cleanup;
            }

            caph->use_ipc = 1;
        } else if (r == 2) {
            if (sscanf(optarg, "%d", &(caph->out_fd)) != 1) {
                fprintf(stderr, "FATAL: Unable to parse outgoing file descriptor\n");
                ret = -1;
                goto cleanup;
            }
            caph->use_ipc = 1;
        } else if (r == 3) {
            if (sscanf(optarg, "%512[^:]:%u", parse_hname, &parse_port) != 2) {
                fprintf(stderr, "FATAL: Expected host:port for --connect\n");
                ret = -1;
                goto cleanup;
            }

            caph->remote_host = strdup(parse_hname);
            caph->remote_port = parse_port;
        } else if (r == 4) {
            caph->cli_sourcedef = strdup(optarg);
        } else if (r == 5) {
            fprintf(stderr, "INFO: Disabling automatic reconnection to remote servers\n");
            retry = 0;
        } else if (r == 6) {
            fprintf(stderr, "INFO: Entering daemon mode after initial setup\n");
            daemon = 1;
        } else if (r == 7) {
            cf_handler_list_devices(caph);
            cf_handler_free(caph);
            exit(KIS_EXTERNAL_RETCODE_ARGUMENTS);
        } else if (r == 8) {
            gps_arg = strdup(optarg);
        } else if (r == 9) {
            caph->gps_name = strdup(optarg);
        } else if (r == 10) {
            if (sscanf(optarg, "%512[^:]:%u", parse_hname, &parse_port) != 2) {
                fprintf(stderr, "FATAL: Expected ip:port for --host\n");
                ret = -1;
                goto cleanup;
            }

            caph->remote_host = strdup(parse_hname);
            caph->remote_port = parse_port;
        } else if (r == 11) {
            autodetect = 1;

            if (optarg != NULL)
                caph->announced_uuid = strdup(optarg);
        } else if (r == 12) {
            caph->use_tcp = 1;
        } else if (r == 13) {
#ifdef HAVE_LIBWEBSOCKETS
            caph->lwsusessl = 1;
#else
            fprintf(stderr, "FATAL: Cannot specify ssl when not compiled with websockets support\n");
            ret = -1;
            goto cleanup;
#endif
        } else if (r == 14) {
#ifdef HAVE_LIBWEBSOCKETS
            user = strdup(optarg);
#else
            fprintf(stderr, "FATAL: Cannot user a username or password login when not "
                    "compiled with websockets support\n");
            ret = -1;
            goto cleanup;
#endif
        } else if (r == 15) {
#ifdef HAVE_LIBWEBSOCKETS
            password = strdup(optarg);
#else
            fprintf(stderr, "FATAL: Cannot use a username or password login when not "
                    "compiled with websockets support\n");
            ret = -1;
            goto cleanup;
#endif
        } else if (r == 16) {
#ifdef HAVE_LIBWEBSOCKETS
            token = strdup(optarg);
#else
            fprintf(stderr, "FATAL: Cannot use an API key when not compiled with "
                    "websockets support\n");
            ret = -1;
            goto cleanup;
#endif
        } else if (r == 17) {
#ifdef HAVE_LIBWEBSOCKETS
            endp_arg = strdup(optarg);
#else
            fprintf(stderr, "FATAL: Cannot use custom endpoint when not compiled "
                    "with websockets support.\n");
            ret = -1;
            goto cleanup;
#endif
        } else if (r == 18) {
#ifdef HAVE_LIBWEBSOCKETS
            caph->lwssslcapath = strdup(optarg);
#else
            fprintf(stderr, "FATAL: Cannot use SSL certificates when not compiled "
                    "with websockets support\n");
            return -1;
            goto cleanup;
#endif
        } 
    }

#ifndef HAVE_LIBWEBSOCKETS
    if (caph->remote_host != NULL && caph->use_tcp == 0) {
        fprintf(stderr, "FATAL:  Must specify --tcp when not compiled with websockets support\n");
        ret = -1;
        goto cleanup;
    }
#endif

    if (caph->remote_host != NULL && (caph->use_tcp == 0 && caph->remote_port == 3501)) {
        fprintf(stderr, "WARNING: It looks like you're using a legacy TCP remote capture port, but\n"
                "         did not specify '--tcp'; this probably is not what you want!\n");
    }

    /* Spin looking for the remote announcement */
    if (autodetect)
        if (cf_wait_announcement(caph) < 0) {
            ret = -1;
            goto cleanup;
        }

    if (caph->remote_host == NULL) {
        if (caph->cli_sourcedef != NULL) 
            fprintf(stderr, "WARNING: Ignoring --source option when not in remote mode.\n");
#ifdef HAVE_LIBWEBSOCKETS
        if (user != NULL || password != NULL)
            fprintf(stderr, "WARNING: Ignoring --user and --password options when not in "
                    "remote mode\n");
        if (token != NULL)
            fprintf(stderr, "WARNING: Ignoring --apikey when not in remote mode\n");
#endif
    }

#ifdef HAVE_LIBWEBSOCKETS
    if (caph->use_tcp && (user != NULL || password != NULL || token != NULL))
        fprintf(stderr, "WARNING: Ignoring user, password, and apikeys in legacy TCP mode\n");

    if ((user != NULL || password != NULL) && (user == NULL || password == NULL)) {
        fprintf(stderr, "FATAL:  Must specify both username and password\n");
        ret = -1;
        goto cleanup;
    }
#endif

    if (caph->remote_host == NULL && gps_arg != NULL) {
        fprintf(stderr, "WARNING: Ignoring --fixed-gps option when not in remote mode.\n");
    }

    if (gps_arg != NULL) {
        pr = sscanf(gps_arg, "%lf,%lf,%lf", 
                &(caph->gps_fixed_lat), &(caph->gps_fixed_lon),
                &(caph->gps_fixed_alt));

        if (pr == 2) {
            caph->gps_fixed_alt = 0;
        } else if (pr < 2) {
            fprintf(stderr, "FATAL:  --fixed-gps expects lat,lon or lat,lon,alt\n");
            ret = -1;
            goto cleanup;
        }

        free(gps_arg);
        gps_arg = NULL;
    }


    if (caph->remote_host != NULL) {
        /* Must have a --source to present to the remote host */
        if (caph->cli_sourcedef == NULL) {
            fprintf(stderr, "FATAL: --source option required when connecting to a remote host\n");
            return -1;
        }

        /* Set retry only when we have a remote host */
        caph->remote_retry = retry;

        /* Set daemon mode only when we have a remote host */
        caph->daemonize = daemon;

        /* If we're not tcp, we're websockets */
        if (!caph->use_tcp) {
#ifdef HAVE_LIBWEBSOCKETS
            caph->use_ws = 1;
#else
            fprintf(stderr, "FATAL:  Not compiled with libwebsockets support, cannot use websockets remote capture.\n");
#endif
        }

#ifdef HAVE_LIBWEBSOCKETS
        if (caph->use_ws && user == NULL && password == NULL && token == NULL) {
            fprintf(stderr, "FATAL: User and password or API key required for remote capture\n");
            ret = -1;
            goto cleanup;
        }

        if (user != NULL && token != NULL) 
            fprintf(stderr, "WARNING: Ignoring APIKEY and using login information\n");

        if (endp_arg == NULL)
            endp_arg = strdup("/datasource/remote/remotesource.ws");
        else
            fprintf(stderr, "INFO: Using custom endpoint path %s\n", endp_arg);

        if (user != NULL && password != NULL) {
            snprintf(uri, 1024, "%s?user=%s&password=%s", endp_arg, user, password);
            caph->lwsuri = strdup(uri);
        } else if (token != NULL) {
            snprintf(uri, 1024, "%s?KISMET=%s", endp_arg, token);
            caph->lwsuri = strdup(uri);
        }

#endif

        ret = 2;
        goto cleanup;
    }

    ret = 1;

    if (caph->in_fd == -1 || caph->out_fd == -1) {
        ret = -1;
        goto cleanup;
    }

cleanup:
    if (gps_arg != NULL)
        free(gps_arg);

#ifdef HAVE_LIBWEBSOCKETS
    if (user != NULL)
        free(user);
    if (password != NULL)
        free(password);
    if (token != NULL)
        free(token);
    if (endp_arg != NULL)
        free(endp_arg);
#endif

    return ret;

}

void cf_print_help(kis_capture_handler_t *caph, const char *argv0) {
    fprintf(stderr, "%s is a capture driver for Kismet.  Typically it is started\n"
            "automatically by the Kismet server.\n", argv0);
    
    if (caph->remote_capable) {
        fprintf(stderr, "\n%s supports sending data to a remote Kismet server\n"
                "usage: %s [options]\n"
                " --connect [host]:[port]      Connect to remote Kismet server on [host] and [port]; by\n"
                "                               default this now uses the new websockets interface built\n"
                "                               into the Kismet webserver on port 2501; to connect using\n"
                "                               the legacy remote capture protocol, specify the '--tcp'\n"
                "                               option and the appropriate port, by default port 3501.\n"
                " --tcp                        Use the legacy TCP remote capture protocol, when combined\n"
                "                               with the --connect option.  The modern protocol uses \n"
                "                               websockets built into the Kismet server and does not\n"
                "                               need this option.\n"
                " --ssl                        Use SSL to connect to a websocket-enabled Kismet server\n"
                " --ssl-certificate [certfile] Use SSL to connect to a websocket-enabled Kismet server\n"
                "                               and use the provided certificate authority certificate\n"
                "                               to validate the server.\n"
                " --user [username]            Kismet username for a websockets-based remote capture\n"
                "                               source.  A username and password, or an API key, are\n"
                "                               required for websockets mode.  A username and password\n"
                "                               are ONLY used in websockets mode.\n"
                " --password [password]        Kismet password for a websockets-based remote capture source.\n"
                "                               A username and password, or an API key, are required for\n"
                "                               websocket mode.  A username and password are ONLY used in\n"
                "                               websockets mode.\n"
                " --apikey [api key]           A Kismet API key for the 'datasource' role; this may be\n"
                "                               supplied instead of a username and password for websockets\n"
                "                               based remote capture.  An API key is ONLY used in websockets\n"
                "                               mode.\n"
                " --endpoint [endpoint]        An alternate endpoint for the websockets connection.  By\n"
                "                               default remote datasources are terminated at\n"
                "                                 /datasource/remote/remotesource.ws\n"
                "                               This should typically only be changed when using a HTTP proxy\n"
                "                               homing the Kismet service under a directory.  Endpoints \n"
                "                               should include the full path to the websocket endpoint, for\n"
                "                               example:\n"
                "                                 --endpoint=/kismet/proxy/datasource/remote/remotesource.ws\n"
                " --source [source def]        Specify a source to send to the remote \n"
                "                              Kismet server; only used in conjunction with remote capture.\n"
                " --disable-retry              Do not attempt to reconnect to a remote server if there is an\n"
                "                               error; exit immediately.  By default a remote capture will\n"
                "                               attempt to reconnect indefinitely if the server is not\n"
                "                               available.\n"
                " --fixed-gps [lat,lon,alt]    Set a fixed location for this capture (remote only),\n"
                "                               accepts lat,lon,alt or lat,lon\n"
                " --gps-name [name]            Set an alternate GPS name for this source\n"
                " --daemonize                  Background the capture tool and enter daemon mode.\n"
                " --list                       List supported devices detected\n"
				" --autodetect [uuid:optional] Look for a Kismet server in announcement mode, optionally \n"
				"                              waiting for a specific server UUID to be seen.  Requires \n"
				"                              a Kismet server configured for announcement mode.\n"
                " --version                    Print version and exit.\n",
                argv0, argv0);
    }

}


void cf_handler_set_listdevices_cb(kis_capture_handler_t *capf, 
        cf_callback_listdevices cb) {
    pthread_mutex_lock(&(capf->handler_lock));
    capf->listdevices_cb = cb;
    pthread_mutex_unlock(&(capf->handler_lock));
}

void cf_handler_set_probe_cb(kis_capture_handler_t *capf, cf_callback_probe cb) {
    pthread_mutex_lock(&(capf->handler_lock));
    capf->probe_cb = cb;
    pthread_mutex_unlock(&(capf->handler_lock));
}

void cf_handler_set_open_cb(kis_capture_handler_t *capf, 
        cf_callback_open cb) {
    pthread_mutex_lock(&(capf->handler_lock));
    capf->open_cb = cb;
    pthread_mutex_unlock(&(capf->handler_lock));
}

void cf_handler_set_userdata(kis_capture_handler_t *capf, void *userdata) {
    pthread_mutex_lock(&(capf->handler_lock));
    capf->userdata = userdata;
    pthread_mutex_unlock(&(capf->handler_lock));
}

void cf_handler_set_capture_cb(kis_capture_handler_t *capf, cf_callback_capture cb) {
    pthread_mutex_lock(&(capf->handler_lock));
    capf->capture_cb = cb;
    pthread_mutex_unlock(&(capf->handler_lock));
}

void cf_handler_set_spectrumconfig_cb(kis_capture_handler_t *capf, 
        cf_callback_spectrumconfig cb) {
    pthread_mutex_lock(&(capf->handler_lock));
    capf->spectrumconfig_cb = cb;
    pthread_mutex_unlock(&(capf->handler_lock));
}

void cf_handler_set_unknown_cb(kis_capture_handler_t *capf, cf_callback_unknown cb) {
    pthread_mutex_lock(&(capf->handler_lock));
    capf->unknown_cb = cb;
    pthread_mutex_unlock(&(capf->handler_lock));
}

void cf_handler_set_chantranslate_cb(kis_capture_handler_t *capf, 
        cf_callback_chantranslate cb) {
    pthread_mutex_lock(&(capf->handler_lock));
    capf->chantranslate_cb = cb;
    pthread_mutex_unlock(&(capf->handler_lock));
}

void cf_handler_set_chancontrol_cb(kis_capture_handler_t *capf,
        cf_callback_chancontrol cb) {
    pthread_mutex_lock(&(capf->handler_lock));
    capf->chancontrol_cb = cb; 
    pthread_mutex_unlock(&(capf->handler_lock));
}

void cf_handler_set_chanfree_cb(kis_capture_handler_t *capf, cf_callback_chanfree cb) {
    pthread_mutex_lock(&(capf->handler_lock));
    capf->chanfree_cb = cb;
    pthread_mutex_unlock(&(capf->handler_lock));
}

/* Internal capture thread which spawns the capture callback
 */
void *cf_int_capture_thread(void *arg) {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) arg;

    /* Set us cancelable */
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    if (caph->capture_cb != NULL) {
        (*(caph->capture_cb))(caph);
    } else {
        fprintf(stderr, "ERROR - No capture handler defined for capture thread\n");
    }

    // cf_send_error(caph, 0, "capture thread ended, source is closed.");
   
    cf_handler_spindown(caph);

    return NULL;
}

/*
 * Catch any terminated processes and call any termination handlers they 
 * have; remove them from the IPC list.
 *
 * IPC termination callback is responsible for freeing the IPC record, 
 * if not tracked elsewhere.
 */
void cf_process_child_signals(kis_capture_handler_t *caph) {
    while (1) {
        int pid_status;
        pid_t caught_pid;
        cf_ipc_t *prev_ipc = NULL;
        cf_ipc_t *ipc = NULL;

        if ((caught_pid = waitpid(-1, &pid_status, WNOHANG | WUNTRACED)) > 0) {
            pthread_mutex_lock(&(caph->out_ringbuf_lock));

            if (caph->shutdown) {
                continue;
            }

            ipc = caph->ipc_list;

            while (ipc != NULL) {
                if (ipc->pid == caught_pid) {
                    if (ipc == caph->ipc_list) {
                        caph->ipc_list = ipc->next;
                    } else {
                        prev_ipc->next = ipc->next;
                    }

                    if (ipc->term_callback != NULL) {
                        ipc->term_callback(caph, ipc, pid_status);
                    }

                    break;
                }

                prev_ipc = ipc;
                ipc = ipc->next;
            }

            pthread_mutex_unlock(&(caph->out_ringbuf_lock));
        }
    }
}

static sigset_t cf_core_signal_mask;
void *cf_int_signal_thread(void *arg) {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) arg;

    int sig_caught, r; 

#if 0
    /* Set a timer to wake up from sigwait and make sure we have nothing we need to deal with */
    struct itimerval itval;

    itval.it_value.tv_sec = 0;
    itval.it_value.tv_usec = 100000;
    itval.it_interval = itval.it_value;

    setitimer(ITIMER_REAL, &itval, NULL);
#endif

    /* Unblock signals, we handle them here */
    sigset_t unblock_mask;
    sigfillset(&unblock_mask);
    pthread_sigmask(SIG_UNBLOCK, &unblock_mask, NULL);

    while (!caph->spindown && !caph->shutdown) { 
        r = sigwait(&cf_core_signal_mask, &sig_caught);

        if (r != 0)
            continue;

        switch (sig_caught) { 
            case SIGINT:
            case SIGTERM:
            case SIGHUP:
            case SIGQUIT:
                if (caph->monitor_pid > 0) {
                    kill(caph->monitor_pid, SIGINT);
                }

                if (caph->child_pid > 0) {
                    kill(caph->child_pid, SIGINT);
                }

                pthread_mutex_lock(&(caph->out_ringbuf_lock));
                if (caph->capture_running) {
                    pthread_cancel(caph->capturethread);
                    caph->capture_running = 0;
                }
                pthread_mutex_unlock(&(caph->out_ringbuf_lock));

                /* Kill anything pending */
                pthread_cond_broadcast(&(caph->out_ringbuf_flush_cond));

                break;

            case SIGCHLD:
                cf_process_child_signals(caph);
                break;

            case SIGALRM:
                /* Do nothing with the timer, it just ticks us to break out of sigwait */
                break;

        }
    }

    return NULL;
}

/* Launch a capture thread after opening has been successful */
int cf_handler_launch_capture_thread(kis_capture_handler_t *caph) {
    /* Set the thread attributes - detached, cancellable */
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setschedpolicy(&attr, SCHED_FIFO);

    sigemptyset(&cf_core_signal_mask);

    /*
    sigaddset(&cf_core_signal_mask, SIGINT);
    sigaddset(&cf_core_signal_mask, SIGQUIT);
    sigaddset(&cf_core_signal_mask, SIGTERM);
    sigaddset(&cf_core_signal_mask, SIGHUP);
    sigaddset(&cf_core_signal_mask, SIGSEGV);
     */

    sigaddset(&cf_core_signal_mask, SIGALRM);
    sigaddset(&cf_core_signal_mask, SIGQUIT);
    sigaddset(&cf_core_signal_mask, SIGCHLD);
    sigaddset(&cf_core_signal_mask, SIGPIPE);

    /* Set thread mask for all new threads */
    pthread_sigmask(SIG_BLOCK, &cf_core_signal_mask, NULL);

    /* Launch the signal handling thread */ 
    if (pthread_create(&(caph->signalthread), &attr, cf_int_signal_thread, caph) < 0) {
        cf_send_error(caph, 0, "failed to launch signal thread");
        cf_handler_spindown(caph);
        return -1;
    }

    pthread_mutex_lock(&(caph->handler_lock));
    if (caph->capture_running) {
        pthread_mutex_unlock(&(caph->handler_lock));
        return 0;
    }

    if (pthread_create(&(caph->capturethread), &attr, 
                cf_int_capture_thread, caph) < 0) {
        cf_send_error(caph, 0, "failed to launch capture thread");
        cf_handler_spindown(caph);
        return -1;
    }

    caph->capture_running = 1;

    pthread_mutex_unlock(&(caph->handler_lock));
    
    return 1;
}

void cf_handler_wait_ringbuffer(kis_capture_handler_t *caph) {
    pthread_cond_wait(&(caph->out_ringbuf_flush_cond),
            &(caph->out_ringbuf_flush_cond_mutex));
    pthread_mutex_unlock(&(caph->out_ringbuf_flush_cond_mutex));
}

/* Internal capture thread which drives channel hopping
 */
void *cf_int_chanhop_thread(void *arg) {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) arg;

    /* Set us cancelable */
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    size_t hoppos;
    
    /* How long we're waiting until the next time */
    unsigned int wait_sec = 0;
    unsigned int wait_usec = 0;

    char errstr[STATUS_MAX];
    
    int r = 0;

    /* Figure out where we are in the hopping vec, and set us to actively hopping
     * right now; this will block until the thread launcher brings us up */
    pthread_mutex_lock(&(caph->handler_lock));
    hoppos = caph->channel_hop_offset;
    caph->hopping_running = 1;
    pthread_mutex_unlock(&(caph->handler_lock));


    while (1) {
        pthread_mutex_lock(&(caph->handler_lock));

        /* Cancel thread if we're no longer hopping */
        if (caph->channel_hop_rate == 0 || caph->hopping_running == 0) {
            caph->hopping_running = 0;
            pthread_mutex_unlock(&(caph->handler_lock));
            return NULL;
        }
       
        wait_usec = 1000000L / caph->channel_hop_rate;

        if (wait_usec < 50000) {
            wait_sec = 0;
            wait_usec = 50000;
        } else if (wait_usec > 1000000L) {
            wait_sec = wait_usec / 1000000L;
            wait_usec = wait_usec % 1000000L;
        }

        pthread_mutex_unlock(&(caph->handler_lock));

        /* Sleep until the next wakeup */
        sleep(wait_sec);
        usleep(wait_usec);

        pthread_mutex_lock(&caph->handler_lock);

        if (caph->channel_hop_rate == 0 || caph->chancontrol_cb == NULL) {
            caph->hopping_running = 0;
            pthread_mutex_unlock(&caph->handler_lock);
            return NULL;
        }

        errstr[0] = 0;
        if ((r = (caph->chancontrol_cb)(caph, 0, 
                    caph->custom_channel_hop_list[hoppos % caph->channel_hop_list_sz], 
                    errstr)) < 0) {
            fprintf(stderr, "FATAL:  Datasource channel control callback failed.\n");
            cf_send_error(caph, 0, errstr);
            caph->hopping_running = 0;
            pthread_mutex_unlock(&caph->handler_lock);
            cf_handler_spindown(caph);
            return NULL;
        } else if (r == 0) {
            /* Append to the linked list */
            struct cf_channel_error *err;
            int err_seen = 0;

            for (err = (struct cf_channel_error *) caph->channel_hop_failure_list;
                    err != NULL; err = err->next) {
                if (err->channel_pos == (hoppos % caph->channel_hop_list_sz)) {
                    err_seen = 1;
                    break;
                }
            }

            // Only add error positions we haven't seen in error before
            if (!err_seen) {
                err = (struct cf_channel_error *) malloc(sizeof(struct cf_channel_error));
                err->channel_pos = hoppos % caph->channel_hop_list_sz;
                err->next = (struct cf_channel_error *) caph->channel_hop_failure_list;
                caph->channel_hop_failure_list = err;
                caph->channel_hop_failure_list_sz++;
            }
        }

        /* Increment by the shuffle amount */
        if (caph->channel_hop_shuffle)
            hoppos += caph->channel_hop_shuffle_spacing;
        else
            hoppos++;

        /* If we've gotten back to 0, look at the failed channel list.  This is super
         * inefficient because it has to do multiple crawls of a linked list, but
         * it should only happen once per interface to clean out the bogons. */
        if ((hoppos % caph->channel_hop_list_sz) == 0 &&
                caph->channel_hop_failure_list_sz != 0) {
            char **channel_hop_list_new;
            void **custom_channel_hop_list_new;
            size_t new_sz;
            size_t i, ni;
            struct cf_channel_error *err, *errnext;

            /* Safety net */
            if (caph->channel_hop_failure_list_sz == caph->channel_hop_list_sz) {
                snprintf(errstr, STATUS_MAX, "All configured channels are in error state!");
                cf_send_error(caph, 0, errstr);
                caph->hopping_running = 0;
                pthread_mutex_unlock(&caph->handler_lock);
                cf_handler_spindown(caph);
                return NULL;
            }

            if (caph->channel_hop_failure_list_sz > caph->channel_hop_list_sz) {
                snprintf(errstr, STATUS_MAX, "Attempted to clean up channels which were "
                        "in error state, but there were more error channels (%lu) than "
                        "assigned channels (%lu), something is wrong internally.",
                        caph->channel_hop_failure_list_sz,
                        caph->channel_hop_list_sz);
                cf_send_error(caph, 0, errstr);
                caph->hopping_running = 0;
                pthread_mutex_unlock(&caph->handler_lock);
                cf_handler_spindown(caph);
                return NULL;
            }

            /* shrink the channel list and the custom list, and copy only the 
             * valid ones, eliminating the bogus ones */
            new_sz = caph->channel_hop_list_sz - caph->channel_hop_failure_list_sz;

            channel_hop_list_new = (char **) malloc(sizeof(char *) * new_sz);
            custom_channel_hop_list_new = (void **) malloc(sizeof(void *) * new_sz);

            for (i = 0, ni = 0; i < caph->channel_hop_list_sz && ni < new_sz; i++) {
                int err_seen = 0;

                for (err = (struct cf_channel_error *) caph->channel_hop_failure_list;
                        err != NULL; err = err->next) {
                    if (err->channel_pos == i) {
                        err_seen = 1;
                        break;
                    }
                }

                /* If it's in error, free it */
                if (err_seen) {
                    free(caph->channel_hop_list[i]);
                    if (caph->chanfree_cb != NULL) 
                        (caph->chanfree_cb)(caph->custom_channel_hop_list[i]);
                    continue;
                }

                /* Otherwise move the pointer to our new list */
                channel_hop_list_new[ni] = caph->channel_hop_list[i];
                custom_channel_hop_list_new[ni] = caph->custom_channel_hop_list[i];
                ni++;
            }

            /* Remove the old lists and swap in the new ones */
            free(caph->channel_hop_list);
            free(caph->custom_channel_hop_list);

            caph->channel_hop_list = channel_hop_list_new;
            caph->custom_channel_hop_list = custom_channel_hop_list_new;
            caph->channel_hop_list_sz = new_sz;

            /* Spam a configresp which should trigger a reconfigure */
            snprintf(errstr, STATUS_MAX, "Removed %lu channels from the channel list "
                    "because the source could not tune to them", 
                    caph->channel_hop_failure_list_sz);
            cf_send_configresp(caph, 0, 1, errstr, NULL);


            /* Clear out the old list */
            err = (struct cf_channel_error *) caph->channel_hop_failure_list;
            while (err != NULL) {
                errnext = err->next;
                free(err);
                err = errnext;
            }
            caph->channel_hop_failure_list = NULL;
            caph->channel_hop_failure_list_sz = 0;
        }

        pthread_mutex_unlock(&caph->handler_lock);
    }

    return NULL;
}

int cf_handler_launch_hopping_thread(kis_capture_handler_t *caph) {
    /* Set the thread attributes - detached, cancelable */
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setschedpolicy(&attr, SCHED_FIFO);

    pthread_mutex_lock(&(caph->handler_lock));
    if (caph->hopping_running) {
        pthread_cancel(caph->hopthread);
        caph->hopping_running = 0;
    }

    if (pthread_create(&(caph->hopthread), &attr, cf_int_chanhop_thread, caph) < 0) {
        cf_send_error(caph, 0, "failed to launch channel hopping thread");
        cf_handler_spindown(caph);
        return -1;
    }

    caph->hopping_running = 1;

    pthread_mutex_unlock(&(caph->handler_lock));
    
    return 1;
}

/* Common dispatch layer across v0 and v2 frames */
int cf_dispatch_rx_content(kis_capture_handler_t *caph, const char *command, 
        uint32_t seqno, const uint8_t *data, size_t packet_sz) {
    int cbret = -1;
    char msgstr[STATUS_MAX];
    size_t i;

    pthread_mutex_lock(&(caph->handler_lock));

    /* Split into commands and handle them */
    if (strncasecmp(command, "PING", 32) == 0) {
        caph->last_ping = time(NULL);
        cf_send_pong(caph, seqno);
        cbret = 1;
        goto finish;
    } else if (strncasecmp(command, "PONG", 32) == 0) {
        cbret = 1;
        goto finish;
    } else if (strncasecmp(command, "KDSLISTINTERFACES", 32) == 0) {
        if (caph->listdevices_cb == NULL) {
            if (caph->verbose)
                fprintf(stderr, "ERROR: Capture source (%s) source does not support listing datasources.\n",
						caph->capsource_type);

            cf_send_listresp(caph, seqno, true, "", NULL, 0);
            cbret = -1;
            goto finish;
        } else {
            cf_params_list_interface_t **interfaces = NULL;
            msgstr[0] = 0;
            cbret = (*(caph->listdevices_cb))(caph, seqno, msgstr, &interfaces);

            if (caph->verbose && strlen(msgstr) > 0) {
                if (cbret >= 0)
                    fprintf(stderr, "INFO: %s\n", msgstr);
                else
                    fprintf(stderr, "ERROR: %s\n", msgstr);
            }

            cf_send_listresp(caph, seqno, cbret >= 0, msgstr, 
                    interfaces, cbret < 0 ? 0 : cbret);

            if (cbret > 0) {
                for (i = 0; i < (size_t) cbret; i++) {
                    if (interfaces[i] != NULL) {
                        if (interfaces[i]->interface != NULL)
                            free(interfaces[i]->interface);
                        if (interfaces[i]->flags != NULL)
                            free(interfaces[i]->flags);
                        if (interfaces[i]->hardware != NULL)
                            free(interfaces[i]->hardware);

                        free(interfaces[i]);
                    }
                }

                free(interfaces);
            }

            /* Always spin down after listing */
            cf_handler_spindown(caph);
            goto finish;
        }
    } else if (strncasecmp(command, "KDSPROBESOURCE", 32) == 0) {
        if (caph->probe_cb == NULL) {
            if (caph->verbose)
                fprintf(stderr, "ERROR:  Source does not support automatic probing.\n");
            pthread_mutex_unlock(&(caph->handler_lock));
            cf_send_proberesp(caph, seqno, false, "Source does not support probing", NULL, NULL);
            cbret = -1;
            goto finish;
        } else {
            KismetDatasource__ProbeSource *probe_cmd = NULL;

            cf_params_interface_t *interfaceparams = NULL;
            cf_params_spectrum_t *spectrumparams = NULL;

            char *uuid = NULL;

            /* Unpack the protbuf */
            probe_cmd = kismet_datasource__probe_source__unpack(NULL, packet_sz, data);

            if (probe_cmd == NULL) {
                fprintf(stderr, "FATAL:  Invalid frame received, unable to unpack "
                        "KDSPROBESOURCE command\n");
                cbret = -1;
                goto finish;
            }
            
            msgstr[0] = 0;
            cbret = (*(caph->probe_cb))(caph, seqno, probe_cmd->definition,
                    msgstr, &uuid, NULL, &interfaceparams, &spectrumparams);

            cf_send_proberesp(caph, seqno, cbret < 0 ? 0 : cbret, msgstr, interfaceparams, spectrumparams);

            kismet_datasource__probe_source__free_unpacked(probe_cmd, NULL);

            if (uuid != NULL)
                free(uuid);

            if (interfaceparams != NULL)
                cf_params_interface_free(interfaceparams);

            if (spectrumparams != NULL)
                cf_params_spectrum_free(spectrumparams);

            /* Always spin down after probing */
            cf_handler_spindown(caph);

            goto finish;
        }
    } else if (strncasecmp(command, "KDSOPENSOURCE", 32) == 0) {
        if (caph->open_cb == NULL) {
            if (caph->verbose)
                fprintf(stderr, "ERROR: Source cannot be opened (no open function)\n");

            pthread_mutex_unlock(&(caph->handler_lock));
            cf_send_openresp(caph, seqno,
                    false, "source cannot be opened", 0, NULL, NULL, NULL);
            cbret = -1;
        } else {
            KismetDatasource__OpenSource *open_cmd = NULL;

            uint32_t dlt;

            cf_params_interface_t *interfaceparams = NULL;
            cf_params_spectrum_t *spectrumparams = NULL;

            char *uuid = NULL;

            /* Unpack the protbuf */
            open_cmd = kismet_datasource__open_source__unpack(NULL, packet_sz, data);

            if (open_cmd == NULL) {
                fprintf(stderr, "FATAL:  Invalid frame received, unable to unpack "
                        "KDSOPENSOURCE command\n");
                cbret = -1;
                goto finish;
            }
            
            msgstr[0] = 0;
            cbret = (*(caph->open_cb))(caph,
                    seqno, open_cmd->definition,
                    msgstr, &dlt, &uuid, NULL,
                    &interfaceparams, &spectrumparams);

            if (caph->verbose && strlen(msgstr) > 0) {
                if (cbret >= 0)
                    fprintf(stderr, "INFO: %s\n", msgstr);
                else
                    fprintf(stderr, "ERROR: %s\n", msgstr);
            }

            cf_send_openresp(caph, seqno,
                    cbret < 0 ? 0 : cbret, msgstr, dlt, uuid, interfaceparams,
                    spectrumparams);

            if (uuid != NULL)
                free(uuid);

            if (interfaceparams != NULL)
                cf_params_interface_free(interfaceparams);

            if (spectrumparams != NULL)
                cf_params_spectrum_free(spectrumparams);

            kismet_datasource__open_source__free_unpacked(open_cmd, NULL);

            if (caph->remote_host) {
                fprintf(stderr, "INFO: %s:%u starting capture...\n", caph->remote_host, caph->remote_port);
            }

            if (cbret >= 0) {
                /* fprintf(stderr, "DEBUG - launching capture thread\n"); */
                cf_handler_launch_capture_thread(caph);
            }

            goto finish;
        }
    } else if (strncasecmp(command, "KDSCONFIGURE", 32) == 0) {
        KismetDatasource__Configure *conf_cmd;

        double chanhop_rate = 0;
        char **chanhop_channels = NULL;
        void **chanhop_priv_channels = NULL;
        size_t chanhop_channels_sz = 0, szi = 0;
        int chanhop_shuffle = 0, chanhop_shuffle_spacing = 1, chanhop_offset = 0;
        void *translate_chan = NULL;

        /* Unpack the protbuf */
        conf_cmd = kismet_datasource__configure__unpack(NULL, packet_sz, data);

        if (conf_cmd == NULL) {
            fprintf(stderr, "FATAL:  Invalid frame received, unable to unpack KDSCONFIGURE command\n");
            cbret = -1;
            goto finish;
        }

        if (conf_cmd->channel != NULL) {
            /* Handle channel set */
            if (caph->chancontrol_cb == NULL) {
                if (caph->verbose)
                    fprintf(stderr, "ERROR: Source does not support channel setting\n");

                pthread_mutex_unlock(&(caph->handler_lock));
                cf_send_configresp(caph, seqno, 0, "Source does not support setting channel", NULL);
                cbret = 0;

                kismet_datasource__configure__free_unpacked(conf_cmd, NULL);
                goto finish;
            } else {
                if (caph->chantranslate_cb != NULL) {
                    translate_chan = (*(caph->chantranslate_cb))(caph, conf_cmd->channel->channel);
                } else {
                    translate_chan = strdup(conf_cmd->channel->channel);
                }

                if (caph->hopping_running) {
                    pthread_cancel(caph->hopthread);
                    caph->hopping_running = 0;
                }

                msgstr[0] = 0;
                cbret = (*(caph->chancontrol_cb))(caph, seqno, translate_chan, msgstr);

                if (caph->verbose && strlen(msgstr) > 0) {
                    if (cbret >= 0)
                        fprintf(stderr, "INFO: %s\n", msgstr);
                    else
                        fprintf(stderr, "ERROR: %s\n", msgstr);
                }

                /* Log the channel we're set to */
                if (cbret > 0) {
                    if (caph->channel != NULL)
                        free(caph->channel);
                    caph->channel = strdup(conf_cmd->channel->channel);
                }

                /* Send a response based on the channel set success */
                cf_send_configresp(caph, seqno, cbret >= 0, msgstr, NULL);

                /* Free our channel copies */
                if (caph->chanfree_cb != NULL)
                    (*(caph->chanfree_cb))(translate_chan);
                else
                    free(translate_chan);

                kismet_datasource__configure__free_unpacked(conf_cmd, NULL);

                goto finish;
            }

        } else if (conf_cmd->hopping != NULL) {
            /* Otherwise process hopping */
            if (conf_cmd->hopping->n_channels == 0) {
                if (caph->verbose)
                    fprintf(stderr, "ERROR:  No channels provided in hopping configuration.\n");

                cf_send_configresp(caph, seqno, 0, "No channels in hopping configuration", NULL);
                cbret = -1;

                kismet_datasource__configure__free_unpacked(conf_cmd, NULL);

                goto finish;
            }

            if (caph->chancontrol_cb == NULL) {
                if (caph->verbose)
                    fprintf(stderr, "ERROR:  Source does not support setting channels\n");

                cf_send_configresp(caph, seqno, 0, "Source does not support setting channel", NULL);
                cbret = -1;

                kismet_datasource__configure__free_unpacked(conf_cmd, NULL);

                goto finish;
            }

            chanhop_channels_sz = conf_cmd->hopping->n_channels;

            chanhop_channels = 
                (char **) malloc(sizeof(char *) * chanhop_channels_sz);

            for (szi = 0; szi < chanhop_channels_sz; szi++) {
                chanhop_channels[szi] = strdup(conf_cmd->hopping->channels[szi]);
            }

            /* Translate all the channels, or dupe them as strings */
            chanhop_priv_channels = 
                (void **) malloc(sizeof(void *) * chanhop_channels_sz);

            for (szi = 0; szi < chanhop_channels_sz; szi++) {
                if (caph->chantranslate_cb != NULL) {
                    chanhop_priv_channels[szi] = 
                        (*(caph->chantranslate_cb))(caph, conf_cmd->hopping->channels[szi]);
                } else {
                    chanhop_priv_channels[szi] = strdup(conf_cmd->hopping->channels[szi]);
                }
            }

            /* Load any configure options or default to what we're already set for */
            if (conf_cmd->hopping->has_rate)
                chanhop_rate = conf_cmd->hopping->rate;
            else
                chanhop_rate = caph->channel_hop_rate;

            if (conf_cmd->hopping->has_shuffle)
                chanhop_shuffle = conf_cmd->hopping->shuffle;
            else
                chanhop_shuffle = caph->channel_hop_shuffle;

            if (conf_cmd->hopping->has_shuffle_skip) 
                chanhop_shuffle_spacing = conf_cmd->hopping->shuffle_skip;
            else 
                chanhop_shuffle_spacing = caph->channel_hop_shuffle_spacing;

            if (conf_cmd->hopping->has_offset)
                chanhop_offset = conf_cmd->hopping->offset;
            else
                chanhop_offset = caph->channel_hop_offset;

            /* Set the hop data, which will handle our thread */
            cf_handler_assign_hop_channels(caph, chanhop_channels,
                    chanhop_priv_channels, chanhop_channels_sz, chanhop_rate,
                    chanhop_shuffle, chanhop_shuffle_spacing, chanhop_offset);

            /* Return a completion, and we do NOT free the channel lists we
             * dynamically allocated out of the buffer with cf_get_CHANHOP, as
             * we're now using them for keeping the channel record in the
             * caph */
            cf_send_configresp(caph, seqno, 1, NULL, NULL);
            cbret = 1;

            kismet_datasource__configure__free_unpacked(conf_cmd, NULL);

            goto finish;
        }
    } else {
        cbret = -1;

        /* If we have an unknown frame handler, give it a chance to process this
         * frame */
        if (caph->unknown_cb != NULL) {
            cbret = 
                (*(caph->unknown_cb))(caph, seqno, command, (const char *) data, packet_sz);
        }

        if (cbret < 0) {
            pthread_mutex_unlock(&(caph->handler_lock));
            cf_send_proberesp(caph, seqno, false, "Unsupported request", NULL, NULL);
            return 0;
        }
    }
    
finish:
    pthread_mutex_unlock(&caph->handler_lock);

    return cbret;
}

int cf_handle_rx_content(kis_capture_handler_t *caph, const uint8_t *buffer, size_t len) {
    kismet_external_frame_t *external_frame;
    kismet_external_frame_v2_t *external_frame_v2;

    /* Incoming size */
    uint32_t packet_sz;

    /* Incoming seqno */
    uint32_t seqno;

    /* Legacy v0 command header */
    KismetExternal__Command *kds_cmd;

    int ret;

    if (len < sizeof(kismet_external_frame_t)) {
        fprintf(stderr, "DEBUG: runt frame\n");
        return -1;
    }

    external_frame = (kismet_external_frame_t *) buffer;
    external_frame_v2 = (kismet_external_frame_v2_t *) buffer;

    /* Check the signature */
    if (ntohl(external_frame->signature) != KIS_EXTERNAL_PROTO_SIG) {
        fprintf(stderr, "FATAL: Capture source (%s) invalid frame header received\n",
				caph->capsource_type);
        return -1;
    }

    /* If the signature passes, see if we can read the whole frame */
    packet_sz = ntohl(external_frame->data_sz);

    if (ntohs(external_frame_v2->v2_sentinel) == KIS_EXTERNAL_V2_SIG &&
            ntohs(external_frame_v2->frame_version) == 0x02) {

        if (len < packet_sz + sizeof(kismet_external_frame_v2_t)) {
            fprintf(stderr, "FATAL: Capture source (%s) malforned too-small v2 packet\n",
					caph->capsource_type);
            return -1;
        }

        seqno = ntohl(external_frame_v2->seqno);

        return cf_dispatch_rx_content(caph, external_frame_v2->command, seqno,
                external_frame_v2->data, packet_sz);
    } else {
        if (len < packet_sz + sizeof(kismet_external_frame_t)) {
            fprintf(stderr, "FATAL: Capture source (%s) malformed too-small v0 packet\n",
					caph->capsource_type);
            return -1;
        }

        kds_cmd = kismet_external__command__unpack(NULL, packet_sz, external_frame->data);

        if (kds_cmd == NULL) {
            fprintf(stderr, "FATAL:  Capture source (%s) invalid frame received, unable to unpack v0 command\n",
					caph->capsource_type);
            return -1;
        }

        ret = cf_dispatch_rx_content(caph, kds_cmd->command, kds_cmd->seqno,
                kds_cmd->content.data, kds_cmd->content.len);

        kismet_external__command__free_unpacked(kds_cmd, NULL);

        return ret;
    }
}


int cf_handle_rb_rx_data(kis_capture_handler_t *caph) {
    size_t rb_available;

    /* Buffer of entire frame, dynamic */
    uint8_t *frame_buf;

    kismet_external_frame_t *external_frame;
    kismet_external_frame_v2_t *external_frame_v2;

    /* Incoming size */
    uint32_t packet_sz;
    uint32_t total_sz = 0;

    int cbret;

    rb_available = kis_simple_ringbuf_used(caph->in_ringbuf);

    if (rb_available < sizeof(kismet_external_frame_t)) {
        /* fprintf(stderr, "DEBUG - insufficient data to represent a frame\n"); */
        return 0;
    }

    if (kis_simple_ringbuf_peek_zc(caph->in_ringbuf, (void **) &frame_buf, 
                sizeof(kismet_external_frame_t)) != sizeof(kismet_external_frame_t)) {
        return 0;
    }

    external_frame = (kismet_external_frame_t *) frame_buf;
    external_frame_v2 = (kismet_external_frame_v2_t *) frame_buf;

    /* Check the signature */
    if (ntohl(external_frame->signature) != KIS_EXTERNAL_PROTO_SIG) {
        kis_simple_ringbuf_peek_free(caph->in_ringbuf, frame_buf);
        fprintf(stderr, "FATAL: Capture source (%s) invalid frame header received\n",
				caph->capsource_type);
        return -1;
    }

    packet_sz = ntohl(external_frame_v2->data_sz);

    /* Check for a v2 frame */
    if (ntohs(external_frame_v2->v2_sentinel) == KIS_EXTERNAL_V2_SIG &&
            ntohs(external_frame_v2->frame_version) == 0x02) {
        total_sz = packet_sz + sizeof(kismet_external_frame_v2_t);
    } else {
        total_sz = packet_sz + sizeof(kismet_external_frame_t);
    }

    if (total_sz >= kis_simple_ringbuf_size(caph->in_ringbuf)) {
        kis_simple_ringbuf_peek_free(caph->in_ringbuf, frame_buf);
        fprintf(stderr, "FATAL: Capture source (%s) incoming packet too large for ringbuf\n",
				caph->capsource_type);
        return -1;
    }

    if (rb_available < total_sz) {
        kis_simple_ringbuf_peek_free(caph->in_ringbuf, frame_buf);
        return 0;
    }

    /* Free the peek of the frame header */
    kis_simple_ringbuf_peek_free(caph->in_ringbuf, frame_buf);

    /* We've got enough to read it all; try to zc the buffer */

    /* Peek our ring buffer */
    if (kis_simple_ringbuf_peek_zc(caph->in_ringbuf, (void **) &frame_buf, total_sz) != total_sz) {
        fprintf(stderr, "FATAL: Capture source (%s) failed to read packet from ringbuf\n",
				caph->capsource_type);
        free(frame_buf);
        return -1;
    }

    cbret = cf_handle_rx_content(caph, frame_buf, total_sz);

    kis_simple_ringbuf_peek_free(caph->in_ringbuf, frame_buf);

    /* Clear it out from the buffer */
    kis_simple_ringbuf_read(caph->in_ringbuf, NULL, total_sz);

    return cbret;
}

int cf_handler_tcp_remote_connect(kis_capture_handler_t *caph) {
    struct hostent *connect_host;
    struct sockaddr_in client_sock, local_sock;
    int client_fd;
    int sock_flags;

    char msgstr[STATUS_MAX];

    char *uuid = NULL;

    int cbret;

    cf_params_interface_t *cpi;
    cf_params_spectrum_t *cps;

    /* If we have nothing to connect to... */
    if (caph->remote_host == NULL)
        return 0;

    /* Remotes are always verbose */
    caph->verbose = 1;

    /* close the fd if it's open */
    if (caph->tcp_fd >= 0) {
        close(caph->tcp_fd);
        caph->tcp_fd = -1;
    }

    /* Reset the last ping */
    caph->last_ping = time(0);

    /* Reset spindown */
    caph->spindown = 0;
    caph->shutdown = 0;

    caph->in_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_IN_SZ);
    if (caph->in_ringbuf == NULL) {
        fprintf(stderr, "FATAL:  Cannot allocate socket ringbuffer\n");
        return -1;
    }

    caph->out_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_OUT_SZ);
    if (caph->out_ringbuf == NULL) {
        fprintf(stderr, "FATAL:  Cannot allocate socket ringbuffer\n");
        return -1;
    }


    /* Perform a local probe on the source to see if it's valid */
    msgstr[0] = 0;

    cpi = NULL;
    cps = NULL;

    if (caph->probe_cb == NULL) {
        fprintf(stderr, "FATAL - unable to connect as remote source when no probe callback provided.\n");
        return -1;
    }

    cbret = (*(caph->probe_cb))(caph, 0, caph->cli_sourcedef, msgstr, &uuid, NULL, &cpi, &cps);

    if (cpi != NULL)
        cf_params_interface_free(cpi);

    if (cps != NULL)
        cf_params_spectrum_free(cps);

    if (cbret <= 0) {
        fprintf(stderr, "FATAL - Could not probe local source prior to connecting to the "
                "remote host: %s\n", msgstr);

        if (uuid)
            free(uuid);
    
        return -1;
    }

    if ((connect_host = gethostbyname(caph->remote_host)) == NULL) {
        fprintf(stderr, "FATAL - Could not resolve hostname for remote connection to '%s'\n",
                caph->remote_host);

        if (uuid)
            free(uuid);

        return -1;
    }

    memset(&client_sock, 0, sizeof(client_sock));
    client_sock.sin_family = connect_host->h_addrtype;
    memcpy((char *) &(client_sock.sin_addr.s_addr), connect_host->h_addr_list[0],
            connect_host->h_length);
    client_sock.sin_port = htons(caph->remote_port);

    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "FATAL - Could not connect to remote host '%s:%u': %s\n",
                caph->remote_host, caph->remote_port, strerror(errno));

        if (uuid)
            free(uuid);

        return -1;
    }

    sock_flags = fcntl(client_fd, F_GETFL, 0);
    fcntl(client_fd, F_SETFL, sock_flags | O_NONBLOCK);

    sock_flags = fcntl(client_fd, F_GETFD, 0);
    fcntl(client_fd, F_SETFD, sock_flags | FD_CLOEXEC);

    memset(&local_sock, 0, sizeof(local_sock));
    local_sock.sin_family = AF_INET;
    local_sock.sin_addr.s_addr = htonl(INADDR_ANY);
    local_sock.sin_port = htons(0);

    if (bind(client_fd, (struct sockaddr *) &local_sock, sizeof(local_sock)) < 0) {
        fprintf(stderr, "FATAL - Could not connect to remote host '%s:%u': %s\n",
                caph->remote_host, caph->remote_port, strerror(errno));
        close(client_fd);

        if (uuid)
            free(uuid);

        return -1;
    }

    if (connect(client_fd, (struct sockaddr *) &client_sock, sizeof(client_sock)) < 0) {
        if (errno != EINPROGRESS) {
            fprintf(stderr, "FATAL - Could not connect to remote host '%s:%u': %s\n",
                    caph->remote_host, caph->remote_port, strerror(errno));

            close(client_fd);

            if (uuid)
                free(uuid);

            return -1;
        }
    }

    caph->tcp_fd = client_fd;

    fprintf(stderr, "INFO: Connected to '%s:%u'...\n", caph->remote_host, caph->remote_port);

    /* Send the NEWSOURCE command to the Kismet server */
    cf_send_newsource(caph, uuid);

    if (uuid)
        free(uuid);

    return 1;
}

#ifdef HAVE_LIBWEBSOCKETS
void ws_connect_attempt(kis_capture_handler_t *caph) {
    char msgstr[STATUS_MAX];
    int cbret;
    cf_params_interface_t *cpi;
    cf_params_spectrum_t *cps;

    /* Remotes are always verbose */
    caph->verbose = 1;

    /* Reset the last ping */
    caph->last_ping = time(0);

    /* Reset spindown */
    caph->spindown = 0;
    caph->shutdown = 0;

    msgstr[0] = 0;
    cpi = NULL;
    cps = NULL;

    if (caph->probe_cb == NULL) {
        fprintf(stderr, "FATAL - unable to connect as remote source when no probe callback "
                "provided.\n");
        caph->spindown = 1;
        return;
    }

    cbret = (*(caph->probe_cb))(caph, 0, caph->cli_sourcedef, msgstr, &caph->lwsuuid, 
            NULL, &cpi, &cps);

    if (cpi != NULL)
        cf_params_interface_free(cpi);

    if (cps != NULL)
        cf_params_spectrum_free(cps);

    if (cbret <= 0) {
        fprintf(stderr, "FATAL - Could not probe local source prior to connecting to the "
                "remote host: %s\n", msgstr);
        caph->spindown = 1;
        return;
    }

    caph->lwsci.context = caph->lwscontext;
    caph->lwsci.port = caph->remote_port;
    caph->lwsci.address = caph->remote_host;
    caph->lwsci.path = caph->lwsuri;
    caph->lwsci.host = caph->lwsci.address;
    caph->lwsci.origin  = caph->lwsci.address;
    caph->lwsci.ssl_connection = 0;

    if (caph->lwsusessl) {
        caph->lwsci.ssl_connection |= LCCSCF_USE_SSL;
    }

    caph->lwsci.protocol = "kismet-remote";
    caph->lwsci.pwsi = &caph->lwsclientwsi;

    if (!lws_client_connect_via_info(&caph->lwsci)) {
        fprintf(stderr, "FATAL - Datasource could not connect websocket\n");
        return;
    }
}

/* handler which gets dispatched by libwebsockets */
int ws_remotecap_broker(struct lws *wsi, enum lws_callback_reasons reason,
        void *user, void *in, size_t len) {

    kis_capture_handler_t *caph = (kis_capture_handler_t *) lws_context_user(lws_get_context(wsi));

    struct cf_ws_msg *wmsg;
    int m;

    switch (reason) {
        case LWS_CALLBACK_PROTOCOL_INIT:
            caph->lwscontext = lws_get_context(wsi);
            caph->lwsprotocol = lws_get_protocol(wsi);
            caph->lwsvhost = lws_get_vhost(wsi);
            ws_connect_attempt(caph);

            pthread_mutex_lock(&caph->handler_lock);

            if (caph->spindown) {
                caph->lwsclientwsi = NULL;
                caph->lwsestablished = 0;
                caph->shutdown = 1;
            }

	    pthread_mutex_unlock(&caph->handler_lock);

            break;
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            pthread_mutex_lock(&caph->handler_lock);
            caph->lwsclientwsi = NULL;
            caph->lwsestablished = 0;
            caph->shutdown = 1;
            pthread_mutex_unlock(&caph->handler_lock);

            fprintf(stderr, "FATAL: Datasource could not connect websocket client\n");
            lws_cancel_service(caph->lwscontext);
            break;
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            caph->lwsestablished = 1;
            cf_send_newsource(caph, caph->lwsuuid);
            break;
        case LWS_CALLBACK_CLIENT_WRITEABLE:
            pthread_mutex_lock(&caph->out_ringbuf_lock);

            wmsg = (struct cf_ws_msg *) lws_ring_get_element(caph->lwsring, &caph->lwstail);
            if (wmsg == NULL)
                goto skip;

            m = lws_write(wsi, (unsigned char *) wmsg->payload + LWS_PRE, 
                    wmsg->len, LWS_WRITE_BINARY);

            if (m != (int) wmsg->len) {
                fprintf(stderr, "FATAL: Datasource could not write data to websocket\n");
                caph->shutdown = 1;
                lws_cancel_service(caph->lwscontext);
                pthread_mutex_unlock(&caph->out_ringbuf_lock);
                return -1;
            }

            lws_ring_consume_single_tail(caph->lwsring, &caph->lwstail, 1);

            if (lws_ring_get_element(caph->lwsring, &caph->lwstail)) {
                lws_callback_on_writable(wsi);
            } else if (caph->spindown) {
                /* If we have no more packets and we're spinning down, finish */
                caph->shutdown = 1;
                lws_cancel_service(caph->lwscontext);
                pthread_mutex_unlock(&caph->out_ringbuf_lock);
                return -1;
            }

            /* Signal to any waiting IO that the buffer has some
             * headroom */
            pthread_cond_broadcast(&(caph->out_ringbuf_flush_cond));

skip:
            pthread_mutex_unlock(&caph->out_ringbuf_lock);
            break;
        case LWS_CALLBACK_CLIENT_CLOSED:
            fprintf(stderr, "FATAL: Datasource websocket closed\n");
            pthread_mutex_lock(&caph->handler_lock);
            caph->lwsclientwsi = NULL;
            caph->lwsestablished = 0;
            caph->shutdown = 1;
            pthread_mutex_unlock(&caph->handler_lock);
            return -1;
        case LWS_CALLBACK_CLIENT_RECEIVE:
            if (cf_handle_rx_content(caph, (const uint8_t *) in, len) < 0) {
                caph->lwsestablished = 0;
                caph->spindown = 1;
                lws_cancel_service(caph->lwscontext);
            }

            break;
        default: 
            break;
    }

    return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void ws_destroy_msg(void *in_msg) {
    struct cf_ws_msg *msg = (struct cf_ws_msg *) in_msg;

    free(msg->payload);
    msg->payload = NULL;
    msg->len = 0;
}
#endif

int cf_handler_loop(kis_capture_handler_t *caph) {
    fd_set rset, wset;
    int max_fd;
    int read_fd, write_fd;
    struct timeval tm;
    int spindown;
    int ret;
    int rv = 0;
    cf_ipc_t *ipc_iter = NULL;

    if (caph->use_tcp || caph->use_ipc) {
        if (caph->in_ringbuf == NULL) {
            caph->in_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_IN_SZ);

            if (caph->in_ringbuf == NULL) {
                fprintf(stderr, "FATAL:  Cannot allocate socket ringbuffer\n");
                return -1;
            }
        }

        if (caph->out_ringbuf == NULL) {
            caph->out_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_OUT_SZ);

            if (caph->out_ringbuf == NULL) {
                fprintf(stderr, "FATAL:  Cannot allocate socket ringbuffer\n");
                return -1;
            }
        }

        if (caph->tcp_fd >= 0) {
            read_fd = caph->tcp_fd;
            write_fd = caph->tcp_fd;
        } else {
            /* Set our descriptors as nonblocking */
            fcntl(caph->in_fd, F_SETFL, fcntl(caph->in_fd, F_GETFL, 0) | O_NONBLOCK);
            fcntl(caph->out_fd, F_SETFL, fcntl(caph->out_fd, F_GETFL, 0) | O_NONBLOCK);

            read_fd = caph->in_fd;
            write_fd = caph->out_fd;
        }

        /* Basic select loop using ring buffers; we fill in from the read descriptor
         * and try to make frames; similarly we populate the outbound descriptor from
         * anything that comes in from our IO thread */
        while (1) {
            FD_ZERO(&rset);
            FD_ZERO(&wset);

            /* Check shutdown state or if we're spinning down */
            pthread_mutex_lock(&(caph->handler_lock));

            /* Hard shutdown */
            if (caph->shutdown) {
                fprintf(stderr, "FATAL: Shutting down main select loop\n");
                pthread_mutex_unlock(&(caph->handler_lock));
                rv = -1;
                break;
            }

            if (caph->last_ping != 0 && time(NULL) - caph->last_ping > 15) {
                fprintf(stderr, "FATAL: Capture source %u did not get PING from Kismet for "
                        "over 15 seconds; shutting down\n", getpid());
                pthread_mutex_unlock(&(caph->handler_lock));
                rv = -1;
                break;
            }

            /* Copy spindown state outside of lock */
            spindown = caph->spindown;

            max_fd = 0;

            ipc_iter = caph->ipc_list;

            while (ipc_iter != NULL) {
                if (ipc_iter->running == 0) {
                    ipc_iter = ipc_iter->next;
                    continue;
                }

                if (spindown == 0) {
                    FD_SET(ipc_iter->out_fd, &rset);
                    if (max_fd < ipc_iter->out_fd)
                        max_fd = ipc_iter->out_fd;

                    FD_SET(ipc_iter->err_fd, &rset);
                    if (max_fd < ipc_iter->err_fd)
                        max_fd = ipc_iter->err_fd;
                }

                pthread_mutex_lock(&ipc_iter->out_ringbuf_lock);

                if (kis_simple_ringbuf_used(ipc_iter->out_ringbuf) != 0) {
                    FD_SET(ipc_iter->in_fd, &wset);
                    if (max_fd < ipc_iter->in_fd)
                        max_fd = ipc_iter->in_fd;
                }

                pthread_mutex_unlock(&ipc_iter->out_ringbuf_lock);

                ipc_iter = ipc_iter->next;
            }

            pthread_mutex_unlock(&(caph->handler_lock));

            /* Only set read sets if we're not spinning down */
            if (spindown == 0) {
                /* Only set rset if we're not spinning down */
                FD_SET(read_fd, &rset);
                if (max_fd < read_fd)
                    max_fd = read_fd;
            }

            /* Inspect the write buffer - do we have data? */
            pthread_mutex_lock(&(caph->out_ringbuf_lock));

            if (kis_simple_ringbuf_used(caph->out_ringbuf) != 0) {
                FD_SET(write_fd, &wset);
                if (max_fd < write_fd)
                    max_fd = write_fd;
            } else if (spindown != 0) {
                pthread_mutex_unlock(&(caph->out_ringbuf_lock));
                rv = 0;
                break;
            }

            pthread_mutex_unlock(&(caph->out_ringbuf_lock));

            tm.tv_sec = 0;
            tm.tv_usec = 500000;

            if ((ret = select(max_fd + 1, &rset, &wset, NULL, &tm)) < 0) {
                if (errno != EINTR && errno != EAGAIN) {
                    fprintf(stderr, "FATAL:  Error during select(): %s\n", strerror(errno));
                    rv = -1;
                    break;
                }
            }

            if (ret == 0)
                continue;

            pthread_mutex_lock(&caph->handler_lock);

            ipc_iter = caph->ipc_list;

            while (ipc_iter != NULL) {
                if (ipc_iter->running == 0) {
                    ipc_iter = ipc_iter->next;
                    continue;
                }

                /* If the IPC handler wants to be re-called, do it immediately
                 * regardless of incoming data */
                if (ipc_iter->retry_rx && ipc_iter->rx_callback != NULL) {
                    ipc_iter->rx_callback(caph, ipc_iter, 0);
                }

                /* Handle stdout ops into the buffer */
                if (FD_ISSET(ipc_iter->out_fd, &rset) && ipc_iter->running) {
                    while (kis_simple_ringbuf_available(ipc_iter->in_ringbuf)) {
                        ssize_t amt_read;
                        size_t maxread = 0;
                        uint8_t *buf;
                        size_t buf_avail;

                        buf_avail = kis_simple_ringbuf_available(ipc_iter->in_ringbuf);
                        maxread = kis_simple_ringbuf_reserve_zcopy(ipc_iter->in_ringbuf, (void **) &buf, buf_avail);

                        amt_read = read(ipc_iter->out_fd, buf, maxread);

                        if (amt_read == 0) {
                            kis_simple_ringbuf_commit(ipc_iter->in_ringbuf, buf, 0);
                            if (ipc_iter->term_callback != NULL) {
                                ipc_iter->term_callback(caph, ipc_iter, -1);
                            }
                            ipc_iter->running = 0;
                            break;
                        } else if (amt_read < 0) {
                            kis_simple_ringbuf_commit(ipc_iter->in_ringbuf, buf, 0);

                            if (errno != EINTR && errno != EAGAIN) {
                                if (ipc_iter->term_callback != NULL) {
                                    ipc_iter->term_callback(caph, ipc_iter, -1);
                                }
                                ipc_iter->running = 0;
                            }

                            break;
                        } else { 
                            kis_simple_ringbuf_commit(ipc_iter->in_ringbuf, buf, amt_read);
                            amt_read = kis_simple_ringbuf_used(ipc_iter->in_ringbuf);

                            if (ipc_iter->rx_callback != NULL) { 
                                ipc_iter->retry_rx = 0;
                                ipc_iter->rx_callback(caph, ipc_iter, amt_read);
                            } else {
                                /* If there is no handler, throw the data out */
                                kis_simple_ringbuf_clear(ipc_iter->in_ringbuf);
                            }
                        }
                    }
                }

                if (FD_ISSET(ipc_iter->err_fd, &rset) && ipc_iter->running) {
                    while (kis_simple_ringbuf_available(ipc_iter->err_ringbuf)) {
                        ssize_t amt_read;
                        size_t maxread = 0;
                        uint8_t *buf;
                        size_t buf_avail;

                        buf_avail = kis_simple_ringbuf_available(ipc_iter->err_ringbuf);
                        maxread = kis_simple_ringbuf_reserve_zcopy(ipc_iter->err_ringbuf, (void **) &buf, buf_avail);

                        amt_read = read(ipc_iter->err_fd, buf, maxread);

                        if (amt_read == 0) {
                            kis_simple_ringbuf_commit(ipc_iter->err_ringbuf, buf, 0);
                            if (ipc_iter->term_callback != NULL) {
                                ipc_iter->term_callback(caph, ipc_iter, -1);
                            }
                            ipc_iter->running = 0;
                            break;
                        } else if (amt_read < 0) {
                            kis_simple_ringbuf_commit(ipc_iter->err_ringbuf, buf, 0);

                            if (errno != EINTR && errno != EAGAIN) {
                                if (ipc_iter->term_callback != NULL) {
                                    ipc_iter->term_callback(caph, ipc_iter, -1);
                                }
                                ipc_iter->running = 0;
                            }

                            break;
                        } else {
                            kis_simple_ringbuf_commit(ipc_iter->err_ringbuf, buf, amt_read);
                            amt_read = kis_simple_ringbuf_used(ipc_iter->err_ringbuf);

                            if (ipc_iter->err_callback != NULL) {
                                ipc_iter->err_callback(caph, ipc_iter, amt_read);
                            } else {
                                /* If there is no handler, throw the data out */
                                kis_simple_ringbuf_clear(ipc_iter->err_ringbuf);
                            }
                        }
                    }
                }

                /* Write anything queued to the stdin of the forked process */
                if (FD_ISSET(ipc_iter->in_fd, &wset) && ipc_iter->running) {
                    pthread_mutex_lock(&ipc_iter->out_ringbuf_lock);

                    if (kis_simple_ringbuf_used(ipc_iter->out_ringbuf) != 0) {
                        ssize_t written_sz = 0;
                        size_t peeked_sz = 0;
                        uint8_t *peek_buf = NULL;

                        peeked_sz = kis_simple_ringbuf_peek_zc(ipc_iter->out_ringbuf, (void **) &peek_buf, 0);

                        /* Don't know how we'd get here... */
                        if (peeked_sz == 0) {
                            kis_simple_ringbuf_peek_free(ipc_iter->out_ringbuf, peek_buf);
                        } else {
                            written_sz = write(ipc_iter->in_fd, peek_buf, peeked_sz);

                            if (written_sz < 0) {
                                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                                    kis_simple_ringbuf_peek_free(ipc_iter->out_ringbuf, peek_buf);
                                    if (ipc_iter->term_callback != NULL) {
                                        ipc_iter->term_callback(caph, ipc_iter, -1);
                                    }
                                    ipc_iter->running = 0;
                                }

                            } else {
                                kis_simple_ringbuf_peek_free(ipc_iter->out_ringbuf, peek_buf);
                                kis_simple_ringbuf_read(ipc_iter->out_ringbuf, NULL, (size_t) written_sz);
                            }
                        }
                    }

                    pthread_mutex_unlock(&ipc_iter->out_ringbuf_lock);
                }

                ipc_iter = ipc_iter->next;
            }

            pthread_mutex_unlock(&caph->handler_lock);

            if (FD_ISSET(read_fd, &rset)) {
                while (kis_simple_ringbuf_available(caph->in_ringbuf)) {
                    /* We use a fixed-length read buffer for simplicity, and we shouldn't
                     * ever have too many incoming packets queued because the datasource
                     * protocol is very tx-heavy */
                    ssize_t amt_read;
                    size_t amt_buffered;
                    uint8_t rbuf[1024];
                    size_t maxread = 0;

                    /* Read don't read more than we can handle in the buffer or in our
                     * read slot */
                    maxread = kis_simple_ringbuf_available(caph->in_ringbuf);

                    if (maxread > 1024)
                        maxread = 1024;

                    if (caph->remote_host != NULL) {
                        // amt_read = recv(read_fd, rbuf, maxread, MSG_DONTWAIT);
                        amt_read = recv(read_fd, rbuf, maxread, 0);
                    } else {
                        amt_read = read(read_fd, rbuf, maxread);
                    }

                    if (amt_read == 0) {
                        fprintf(stderr, "FATAL: Remote side closed read pipe\n");
                        rv = -1;
                        goto cap_loop_fail;
                    } else if (amt_read < 0) {
                        /* Detect nonblocking */
                        if (errno != EINTR && errno != EAGAIN) {
                            fprintf(stderr, "FATAL:  Error during read(): %s\n", strerror(errno));
                            rv = -1;
                            goto cap_loop_fail;
                        } else {
                            /* Drop out of read/process loop */
                            break;
                        }
                    }

                    amt_buffered = kis_simple_ringbuf_write(caph->in_ringbuf, rbuf, amt_read);

                    if ((ssize_t) amt_buffered != amt_read) {
                        /* Bail entirely - to do, report error if we can over connection */
                        fprintf(stderr, "FATAL:  Error during read(): insufficient buffer space\n");
                        rv = -1;
                        goto cap_loop_fail;
                    }

                    /* See if we have a complete packet to do something with */
                    if (cf_handle_rb_rx_data(caph) < 0) {
                        /* Enter spindown if processing an incoming packet failed */
                        fprintf(stderr, "FATAL:  Datasource helper (%s) failed, could not process incoming control packet.\n",
								caph->capsource_type);
                        cf_handler_spindown(caph);
                    }
                }
            }

            if (FD_ISSET(write_fd, &wset)) {
                /* We can write data - lock the ring buffer mutex and write out
                 * whatever we can; we peek the ringbuffer and then flag off what
                 * we've successfully written out */
                ssize_t written_sz;
                size_t peeked_sz;
                uint8_t *peek_buf = NULL;

                pthread_mutex_lock(&(caph->out_ringbuf_lock));

                peeked_sz = kis_simple_ringbuf_peek_zc(caph->out_ringbuf, (void **) &peek_buf, 0);

                /* Don't know how we'd get here... */
                if (peeked_sz == 0) {
                    kis_simple_ringbuf_peek_free(caph->out_ringbuf, peek_buf);
                    pthread_mutex_unlock(&(caph->out_ringbuf_lock));
                    continue;
                }

                /* Same nonsense as before - send on tcp, write on pipes */
                if (caph->remote_host != NULL) {
                    // written_sz = send(write_fd, peek_buf, peeked_sz, MSG_DONTWAIT);
                    written_sz = send(write_fd, peek_buf, peeked_sz, 0);
                } else {
                    written_sz = write(write_fd, peek_buf, peeked_sz);
                }

                if (written_sz < 0) {
                    if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                        kis_simple_ringbuf_peek_free(caph->out_ringbuf, peek_buf);
                        pthread_mutex_unlock(&(caph->out_ringbuf_lock));
                        fprintf(stderr, "FATAL:  Error during write(): %s\n", strerror(errno));
                        rv = -1;
                        break;
                    }
                }

                /* Flag it as consumed */
                kis_simple_ringbuf_read(caph->out_ringbuf, NULL, (size_t) written_sz);

                /* Get rid of the peek */
                kis_simple_ringbuf_peek_free(caph->out_ringbuf, peek_buf);

                /* Unlock */
                pthread_mutex_unlock(&(caph->out_ringbuf_lock));

                /* Signal to any waiting IO that the buffer has some
                 * headroom */
                pthread_cond_broadcast(&(caph->out_ringbuf_flush_cond));
            }
        }
    } else if (caph->use_ws) {
#ifdef HAVE_LIBWEBSOCKETS
        caph->lwsring = 
            lws_ring_create(sizeof(struct cf_ws_msg), CAP_FRAMEWORK_WS_BUF_SZ, ws_destroy_msg);

        if (!caph->lwsring) {
            fprintf(stderr, "FATAL:  Cannot allocate websocket ringbuffer\n");
            return -1;
        }

        ret = 0;

        while (ret >= 0 && !caph->shutdown)
            lws_service(caph->lwscontext, 0);

        fprintf(stderr, "FATAL:  Datasource exiting libwebsocket loop\n");
#endif
    } else {
        fprintf(stderr, "FATAL:  Could not determine mode?\n");
        return -1;
    }


    /* Fall out of select loop */

cap_loop_fail:
    /* Kill the capture thread */
    pthread_mutex_lock(&(caph->out_ringbuf_lock));

    if (caph->capture_running) {
        pthread_cancel(caph->capturethread);
        caph->capture_running = 0;
    }

    pthread_mutex_unlock(&(caph->out_ringbuf_lock));

    /* Kill anything pending */
    pthread_cond_broadcast(&(caph->out_ringbuf_flush_cond));
    return rv;
}

int cf_send_rb_raw_bytes(kis_capture_handler_t *caph, uint8_t *data, size_t len) {
    pthread_mutex_lock(&(caph->out_ringbuf_lock));

    if (kis_simple_ringbuf_available(caph->out_ringbuf) < len) {
        /* fprintf(stderr, "debug - Insufficient room in write buffer to queue data\n"); */
        pthread_mutex_unlock(&(caph->out_ringbuf_lock));
        return 0;
    }

    if (kis_simple_ringbuf_write(caph->out_ringbuf, data, len) != len) {
        fprintf(stderr, "FATAL: Failed to write data to buffer\n");
        pthread_mutex_unlock(&(caph->out_ringbuf_lock));
        return -1;
    }

    pthread_mutex_unlock(&(caph->out_ringbuf_lock));

    return 1;
}

#ifdef HAVE_LIBWEBSOCKETS
int cf_send_ws_raw_bytes(kis_capture_handler_t *caph, uint8_t *data, size_t len) {
    int n;
    struct cf_ws_msg wsmsg;

    pthread_mutex_lock(&caph->out_ringbuf_lock);

    n = lws_ring_get_count_free_elements(caph->lwsring);
    if (n == 0) {
        pthread_mutex_unlock(&caph->out_ringbuf_lock);
        lws_cancel_service(caph->lwscontext);
        return 0;
    }

    wsmsg.payload = (char *) malloc(LWS_PRE + len);
    if (wsmsg.payload == NULL) {
        fprintf(stderr, "FATAL: Failed to allocate ws buffer\n");
        pthread_mutex_unlock(&caph->out_ringbuf_lock);
        lws_cancel_service(caph->lwscontext);
        return -1;
    }

    memcpy(wsmsg.payload + LWS_PRE, data, len);

    wsmsg.len = len;

    n = (int) lws_ring_insert(caph->lwsring, &wsmsg, 1);
    if (n != 1) {
        fprintf(stderr, "FATAL:  Failed to queue ws message\n");
        pthread_mutex_unlock(&caph->out_ringbuf_lock);
        lws_cancel_service(caph->lwscontext);
        return -1;
    }

    pthread_mutex_unlock(&caph->out_ringbuf_lock);

    pthread_mutex_lock(&caph->handler_lock);
    if (caph->lwsclientwsi != NULL)
        lws_callback_on_writable(caph->lwsclientwsi);
    pthread_mutex_unlock(&caph->handler_lock);

    return 1;
}
#endif

int cf_send_raw_bytes(kis_capture_handler_t *caph, uint8_t *data, size_t len) {
    if (caph->use_tcp || caph->use_ipc)
        return cf_send_rb_raw_bytes(caph, data, len);
#ifdef HAVE_LIBWEBSOCKETS
    else if (caph->use_ws)
        return cf_send_ws_raw_bytes(caph, data, len);
#endif

    return -1;
}

int cf_send_rb_packet(kis_capture_handler_t *caph, const char *command, uint32_t seqno,
        uint8_t *data, size_t len) {

    /* Frame we'll be sending */
    kismet_external_frame_v2_t *frame;
    /* Size of serialized command data */
    size_t rs_sz;
    /* Buffer holding all of it */
    uint8_t *send_buffer;

    /* Directly inject into the ringbuffer with a zero-copy */

    pthread_mutex_lock(&(caph->out_ringbuf_lock));

    rs_sz = kis_simple_ringbuf_reserve(caph->out_ringbuf, (void **) &send_buffer, 
            len + sizeof(kismet_external_frame_v2_t));

    if (rs_sz != len + sizeof(kismet_external_frame_v2_t)) {
        // fprintf(stderr, "DEBUG - insufficient size in outgoing buffer for %lu\n", len);
        free(data);
        pthread_mutex_unlock(&(caph->out_ringbuf_lock));
        return 0;
    }

    /* Map to the tx frame */
    frame = (kismet_external_frame_v2_t *) send_buffer;

    /* Set the signature and data size */
    frame->signature = htonl(KIS_EXTERNAL_PROTO_SIG);
    frame->data_sz = htonl(len);

    frame->v2_sentinel = htons(KIS_EXTERNAL_V2_SIG);
    frame->frame_version = htons(2);

    frame->seqno = htonl(seqno);

    strncpy(frame->command, command, 32);

    memcpy(frame->data, data, len);

    kis_simple_ringbuf_commit(caph->out_ringbuf, send_buffer, rs_sz);

    pthread_mutex_unlock(&(caph->out_ringbuf_lock));

    free(data);

    return rs_sz;
}

#ifdef HAVE_LIBWEBSOCKETS
int cf_send_ws_packet(kis_capture_handler_t *caph, const char *command, uint32_t seqno,
        uint8_t *data, size_t len) {
    /* Frame we'll be sending */
    kismet_external_frame_v2_t *frame;
    /* message buffer */
    struct cf_ws_msg wsmsg;

    int n;

    pthread_mutex_lock(&caph->out_ringbuf_lock);

    n = lws_ring_get_count_free_elements(caph->lwsring);
    if (n == 0) {
        free(data);
        pthread_mutex_unlock(&caph->out_ringbuf_lock);
        return 0;
    }

    wsmsg.payload = (char *) malloc(LWS_PRE + len + sizeof(kismet_external_frame_v2_t));
    if (wsmsg.payload == NULL) {
        free(data);
        fprintf(stderr, "FATAL: Failed to allocate ws buffer\n");
        pthread_mutex_unlock(&caph->out_ringbuf_lock);
        return -1;
    }

    /* Map to the tx frame */
    frame = (kismet_external_frame_v2_t *) (wsmsg.payload + LWS_PRE);

    /* Set the signature and data size */
    frame->signature = htonl(KIS_EXTERNAL_PROTO_SIG);
    frame->data_sz = htonl(len);

    frame->v2_sentinel = htons(KIS_EXTERNAL_V2_SIG);
    frame->frame_version = htons(2);

    frame->seqno = htonl(seqno);
    strncpy(frame->command, command, 32);

    memcpy(frame->data, data, len);

    wsmsg.len = len + sizeof(kismet_external_frame_v2_t);

    n = (int) lws_ring_insert(caph->lwsring, &wsmsg, 1);
    if (n != 1) {
        free(data);
        fprintf(stderr, "FATAL:  Failed to queue ws message\n");
        pthread_mutex_unlock(&caph->out_ringbuf_lock);
        lws_cancel_service(caph->lwscontext);
        return -1;
    }

    free(data);

    pthread_mutex_unlock(&(caph->out_ringbuf_lock));

    pthread_mutex_lock(&caph->handler_lock);
    if (caph->lwsclientwsi != NULL)
        lws_callback_on_writable(caph->lwsclientwsi);
    pthread_mutex_unlock(&caph->handler_lock);

    return 1;
}

#endif

int cf_send_packet(kis_capture_handler_t *caph, const char *packtype, uint8_t *data, size_t len) {
    uint32_t seqno;

    /* Lock the handler and get the next sequence number */
    pthread_mutex_lock(&(caph->handler_lock));
    if (++caph->seqno == 0)
        caph->seqno = 1;
    seqno = caph->seqno;
    pthread_mutex_unlock(&(caph->handler_lock));

    if (caph->use_tcp || caph->use_ipc) {
        return cf_send_rb_packet(caph, packtype, seqno, data, len);
#ifdef HAVE_LIBWEBSOCKETS
    } else if (caph->use_ws) {
        return cf_send_ws_packet(caph, packtype, seqno, data, len);
#endif
    } else {
        fprintf(stderr, "ERROR:  cf_send_packet with unknown connection type\n");
        return -1;
    }
}

int cf_send_message(kis_capture_handler_t *caph, const char *msg, unsigned int flags) {
    KismetExternal__MsgbusMessage kemsg;
    uint8_t *buf;
    size_t len;

    kismet_external__msgbus_message__init(&kemsg);

    kemsg.msgtext = strdup(msg);
    kemsg.msgtype = (KismetExternal__MsgbusMessage__MessageType) flags;

    len = kismet_external__msgbus_message__get_packed_size(&kemsg);
    buf = (uint8_t *) malloc(len);

    if (buf == NULL) {
        free(kemsg.msgtext);
        return -1;
    }

    kismet_external__msgbus_message__pack(&kemsg, buf);

    free(kemsg.msgtext);

    return cf_send_packet(caph, "MESSAGE", buf, len);
}

int cf_send_warning(kis_capture_handler_t *caph, const char *warning) {
    KismetDatasource__WarningReport kewarning;
    uint8_t *buf;
    size_t len;

    kismet_datasource__warning_report__init(&kewarning);

    kewarning.warning = strdup(warning);

    len = kismet_datasource__warning_report__get_packed_size(&kewarning);
    buf = (uint8_t *) malloc(len);

    if (buf == NULL) {
        free(kewarning.warning);
        return -1;
    }

    kismet_datasource__warning_report__pack(&kewarning, buf);

    free(kewarning.warning);

    return cf_send_packet(caph, "KDSWARNINGREPORT", buf, len);
}

int cf_send_error(kis_capture_handler_t *caph, uint32_t in_seqno, const char *msg) {
    KismetDatasource__ErrorReport keerror;
    KismetDatasource__SubSuccess kesuccess;
    KismetExternal__MsgbusMessage kemsg;

    kismet_datasource__error_report__init(&keerror);
    kismet_datasource__sub_success__init(&kesuccess);
    kismet_external__msgbus_message__init(&kemsg);

    kesuccess.success = false;
    kesuccess.seqno = in_seqno;

    kemsg.msgtext = strdup(msg);
    kemsg.msgtype = MSGFLAG_ERROR;

    keerror.success = &kesuccess;
    keerror.message = &kemsg;

    uint8_t *buf;
    size_t len;

    len = kismet_datasource__error_report__get_packed_size(&keerror);
    buf = (uint8_t *) malloc(len);

    if (buf == NULL) {
        free(kemsg.msgtext);
        return -1;
    }

    kismet_datasource__error_report__pack(&keerror, buf);

    free(kemsg.msgtext);

    return cf_send_packet(caph, "KDSERRORREPORT", buf, len);
}

int cf_send_listresp(kis_capture_handler_t *caph, uint32_t seq, unsigned int success,
        const char *msg, cf_params_list_interface_t **interfaces, size_t len) {
    KismetDatasource__InterfacesReport keinterfaces;
    KismetDatasource__SubSuccess kesuccess;
    KismetExternal__MsgbusMessage kemsg;
    KismetDatasource__SubInterface **kesubinterfaces = NULL;

    kismet_datasource__interfaces_report__init(&keinterfaces);
    kismet_datasource__sub_success__init(&kesuccess);
    kismet_external__msgbus_message__init(&kemsg);

    uint8_t *buf;
    size_t buf_len;

    size_t i;

    bool fault = false;

    if (len > 0) {
        kesubinterfaces = 
            (KismetDatasource__SubInterface **) malloc(sizeof(KismetDatasource__SubInterface *) * len);

        if (kesubinterfaces == NULL) {
            return -1;
        }

        for (i = 0; i < len; i++) {
            kesubinterfaces[i] = 
                (KismetDatasource__SubInterface *) malloc(sizeof(KismetDatasource__SubInterface));

            if (kesubinterfaces[i] == NULL) {
                fault = true;
                break;
            }

            kismet_datasource__sub_interface__init(kesubinterfaces[i]);
           
            /* Use the allocated data; we don't need to free it ourselves */
            kesubinterfaces[i]->interface = interfaces[i]->interface;
            kesubinterfaces[i]->flags = interfaces[i]->flags;
            kesubinterfaces[i]->hardware = interfaces[i]->hardware;
        }

        if (fault) {
            for (i = 0; i < len; i++) {
                if (kesubinterfaces[i] == NULL)
                    break;

                free(kesubinterfaces[i]);
            }

            free(kesubinterfaces);

            return -1;
        }

        keinterfaces.n_interfaces = len;
        keinterfaces.interfaces = kesubinterfaces;
    }

    if (msg != NULL) {
        kemsg.msgtext = strdup(msg);

        if (success) {
            kemsg.msgtype = MSGFLAG_INFO;

            if (caph->verbose)
                fprintf(stderr, "INFO: %s\n", msg);

        } else {
            kemsg.msgtype = MSGFLAG_ERROR;

            if (caph->verbose)
                fprintf(stderr, "ERROR: %s\n", msg);
        }

        keinterfaces.message = &kemsg;
    }

    kesuccess.success = success;
    kesuccess.seqno = seq;
    keinterfaces.success = &kesuccess;

    buf_len = kismet_datasource__interfaces_report__get_packed_size(&keinterfaces);
    buf = (uint8_t *) malloc(buf_len);

    if (buf == NULL) {
        free(kemsg.msgtext);
        return -1;
    }

    kismet_datasource__interfaces_report__pack(&keinterfaces, buf);

    if (msg)
        free(kemsg.msgtext);

    /* We don't need to get rid of the contents of these, they're sharing memory
     * with the interface report coming in */
    for (i = 0; i < len; i++) {
        if (kesubinterfaces[i] == NULL)
            break;

        free(kesubinterfaces[i]);
    }

    free(kesubinterfaces);

    return cf_send_packet(caph, "KDSINTERFACESREPORT", buf, buf_len);
}

int cf_send_proberesp(kis_capture_handler_t *caph, uint32_t seq, 
        unsigned int success, const char *msg, 
        cf_params_interface_t *interface, cf_params_spectrum_t *spectrum) {

    KismetDatasource__ProbeSourceReport keprobe;
    KismetDatasource__SubSuccess kesuccess;
    KismetExternal__MsgbusMessage kemsg;
    KismetDatasource__SubChannels kechannels;
    KismetDatasource__SubChanset kechanset;
    KismetDatasource__SubSpecset kespecset;

    uint8_t *buf;
    size_t buf_len;
    

    kismet_datasource__probe_source_report__init(&keprobe);
    kismet_datasource__sub_success__init(&kesuccess);
    kismet_external__msgbus_message__init(&kemsg);
    kismet_datasource__sub_channels__init(&kechannels);
    kismet_datasource__sub_chanset__init(&kechanset);
    kismet_datasource__sub_specset__init(&kespecset);

    /* Always set the success */
    kesuccess.success = success;
    kesuccess.seqno = seq;

    keprobe.success = &kesuccess;

    if (success) {
        if (caph->verbose)
            fprintf(stderr, "INFO: %s\n", msg);
    } else {
        if (caph->verbose)
            fprintf(stderr, "ERROR: %s\n", msg);
    }

    if (interface != NULL) {
        if (interface->chanset != NULL) {
            kechanset.channel = interface->chanset;
            keprobe.channel = &kechanset;
        }
        
        if (interface->channels_len != 0) {
            kechannels.n_channels = interface->channels_len;
            kechannels.channels = interface->channels;
            keprobe.channels = &kechannels;
        }

        if (interface->hardware != NULL) {
            keprobe.hardware = interface->hardware;
        }

        if (spectrum != NULL) {
            kespecset.has_start_mhz = true;
            kespecset.start_mhz = spectrum->start_mhz;

            kespecset.has_end_mhz = true;
            kespecset.end_mhz = spectrum->end_mhz;

            kespecset.has_samples_per_bucket = true;
            kespecset.samples_per_bucket = spectrum->samples_per_freq;

            kespecset.has_bucket_width_hz = true;
            kespecset.bucket_width_hz = spectrum->bin_width;

            kespecset.has_enable_amp = true;
            kespecset.enable_amp = spectrum->amp;

            kespecset.has_if_amp = true;
            kespecset.if_amp = spectrum->if_amp;

            kespecset.has_baseband_amp = true;
            kespecset.baseband_amp = spectrum->baseband_amp;

            keprobe.spectrum = &kespecset;
        }
    }

    buf_len = kismet_datasource__probe_source_report__get_packed_size(&keprobe);
    buf = (uint8_t *) malloc(buf_len);

    if (buf == NULL) {
        if (msg)
            free(kemsg.msgtext);
        return -1;
    }

    kismet_datasource__probe_source_report__pack(&keprobe, buf);

    if (msg)
        free(kemsg.msgtext);
    
    return cf_send_packet(caph, "KDSPROBESOURCEREPORT", buf, buf_len);
}

int cf_send_openresp(kis_capture_handler_t *caph, uint32_t seq, unsigned int success,
        const char *msg, uint32_t dlt, const char *uuid, 
        cf_params_interface_t *interface, cf_params_spectrum_t *spectrum) {

    KismetDatasource__OpenSourceReport keopen;
    KismetDatasource__SubSuccess kesuccess;
    KismetExternal__MsgbusMessage kemsg;
    KismetDatasource__SubChannels kechannels;
    KismetDatasource__SubChanset kechanset;
    KismetDatasource__SubSpecset kespecset;
    KismetDatasource__SubChanhop kechanhop;

    uint8_t *buf;
    size_t buf_len;

    kismet_datasource__open_source_report__init(&keopen);
    kismet_datasource__sub_success__init(&kesuccess);
    kismet_external__msgbus_message__init(&kemsg);
    kismet_datasource__sub_channels__init(&kechannels);
    kismet_datasource__sub_chanset__init(&kechanset);
    kismet_datasource__sub_specset__init(&kespecset);
    kismet_datasource__sub_chanhop__init(&kechanhop);

    /* Always set the success */
    kesuccess.success = success;
    kesuccess.seqno = seq;

    keopen.success = &kesuccess;

    if (interface != NULL) {
        if (interface->chanset != NULL) {
            kechanset.channel = interface->chanset;
            keopen.channel = &kechanset;
        }

        if (interface->channels_len != 0) {
            kechannels.n_channels = interface->channels_len;
            kechannels.channels = interface->channels;
            keopen.channels = &kechannels;
        }

        /* Set the hopping parameters */
        if (caph->hopping_running > 0) {
            /* we don't have to copy the hop list we just use the same pointers */
            kechanhop.channels = caph->channel_hop_list;
            kechanhop.n_channels = caph->channel_hop_list_sz;

            kechanhop.has_rate = true;
            kechanhop.rate = caph->channel_hop_rate;

            kechanhop.has_shuffle = true;
            kechanhop.shuffle = caph->channel_hop_shuffle;

            kechanhop.has_shuffle_skip = true;
            kechanhop.shuffle_skip = caph->channel_hop_shuffle_spacing;

            kechanhop.has_offset = true;
            kechanhop.offset = caph->channel_hop_offset;

            keopen.hop_config = &kechanhop;
        }

        if (interface->hardware != NULL) {
            keopen.hardware = interface->hardware;
        }

        if (spectrum != NULL) {
            kespecset.has_start_mhz = true;
            kespecset.start_mhz = spectrum->start_mhz;

            kespecset.has_end_mhz = true;
            kespecset.end_mhz = spectrum->end_mhz;

            kespecset.has_samples_per_bucket = true;
            kespecset.samples_per_bucket = spectrum->samples_per_freq;

            kespecset.has_bucket_width_hz = true;
            kespecset.bucket_width_hz = spectrum->bin_width;

            kespecset.has_enable_amp = true;
            kespecset.enable_amp = spectrum->amp;

            kespecset.has_if_amp = true;
            kespecset.if_amp = spectrum->if_amp;

            kespecset.has_baseband_amp = true;
            kespecset.baseband_amp = spectrum->baseband_amp;

            keopen.spectrum = &kespecset;
        }

        /* Set the capif if we have it */
        keopen.capture_interface = interface->capif;
    }

    if (msg != NULL && strlen(msg) != 0) {
        kemsg.msgtext = strdup(msg);

        if (success)
            kemsg.msgtype = (KismetExternal__MsgbusMessage__MessageType) MSGFLAG_INFO;
        else
            kemsg.msgtype = (KismetExternal__MsgbusMessage__MessageType) MSGFLAG_ERROR;

        keopen.message = &kemsg;
    }

    /* Always set the dlt */
    keopen.has_dlt = true;
    keopen.dlt = dlt;

    /* Set the UUID? */
    if (uuid != NULL) {
        keopen.uuid = strdup(uuid);
    }

    buf_len = kismet_datasource__open_source_report__get_packed_size(&keopen);
    buf = (uint8_t *) malloc(buf_len);

    if (buf == NULL) {
        if (msg != NULL)
            free(kemsg.msgtext);
        if (uuid != NULL)
            free(keopen.uuid);
        return -1;
    }

    kismet_datasource__open_source_report__pack(&keopen, buf);

    if (msg != NULL)
        free(kemsg.msgtext);
    if (uuid != NULL)
        free(keopen.uuid);

    return cf_send_packet(caph, "KDSOPENSOURCEREPORT", buf, buf_len);
}

int cf_send_data(kis_capture_handler_t *caph,
        KismetExternal__MsgbusMessage *kv_message,
        KismetDatasource__SubSignal *kv_signal,
        KismetDatasource__SubGps *kv_gps,
        struct timeval ts, uint32_t dlt, uint32_t packet_sz, uint8_t *pack) {

    kismet_external_frame_v2_t *frame;
    size_t rs_sz;
    uint8_t *send_buffer;
    size_t buf_len = 0;
    uint32_t seqno;

    KismetDatasource__DataReport kedata;
    KismetDatasource__SubPacket kepkt;
    KismetDatasource__SubGps kegps;

    kismet_datasource__data_report__init(&kedata);
    kismet_datasource__sub_packet__init(&kepkt);
    kismet_datasource__sub_gps__init(&kegps);

    kedata.signal = kv_signal;
    kedata.message = kv_message;

    if (kv_gps != NULL) {
        kedata.gps = kv_gps;
    } else if (caph->gps_fixed_lat != 0) {
        struct timeval tv;

        kegps.lat = caph->gps_fixed_lat;
        kegps.lon = caph->gps_fixed_lon;
        kegps.alt = caph->gps_fixed_alt;
        kegps.fix = 3;

        gettimeofday(&tv, NULL);
        kegps.time_sec = tv.tv_sec;
        kegps.time_usec = tv.tv_usec;

        kegps.type = strdup("remote-fixed");

        if (caph->gps_name != NULL)
            kegps.name = strdup(caph->gps_name);
        else
            kegps.name = strdup("remote-fixed");

        kedata.gps = &kegps;
    }

    if (packet_sz > 0 && pack != NULL) {
        kepkt.time_sec = ts.tv_sec;
        kepkt.time_usec = ts.tv_usec;
        kepkt.dlt = dlt;
        kepkt.size = packet_sz;
        kepkt.data.len = packet_sz;
        kepkt.data.data = pack;

        kedata.packet = &kepkt;
    }

    if (caph->use_tcp || caph->use_ipc) {
        /* Shortcut internal state tests to use an optimized streaming method to write to 
         * the tcp/ipc ringbuffer using a protobuf_c buffer writer.
         * This is a bunch of code duplication but it's important enough that we get the
         * maximum speed here */

        /* Lock the handler and get the next sequence number */
        pthread_mutex_lock(&(caph->handler_lock));
        if (++caph->seqno == 0)
            caph->seqno = 1;
        seqno = caph->seqno;
        pthread_mutex_unlock(&(caph->handler_lock));

        /* Reserve the buffer space and assemble the packet header just like cf_rb_send_packet */
        pthread_mutex_lock(&(caph->out_ringbuf_lock));

        buf_len = kismet_datasource__data_report__get_packed_size(&kedata);

        rs_sz = kis_simple_ringbuf_reserve(caph->out_ringbuf, (void **) &send_buffer, 
                buf_len + sizeof(kismet_external_frame_v2_t));

        if (rs_sz != buf_len + sizeof(kismet_external_frame_v2_t)) {
            // fprintf(stderr, "DEBUG - insufficient size in outgoing buffer for %lu\n", buf_len);
            pthread_mutex_unlock(&(caph->out_ringbuf_lock));
            return 0;
        }

        /* Map to the tx frame */
        frame = (kismet_external_frame_v2_t *) send_buffer;

        /* Set the signature and data size */
        frame->signature = htonl(KIS_EXTERNAL_PROTO_SIG);
        frame->data_sz = htonl(buf_len);

        frame->v2_sentinel = htons(KIS_EXTERNAL_V2_SIG);
        frame->frame_version = htons(2);

        frame->seqno = htonl(seqno);

        strncpy(frame->command, "KDSDATAREPORT", 32);

        kismet_datasource__data_report__pack(&kedata, frame->data);

        kis_simple_ringbuf_commit(caph->out_ringbuf, send_buffer, rs_sz);

        pthread_mutex_unlock(&(caph->out_ringbuf_lock));

        if (kegps.name != NULL)
            free(kegps.name);
        if (kegps.type != NULL)
            free(kegps.type);

        return rs_sz;
    }  else {
        /* Otherwise we need to use our legacy mode of serializing the packet into a temp
         * buffer then putting that into the websocket ring */
        uint8_t *buf;
        size_t buf_len;

        buf_len = kismet_datasource__data_report__get_packed_size(&kedata);
        buf = (uint8_t *) malloc(buf_len);

        if (buf == NULL) {
            return -1;
        }

        kismet_datasource__data_report__pack(&kedata, buf);

        if (kegps.name != NULL)
            free(kegps.name);
        if (kegps.type != NULL)
            free(kegps.type);

        return cf_send_packet(caph, "KDSDATAREPORT", buf, buf_len);
    }
}


int cf_send_json(kis_capture_handler_t *caph,
        KismetExternal__MsgbusMessage *kv_message,
        KismetDatasource__SubSignal *kv_signal,
        KismetDatasource__SubGps *kv_gps,
        struct timeval ts, char *type, char *json) {

    KismetDatasource__DataReport kedata;
    KismetDatasource__SubJson kejson;
    KismetDatasource__SubGps kegps;

    kismet_datasource__data_report__init(&kedata);
    kismet_datasource__sub_json__init(&kejson);
    kismet_datasource__sub_gps__init(&kegps);

    kedata.signal = kv_signal;
    kedata.message = kv_message;

    if (kv_gps != NULL) {
        kedata.gps = kv_gps;
    } else if (caph->gps_fixed_lat != 0) {
        struct timeval tv;

        kegps.lat = caph->gps_fixed_lat;
        kegps.lon = caph->gps_fixed_lon;
        kegps.alt = caph->gps_fixed_alt;
        kegps.fix = 3;

        gettimeofday(&tv, NULL);
        kegps.time_sec = tv.tv_sec;
        kegps.time_usec = tv.tv_usec;

        kegps.type = strdup("remote-fixed");

        if (caph->gps_name != NULL)
            kegps.name = strdup(caph->gps_name);
        else
            kegps.name = strdup("remote-fixed");

        kedata.gps = &kegps;
    }

    if (type != NULL && json  != NULL) {
        kejson.time_sec = ts.tv_sec;
        kejson.time_usec = ts.tv_usec;
        kejson.type = type;
        kejson.json = json;

        kedata.json = &kejson;
    }

    uint8_t *buf;
    size_t buf_len;

    buf_len = kismet_datasource__data_report__get_packed_size(&kedata);
    buf = (uint8_t *) malloc(buf_len);

    if (buf == NULL) {
        return -1;
    }

    kismet_datasource__data_report__pack(&kedata, buf);

    if (kegps.name != NULL)
        free(kegps.name);
    if (kegps.type != NULL)
        free(kegps.type);

    return cf_send_packet(caph, "KDSDATAREPORT", buf, buf_len);
}


int cf_send_configresp(kis_capture_handler_t *caph, unsigned int seqno, 
        unsigned int success, const char *msg, const char *warning) {

    KismetDatasource__ConfigureReport keconf;
    KismetDatasource__SubSuccess kesuccess;
    KismetExternal__MsgbusMessage kemsg;
    KismetDatasource__SubChanset kechanset;
    KismetDatasource__SubChanhop kechanhop;

    uint8_t *buf;
    size_t buf_len;
    

    kismet_datasource__configure_report__init(&keconf);
    kismet_datasource__sub_success__init(&kesuccess);
    kismet_external__msgbus_message__init(&kemsg);
    kismet_datasource__sub_chanset__init(&kechanset);
    kismet_datasource__sub_chanhop__init(&kechanhop);

    /* Always set the success */
    kesuccess.success = success;
    kesuccess.seqno = seqno;

    keconf.success = &kesuccess;

    if (msg != NULL && strlen(msg) != 0) {
        kemsg.msgtext = strdup(msg);

        if (success)
            kemsg.msgtype = (KismetExternal__MsgbusMessage__MessageType) MSGFLAG_INFO;
        else
            kemsg.msgtype = (KismetExternal__MsgbusMessage__MessageType) MSGFLAG_ERROR;

        keconf.message = &kemsg;
    }

    /* If we're not hopping, set the single channel response */
    if (!caph->hopping_running && caph->channel != NULL) {
        /* Set the single channel */
        kechanset.channel = caph->channel;
        keconf.channel = &kechanset;
    }

    /* Set the hopping parameters */
    /* we don't have to copy the hop list we just use the same pointers */
    kechanhop.channels = caph->channel_hop_list;
    kechanhop.n_channels = caph->channel_hop_list_sz;

    kechanhop.has_rate = true;
    kechanhop.rate = caph->channel_hop_rate;

    kechanhop.has_shuffle = true;
    kechanhop.shuffle = caph->channel_hop_shuffle;

    kechanhop.has_shuffle_skip = true;
    kechanhop.shuffle_skip = caph->channel_hop_shuffle_spacing;

    kechanhop.has_offset = true;
    kechanhop.offset = caph->channel_hop_offset;

    keconf.hopping = &kechanhop;

    buf_len = kismet_datasource__configure_report__get_packed_size(&keconf);
    buf = (uint8_t *) malloc(buf_len);

    if (buf == NULL) {
        if (msg)
            free(kemsg.msgtext);
        return -1;
    }

    kismet_datasource__configure_report__pack(&keconf, buf);

    if (msg)
        free(kemsg.msgtext);

    return cf_send_packet(caph, "KDSCONFIGUREREPORT", buf, buf_len);
}

int cf_send_newsource(kis_capture_handler_t *caph, const char *uuid) {
    KismetDatasource__NewSource kesrc;

    uint8_t *buf;
    size_t buf_len;
    

    kismet_datasource__new_source__init(&kesrc);

    kesrc.definition = caph->cli_sourcedef;
    kesrc.sourcetype = caph->capsource_type;
    if (uuid != NULL)
        kesrc.uuid = strdup(uuid);

    buf_len = kismet_datasource__new_source__get_packed_size(&kesrc);
    buf = (uint8_t *) malloc(buf_len);

    if (buf == NULL) {
        if (uuid != NULL)
            free(kesrc.uuid);
        return -1;
    }

    kismet_datasource__new_source__pack(&kesrc, buf);

    if (uuid != NULL)
        free(kesrc.uuid);

    return cf_send_packet(caph, "KDSNEWSOURCE", buf, buf_len);
}

int cf_send_pong(kis_capture_handler_t *caph, uint32_t in_seqno) {
    KismetExternal__Pong pong;

    uint8_t *buf;
    size_t buf_len;
    

    kismet_external__pong__init(&pong);
    pong.ping_seqno = in_seqno;

    buf_len = kismet_external__pong__get_packed_size(&pong);
    buf = (uint8_t *) malloc(buf_len);

    kismet_external__pong__pack(&pong, buf);

    return cf_send_packet(caph, "PONG", buf, buf_len);
}

double cf_parse_frequency(const char *freq) {
    char *ufreq;
    unsigned int i;
    double v = 0;

    if (freq == NULL)
        return 0;

    if (strlen(freq) == 0)
        return 0;

    /* Make a buffer at least as big as the total string to hold the frequency component */
    ufreq = (char *) malloc(strlen(freq) + 1);

    /* sscanf w/ unbounded string component is still 'safe' here because ufreq is the length
     * of the entire field, so must be able to fit any sub-component of the field.  */
    i = sscanf(freq, "%lf%s", &v, ufreq);

    if (i == 1 || strlen(ufreq) == 0) {
        /* Did we parse a single number or a scientific notation? */
        /* Assume it's in hz */
        v = v / 1000;
    } else if (i == 2) {
        /* hz */
        if (ufreq[0] == 'h' || ufreq[0] == 'H') {
            v = v / 1000;
        } else if (ufreq[0] == 'm' || ufreq[0] == 'M') {
            v = v * 1000;
        } else if (ufreq[0] == 'g' || ufreq[0] == 'G') {
            v = v * 1000 * 1000;
        }
    }

    free(ufreq);
    return v;
}

int cf_drop_most_caps(kis_capture_handler_t *caph) {
    /* Modeled on the Wireshark Dumpcap priv dropping
     *
     * Restricts the capabilities of the process to only NET_ADMIN and NET_RAW and
     * strips capabilities for anything else; almost all capture sources which run as 
     * root will need these, but shouldn't have free reign of the system.
     *
     */

    /* Can't drop caps unless running as root so don't try */
    if (getuid() != 0)
        return 0;

#ifdef HAVE_CAPABILITY
    char errstr[STATUS_MAX];
	cap_value_t cap_list[2] = { CAP_NET_ADMIN, CAP_NET_RAW };
	int cl_len = sizeof(cap_list) / sizeof(cap_value_t);
	cap_t caps = cap_init(); 

	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1) {
        snprintf(errstr, STATUS_MAX, "datasource failed to set keepcaps in prctl: %s",
                strerror(errno));
        cf_send_warning(caph, errstr);
        cap_free(caps);
        return -1;
	}

	cap_set_flag(caps, CAP_PERMITTED, cl_len, cap_list, CAP_SET);
	cap_set_flag(caps, CAP_INHERITABLE, cl_len, cap_list, CAP_SET);

	if (cap_set_proc(caps)) {
        snprintf(errstr, STATUS_MAX, "datasource failed to set future process "
                "capabilities: %s", strerror(errno));
        cf_send_warning(caph, errstr);
        cap_free(caps);
        return -1;
	}

	cap_set_flag(caps, CAP_EFFECTIVE, cl_len, cap_list, CAP_SET);
	if (cap_set_proc(caps)) {
        snprintf(errstr, STATUS_MAX, "datasource failed to set effective capabilities: %s",
                strerror(errno));
        cf_send_warning(caph, errstr);
        cap_free(caps);
        return -1;
    }

	cap_free(caps);

    return 1;
#else
    /*
    snprintf(errstr, STATUS_MAX, "datasource not compiled with libcap capabilities control");
    cf_send_warning(caph, errstr);
    */
    return 0;
#endif
}

int cf_jail_filesystem(kis_capture_handler_t *caph) {
    /* for now don't jail fs because we need it for flock'ing, revisit this */
    return 0;

#ifdef SYS_LINUX
    char errstr[STATUS_MAX];

    /* Can't jail filesystem if not running as root */
    if (getuid() != 0)
        return 0;

    /* Eject ourselves from the namespace into a new temporary one */
    if (unshare(CLONE_NEWNS) < 0) {
        /* Only send warning if we're running as root */
        if (getuid() == 0) {
            snprintf(errstr, STATUS_MAX, "datasource failed to jail to new namespace: %s",
                    strerror(errno));
            cf_send_warning(caph, errstr);
            return -1;
        }

        return 0;
    }

    /* Remount / as a read-only bind-mount of itself over our rootfs */
    if (mount("/", "/", "bind", MS_BIND | MS_REMOUNT | MS_PRIVATE | 
                MS_REC | MS_RDONLY, NULL) < 0) {
        /* Only send warning if we're running as root */
        if (getuid() == 0) {
            snprintf(errstr, STATUS_MAX, "datasource failed to remount root in jail as RO: %s",
                    strerror(errno));
            cf_send_warning(caph, errstr);
            return -1;
        }

        return 0;
    }

    return 1;
#else
    /*
    snprintf(errstr, STATUS_MAX, "datasource framework can only jail namespaces on Linux");
    cf_send_warning(caph, errstr);
    */
    return 0;
#endif
}

void cf_handler_remote_capture(kis_capture_handler_t *caph) {
    int status;

    /* If we're going into daemon mode, fork-exec and drop out here */
    if (caph->daemonize) {
        int pid = fork();

        if (pid < 0) {
            fprintf(stderr, "FATAL:  Unable to fork child process: %s\n", strerror(errno));
            cf_handler_free(caph);
            exit(KIS_EXTERNAL_RETCODE_FORK);
        } else if (pid > 0) {
            fprintf(stderr, "INFO: Entering daemon mode...\n");
            cf_handler_free(caph);
            exit(0);
        }
    }

    /* Don't enter remote loop at all if we're not doing a remote connection */
    if (caph->use_ipc) {
        return;
    }

    while (1) {
        caph->spindown = 0;
        caph->shutdown = 0;

        if (caph->remote_retry && ((caph->monitor_pid = fork()) > 0)) {
            while (1) {
                /* Parent loop waiting for spaned process to exit, then restart */
                pid_t wpid;
                wpid = waitpid(caph->monitor_pid, &status, 0);

                if (wpid == caph->monitor_pid) {
                    if (WIFEXITED(status) || WIFSIGNALED(status)) {
                        fprintf(stderr, "INFO: capture process exited %d signal %d\n", 
                                WEXITSTATUS(status), WTERMSIG(status));
                        break;
                    }
                }
            } 
        } else {
            if (caph->use_tcp) {
                if (cf_handler_tcp_remote_connect(caph) < 1) {
                    exit(KIS_EXTERNAL_RETCODE_TCP);
                }
            } else {
#ifdef HAVE_LIBWEBSOCKETS
                /* Prepare the libwebsockets ssl and context, but let the main connection callback 
                 * via the main lws_service loop */

                memset(&caph->lwsinfo, 0, sizeof(struct lws_context_creation_info));

                caph->lwsinfo.user = caph;

                if (caph->lwsusessl)
                    caph->lwsinfo.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

                if (caph->lwssslcapath != NULL)
                    caph->lwsinfo.client_ssl_ca_filepath = caph->lwssslcapath;

                caph->lwsinfo.port = CONTEXT_PORT_NO_LISTEN;
                caph->lwsinfo.protocols = kismet_lws_protocols;

                /* Should only need to be 2 but lets be safe for now */
                caph->lwsinfo.fd_limit_per_thread = 10;

                caph->lwscontext = lws_create_context(&caph->lwsinfo);
                if (!caph->lwscontext) {
                    fprintf(stderr, "FATAL:  Could not create websockets context\n");
                    exit(KIS_EXTERNAL_RETCODE_WEBSOCKET);
                }

#else
                fprintf(stderr, "FATAL:  Not compiled with websocket support\n");
                exit(KIS_EXTERNAL_RETCODE_WSCOMPILE);
#endif
            }

            /* Exit so main loop continues */
            return;
        }

        /* Don't keep going if we're not retrying */
        if (caph->remote_retry == 0) {
            exit(1);
        }

        fprintf(stderr, "INFO: Sleeping 5 seconds before attempting to reconnect to "
                "remote server\n");
        sleep(5);

    }
}

void cf_set_verbose(kis_capture_handler_t *caph, int verbosity) {
    caph->verbose = verbosity;
}

int cf_wait_announcement(kis_capture_handler_t *caph) {
    struct sockaddr_in lsin;
    int sock;

	int r;
	struct msghdr rcv_msg;
	struct iovec iov;
	kismet_remote_announce announcement;
	struct sockaddr_in recv_addr;

    char *name;

    memset(&lsin, 0, sizeof(struct sockaddr_in));
    lsin.sin_family = AF_INET;
    lsin.sin_port = htons(2501);
    lsin.sin_addr.s_addr = INADDR_ANY;

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        fprintf(stderr, "ERROR:  Could not create listening socket for announcements: %s\n",
                strerror(errno));
		return -1;
    }

    if (bind(sock, (struct sockaddr *) &lsin, sizeof(lsin)) < 0) {
        fprintf(stderr, "ERROR:  Could not bind to listening socket for announcements: %s\n",
                strerror(errno));
        close(sock);
		return -1;
    }

    fprintf(stderr, "INFO: Listening for Kismet server announcements...\n");

    while(1) {
        iov.iov_base = &announcement;
        iov.iov_len = sizeof(kismet_remote_announce);

        rcv_msg.msg_name = &recv_addr;
        rcv_msg.msg_namelen = sizeof(recv_addr);
        rcv_msg.msg_iov = &iov;
        rcv_msg.msg_iovlen = 1;
        rcv_msg.msg_control = NULL;
        rcv_msg.msg_controllen = 0;

        if ((r = recvmsg(sock, &rcv_msg, 0) < 0)) {
            fprintf(stderr, "ERROR:  Failed receiving announcement: %s\n", strerror(errno));
            close(sock);
			return -1;
        }

        if (be64toh(announcement.tag) != REMOTE_ANNOUNCE_TAG)
            fprintf(stderr, "WARNING:  Corrupt/invalid announcement seen, ignoring.\n");

        if (caph->announced_uuid != NULL)
            if (strncmp(caph->announced_uuid, announcement.uuid, 36) != 0) 
                continue;

        caph->remote_host = strdup(inet_ntoa(recv_addr.sin_addr));
        caph->remote_port = ntohl(announcement.remote_port);

        name = strndup(announcement.name, 32);

        fprintf(stderr, "INFO:  Detected Kismet server %s:%u %.36s (%s)\n",
                caph->remote_host, caph->remote_port,
                announcement.uuid, strlen(name) > 0 ? name : "no name");

        free(name);

        close(sock);

        return 1;
    }

}

int cf_ipc_find_exec(kis_capture_handler_t *caph, char *program) {
    char *PATH = strdup(getenv("PATH"));
    char *orig = PATH;
    char *token;
    char binpath[512];
    struct stat sb;

    while ((token = strsep(&PATH, ":")) != NULL) {
        snprintf(binpath, 512, "%s/%s", token, program);
        stat(binpath, &sb);

        if (sb.st_mode & S_IXUSR) {
            return 1;
            break;
        }
    }

    free(orig);

    return 0;
}

cf_ipc_t *cf_ipc_exec(kis_capture_handler_t *caph, int argc, char **argv) { 
    cf_ipc_t *ret = NULL;
    pthread_mutexattr_t mutexattr;

    int inpair[2];
    int outpair[2];
    int errpair[2];

    if (pipe(inpair) < 0) {
        return NULL;
    }

    if (pipe(outpair) < 0) {
        close(inpair[0]);
        close(inpair[1]);
        return NULL;
    }

    if (pipe(errpair) < 0) {
        close(inpair[0]);
        close(inpair[1]);
        close(outpair[0]);
        close(outpair[1]);
        return NULL;
    }

    caph->child_pid = fork();

    if (caph->child_pid < 0) {
        fprintf(stderr, "FATAL: Failed to fork IPC process\n");
        close(inpair[0]);
        close(inpair[1]);
        close(outpair[0]);
        close(outpair[1]);
        close(errpair[0]);
        close(errpair[1]);
        return NULL;
    } else if (caph->child_pid == 0) {
        sigset_t unblock_mask;
        sigfillset(&unblock_mask);
        pthread_sigmask(SIG_UNBLOCK, &unblock_mask, NULL);

        dup2(inpair[0], STDIN_FILENO);
        close(inpair[0]);
        close(inpair[1]);

        dup2(outpair[1], STDOUT_FILENO);
        close(outpair[1]);
        close(outpair[0]);

        dup2(errpair[1], STDERR_FILENO);
        close(errpair[1]);
        close(errpair[0]);

        execvp(argv[0], argv);

        return NULL;
    } else {
        close(inpair[0]);
        close(errpair[1]);
        close(outpair[1]);

        ret = (cf_ipc_t *) malloc(sizeof(cf_ipc_t));
        memset(ret, 0, sizeof(cf_ipc_t));

        ret->running = 1;

        ret->in_fd = inpair[1];
        ret->out_fd = outpair[0];
        ret->err_fd = errpair[0];

        ret->pid = caph->child_pid;

        fcntl(ret->in_fd, F_SETFL, fcntl(ret->in_fd, F_GETFL, 0) | O_NONBLOCK);
        fcntl(ret->out_fd, F_SETFL, fcntl(ret->out_fd, F_GETFL, 0) | O_NONBLOCK);
        fcntl(ret->err_fd, F_SETFL, fcntl(ret->err_fd, F_GETFL, 0) | O_NONBLOCK);

        pthread_mutexattr_init(&mutexattr);
        pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&(ret->out_ringbuf_lock), &mutexattr);

        /* Ungracefully die if we're out of memory */
        ret->in_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_IN_SZ);
        if (ret->in_ringbuf == NULL) {
            fprintf(stderr, "FATAL:  Cannot allocate process ringbuffer (in)\n");
            exit(1);
        }

        /* Ungracefully die if we're out of memory */
        ret->out_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_OUT_SZ);
        if (ret->out_ringbuf == NULL) {
            fprintf(stderr, "FATAL:  Cannot allocate process ringbuffer (out)\n");
            exit(1);
        }

        /* Ungracefully die if we're out of memory */
        ret->err_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_OUT_SZ);
        if (ret->err_ringbuf == NULL) {
            fprintf(stderr, "FATAL:  Cannot allocate process ringbuffer (err)\n");
            exit(1);
        }

        return ret;
    }
}

void cf_ipc_free(kis_capture_handler_t *caph, cf_ipc_t *ipc) {
    kis_simple_ringbuf_free(ipc->in_ringbuf);

    pthread_mutex_lock(&ipc->out_ringbuf_lock);
    kis_simple_ringbuf_free(ipc->out_ringbuf);
    kis_simple_ringbuf_free(ipc->err_ringbuf);
    pthread_mutex_unlock(&ipc->out_ringbuf_lock);

    pthread_mutex_destroy(&ipc->out_ringbuf_lock);

    if (ipc->in_fd >= 0)
        close(ipc->in_fd);
    if (ipc->out_fd >= 0)
        close(ipc->out_fd);
    if (ipc->err_fd >= 0)
        close(ipc->err_fd);

    free(ipc);
}

void cf_ipc_signal(kis_capture_handler_t *caph, cf_ipc_t *ipc, int signal) { 
    kill(ipc->pid, signal);
}

void cf_ipc_set_rx(kis_capture_handler_t *caph, cf_ipc_t *ipc, cf_callback_ipc_data cb) { 
    ipc->rx_callback = cb;
}

void cf_ipc_set_err_rx(kis_capture_handler_t *caph, cf_ipc_t *ipc, cf_callback_ipc_data cb) {
    ipc->err_callback = cb;
}

void cf_ipc_set_term(kis_capture_handler_t *caph, cf_ipc_t *ipc, cf_callback_ipc_term cb) { 
    ipc->term_callback = cb;
}

void cf_ipc_add_process(kis_capture_handler_t *caph, cf_ipc_t *ipc) { 
    pthread_mutex_lock(&(caph->handler_lock));

    cf_ipc_t *first = caph->ipc_list;

    ipc->next = first; 
    caph->ipc_list = ipc;

    pthread_mutex_unlock(&(caph->handler_lock));
}

void cf_ipc_remove_process(kis_capture_handler_t *caph, cf_ipc_t *ipc) {
    pthread_mutex_lock(&(caph->handler_lock));

    cf_ipc_t *current = caph->ipc_list;
    cf_ipc_t *prev = NULL;
    int matched = 0;

    while (current != NULL) {
        if (current->pid == ipc->pid) {
            matched = 1;
            break;
        }

        prev = current;
        current = current->next;
    }

    if (matched) {
        if (prev == NULL) { 
            caph->ipc_list = current->next;
        } else { 
            prev->next = current->next;
        }
    }

    pthread_mutex_unlock(&(caph->handler_lock));
}

