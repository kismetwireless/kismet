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

#include <string.h>

#include "config.h"

#include "msgpuck.h"
#include "capture_framework.h"

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
    char *colonpos;
    char *flagpos;
    char *comma;
    char *equals;

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
        if (strncasecmp(flag, flagpos, (equals - flagpos)) == 0) {
            /* Find the next comma */
            comma = strstr(equals, ",");

            /* If it's null we're the last flag, so use the total length after
             * the equals as the value */
            if (comma == NULL) {
                *ret_value = equals + 1;
                return strlen(equals) - 1;
            }

            /* Otherwise return until the equals */
            *ret_value = equals + 1;
            return (comma - (equals + 1));
        }

        /* Otherwise find the next comma and advance */
        comma = strstr(flagpos, ",");

        /* No comma, no more flags, nothing to find */
        if (comma == NULL) {
            *ret_value = NULL;
            return 0;
        }

        flagpos = comma + 1;
    }

    *ret_value = NULL;
    return 0;
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

    printf("got %lu fields\n", num_fields);

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

kis_capture_handler_t *cf_handler_init() {
    kis_capture_handler_t *ch;
    pthread_mutexattr_t mutexattr;

    ch = (kis_capture_handler_t *) malloc(sizeof(kis_capture_handler_t));

    if (ch == NULL)
        return NULL;

    ch->last_ping = time(NULL);

    ch->remote_host = NULL;

    ch->in_fd = -1;
    ch->out_fd = -1;
    ch->tcp_fd = -1;

    /* Allocate a smaller incoming ringbuffer since most of our traffic is
     * on the outgoing channel */
    ch->in_ringbuf = kis_simple_ringbuf_create(1024 * 16);

    if (ch->in_ringbuf == NULL) {
        free(ch);
        return NULL;
    }

    /* Allocate a much more generous outbound buffer since this is where 
     * packets get queued */
    ch->out_ringbuf = kis_simple_ringbuf_create(1024 * 256);

    if (ch->out_ringbuf == NULL) {
        kis_simple_ringbuf_free(ch->in_ringbuf);
        free(ch);
        return NULL;
    }

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

    ch->userdata = NULL;

    ch->capture_running = 0;
    ch->hopping_running = 0;

    ch->channel_hop_list = NULL;
    ch->custom_channel_hop_list = NULL;
    ch->channel_hop_list_sz = 0;
    ch->channel_hop_shuffle = 0;
    ch->channel_hop_shuffle_spacing = 1;

    return ch;
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

    pthread_mutex_destroy(&(caph->out_ringbuf_lock));
    pthread_mutex_destroy(&(caph->handler_lock));
}

void cf_handler_shutdown(kis_capture_handler_t *caph) {
    if (caph == NULL)
        return;

    pthread_mutex_lock(&(caph->handler_lock));
    caph->shutdown = 1;

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
        void **privchans, size_t chan_sz, double rate, int shuffle, int offset) {
    size_t szi;

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

    caph->channel_hop_list = stringchans;
    caph->custom_channel_hop_list = privchans;
    caph->channel_hop_list_sz = chan_sz;
    caph->channel_hop_rate = rate;

    caph->channel_hop_shuffle = shuffle;
    caph->channel_hop_offset = offset;

    if (caph->channel_hop_shuffle && caph->channel_hop_shuffle_spacing && chan_sz != 0) {
        /* To find a proper randomization number, take the length of the channel
         * list, divide by the preferred skipping distance.
         *
         * We then need to find the closest number to the skipping distance that
         * is not a factor of the maximum so that we get full coverage.
         */
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

int cf_handler_parse_opts(kis_capture_handler_t *caph, int argc, char *argv[]) {
    int option_idx;

    optind = 0;
    opterr = 0;
    option_idx = 0;

    static struct option longopt[] = {
        { "in-fd", required_argument, 0, 1 },
        { "out-fd", required_argument, 0, 2 },
        { "connect", required_argument, 0, 3 },
        { 0, 0, 0, 0 }
    };

    while (1) {
        int r = getopt_long(argc, argv, "-", longopt, &option_idx);

        if (r < 0)
            break;

        if (r == 1) {
            if (sscanf(optarg, "%d", &(caph->in_fd)) != 1) {
                fprintf(stderr, "FATAL: Unable to parse incoming file descriptor\n");
                return -1;
            }
        } else if (r == 2) {
            if (sscanf(optarg, "%d", &(caph->out_fd)) != 1) {
                fprintf(stderr, "FATAL: Unable to parse outgoing file descriptor\n");
                return -1;
            }
        } else if (r == 3) {
            caph->remote_host = strdup(optarg);
        }
    }

    if (caph->remote_host != NULL)
        return 2;

    if (caph->in_fd == -1 || caph->out_fd == -1)
        return -1;

    return 1;

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

    cf_send_error(caph, "capture thread ended, source is closed.");
    
    cf_handler_spindown(caph);

    return NULL;
}

/* Launch a capture thread after opening has been successful */
int cf_handler_launch_capture_thread(kis_capture_handler_t *caph) {
    /* Set the thread attributes - detatched, cancelable */
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_mutex_lock(&(caph->handler_lock));
    if (caph->capture_running) {
        pthread_mutex_unlock(&(caph->handler_lock));
        return 0;
    }

    if (pthread_create(&(caph->capturethread), &attr, 
                cf_int_capture_thread, caph) < 0) {
        /* fprintf(stderr, "debug - failed to pthread_create %s\n", strerror(errno)); */
        cf_send_error(caph, "failed to launch capture thread");
        cf_handler_spindown(caph);
        return -1;
    }

    caph->capture_running = 1;

    pthread_mutex_unlock(&(caph->handler_lock));
    
    /* fprintf(stderr, "debug - capture thread launched\n"); */

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

    /* Where we are in the hopping vec */
    pthread_mutex_lock(&(caph->handler_lock));
    size_t hoppos = caph->channel_hop_offset;
    pthread_mutex_unlock(&(caph->handler_lock));

    /* How long we're waiting until the next time */
    unsigned int wait_sec = 0;
    unsigned int wait_usec = 0;

    char errstr[STATUS_MAX];

    while (1) {
        pthread_mutex_lock(&(caph->handler_lock));

        /* Cancel thread if we're no longer hopping */
        if (caph->channel_hop_rate == 0) {
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
        if ((caph->chancontrol_cb)(caph, 0, 
                    caph->custom_channel_hop_list[hoppos % caph->channel_hop_list_sz], 
                    errstr) < 0) {
            cf_send_error(caph, errstr);
            caph->hopping_running = 0;
            pthread_mutex_unlock(&caph->handler_lock);
            cf_handler_spindown(caph);
            return NULL;
        }

        /* Increment by the shuffle amount */
        if (caph->channel_hop_shuffle)
            hoppos += caph->channel_hop_shuffle_spacing;
        else
            hoppos++;

        pthread_mutex_unlock(&caph->handler_lock);

    }

    return NULL;
}

int cf_handler_launch_hopping_thread(kis_capture_handler_t *caph) {
    /* Set the thread attributes - detatched, cancelable */
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_mutex_lock(&(caph->handler_lock));
    if (caph->hopping_running) {
        pthread_cancel(caph->hopthread);
        caph->hopping_running = 0;
    }

    if (pthread_create(&(caph->hopthread), &attr, cf_int_chanhop_thread, caph) < 0) {
        cf_send_error(caph, "failed to launch channel hopping thread");
        cf_handler_spindown(caph);
        return -1;
    }

    caph->hopping_running = 1;

    pthread_mutex_unlock(&(caph->handler_lock));
    
    return 1;
}

int cf_handle_rx_data(kis_capture_handler_t *caph) {
    size_t rb_available;

    simple_cap_proto_frame_t *cap_proto_frame;

    /* Buffer of just the packet header */
    uint8_t hdr_buf[sizeof(simple_cap_proto_t)];

    /* Buffer of entire frame, dynamic */
    uint8_t *frame_buf;

    /* Incoming size */
    uint32_t packet_sz;

    /* Callback ret */
    int cbret = -1;

    /* Status buffer */
    char msgstr[STATUS_MAX];

    size_t i;

    rb_available = kis_simple_ringbuf_used(caph->in_ringbuf);

    if (rb_available < sizeof(simple_cap_proto_t)) {
        /* fprintf(stderr, "DEBUG - insufficient data to represent a frame\n"); */
        return 0;
    }

    if (kis_simple_ringbuf_peek(caph->in_ringbuf, hdr_buf, 
                sizeof(simple_cap_proto_t)) != sizeof(simple_cap_proto_t)) {
        return 0;
    }

    cap_proto_frame = (simple_cap_proto_frame_t *) hdr_buf;

    /* Check the signature */
    if (ntohl(cap_proto_frame->header.signature) != KIS_CAP_SIMPLE_PROTO_SIG) {
        fprintf(stderr, "FATAL: Invalid frame header received\n");
        return -1;
    }

    /* Check the header checksum */
    if (!validate_simple_cap_proto_header(&(cap_proto_frame->header))) {
        fprintf(stderr, "DEBUG: Invalid checksum on frame header\n");
        return -1;
    }

    /* If the signature passes, see if we can read the whole frame */
    packet_sz = ntohl(cap_proto_frame->header.packet_sz);

    if (rb_available < packet_sz) {
        fprintf(stderr, "DEBUG: Waiting additional data (%lu available, "
                "%u needed\n", rb_available, packet_sz);
        return 0;
    }

    /* We've got enough to read it all; allocate the buffer and read it in */
    frame_buf = (uint8_t *) malloc(packet_sz);

    if (frame_buf == NULL) {
        fprintf(stderr, "FATAL:  Could not allocate read buffer\n");
        return -1;
    }

    /* Peek our ring buffer */
    if (kis_simple_ringbuf_peek(caph->in_ringbuf, frame_buf, packet_sz) != packet_sz) {
        fprintf(stderr, "FATAL: Failed to read packet from ringbuf\n");
        free(frame_buf);
        return -1;
    }

    /* Clear it out from the buffer */
    kis_simple_ringbuf_read(caph->in_ringbuf, NULL, packet_sz);

    cap_proto_frame = (simple_cap_proto_frame_t *) frame_buf;

    /* Validate it */
    if (!validate_simple_cap_proto(&(cap_proto_frame->header))) {
        fprintf(stderr, "FATAL:  Invalid control frame\n");
        free(frame_buf);
        return -1;
    }

    /* Lock so we can look at callbacks */
    pthread_mutex_lock(&(caph->handler_lock));

    if (strncasecmp(cap_proto_frame->header.type, "LISTINTERFACES", 16) == 0) {
        if (caph->listdevices_cb == NULL) {
            pthread_mutex_unlock(&(caph->handler_lock));
            cf_send_listresp(caph, ntohl(cap_proto_frame->header.sequence_number),
                    true, "", NULL, NULL, 0);
            cbret = -1;
        } else {
            char **interfaces = NULL;
            char **flags = NULL;

            msgstr[0] = 0;
            cbret = (*(caph->listdevices_cb))(caph, 
                    ntohl(cap_proto_frame->header.sequence_number),
                    msgstr, &interfaces, &flags);

            cf_send_listresp(caph, ntohl(cap_proto_frame->header.sequence_number),
                    cbret >= 0, msgstr, interfaces, flags, cbret < 0 ? 0 : cbret);

            if (cbret > 0) {
                for (i = 0; i < (size_t) cbret; i++) {
                    if (interfaces[i] != NULL)
                        free(interfaces[i]);
                    if (flags[i] != NULL)
                        free(flags[i]);
                }

                free(interfaces);
                free(flags);
            }

            /* Always spin down after listing */
            cf_handler_spindown(caph);

            pthread_mutex_unlock(&(caph->handler_lock));
        }
    } else if (strncasecmp(cap_proto_frame->header.type, "PROBEDEVICE", 16) == 0) {
        /* fprintf(stderr, "DEBUG - Got PROBEDEVICE request\n"); */

        if (caph->probe_cb == NULL) {
            pthread_mutex_unlock(&(caph->handler_lock));
            cf_send_proberesp(caph, ntohl(cap_proto_frame->header.sequence_number),
                    false, "We don't support probing", NULL, NULL, 0);
            cbret = -1;
        } else {
            char *def, *nuldef = NULL;
            int def_len;

            char **channels = NULL;
            size_t channels_sz = 0;
            char *chanset = NULL;
            
            def_len = cf_get_DEFINITION(&def, cap_proto_frame);

            if (def_len > 0) {
                nuldef = strndup(def, def_len);
            }

            msgstr[0] = 0;
            cbret = (*(caph->probe_cb))(caph,
                    ntohl(cap_proto_frame->header.sequence_number), nuldef,
                    msgstr, &chanset, &channels, &channels_sz);

            cf_send_proberesp(caph, ntohl(cap_proto_frame->header.sequence_number),
                    cbret < 0 ? 0 : cbret, msgstr, chanset, channels, channels_sz);

            if (nuldef != NULL)
                free(nuldef);

            for (i = 0; i < channels_sz; i++) {
                free(channels[i]);
            }

            if (channels != NULL)
                free(channels);

            if (chanset != NULL)
                free(chanset);

            /* Always spin down after probing */
            cf_handler_spindown(caph);

            pthread_mutex_unlock(&(caph->handler_lock));
        }
    } else if (strncasecmp(cap_proto_frame->header.type, "OPENDEVICE", 16) == 0) {
        /* fprintf(stderr, "DEBUG - Got OPENDEVICE request\n"); */

        if (caph->open_cb == NULL) {
            pthread_mutex_unlock(&(caph->handler_lock));
            cf_send_openresp(caph, ntohl(cap_proto_frame->header.sequence_number),
                    false, "source doesn't support opening", 0, NULL, NULL, 
                    NULL, 0, NULL);
            cbret = -1;
        } else {
            char *def, *nuldef = NULL;
            int def_len;

            char **channels = NULL;
            size_t channels_sz = 0;
            char *chanset = NULL;
            char *uuid = NULL;
            char *capif = NULL;
            uint32_t dlt;
            
            def_len = cf_get_DEFINITION(&def, cap_proto_frame);

            if (def_len > 0) {
                nuldef = strndup(def, def_len);
            }

            msgstr[0] = 0;
            cbret = (*(caph->open_cb))(caph,
                    ntohl(cap_proto_frame->header.sequence_number), nuldef,
                    msgstr, &dlt, &uuid, &chanset, &channels, &channels_sz, &capif);

            cf_send_openresp(caph, ntohl(cap_proto_frame->header.sequence_number),
                    cbret < 0 ? 0 : cbret, msgstr, dlt, uuid, chanset, 
                    channels, channels_sz, capif);

            if (nuldef != NULL)
                free(nuldef);

            if (uuid != NULL)
                free(uuid);

            for (i = 0; i < channels_sz; i++) {
                free(channels[i]);
            }

            if (channels != NULL)
                free(channels);

            if (chanset != NULL)
                free(chanset);

            if (cbret >= 0) {
                cf_handler_launch_capture_thread(caph);
            }

            pthread_mutex_unlock(&(caph->handler_lock));
        }

    } else if (strncasecmp(cap_proto_frame->header.type, "CONFIGURE", 16) == 0) {
        char *cdef, *chanset_channel;
        double chanhop_rate;
        char **chanhop_channels;
        void **chanhop_priv_channels;
        size_t chanhop_channels_sz, szi;
        int chanhop_shuffle = 0, chanhop_offset = 0;
        void *translate_chan;
        int r;

        /* fprintf(stderr, "DEBUG - Got CONFIGURE request\n"); */

        /* Look to see if we have a CHANSET command */
        r = cf_get_CHANSET(&cdef, cap_proto_frame);

        if (r < 0) {
            cf_send_configresp(caph, ntohl(cap_proto_frame->header.sequence_number),
                    0, "Unable to parse CHANSET KV");
            cbret = -1;
        } else if (r > 0) {
            if (caph->chancontrol_cb == NULL) {
                pthread_mutex_unlock(&(caph->handler_lock));
                cf_send_configresp(caph, ntohl(cap_proto_frame->header.sequence_number),
                        0, "Source does not support setting channel");
                cbret = 0;
            } else {
                chanset_channel = strndup(cdef, r);

                if (caph->chantranslate_cb != NULL) {
                    translate_chan = (*(caph->chantranslate_cb))(caph, chanset_channel);
                } else {
                    translate_chan = strdup(chanset_channel);
                }

                /* Cancel channel hopping */
                caph->channel_hop_rate = 0;

                if (caph->hopping_running) {
                    pthread_cancel(caph->hopthread);
                    caph->hopping_running = 0;
                }

                msgstr[0] = 0;
                cbret = (*(caph->chancontrol_cb))(caph,
                        ntohl(cap_proto_frame->header.sequence_number), 
                        translate_chan, msgstr);

                /* Send a response based on the channel set success */
                cf_send_configresp_channel(caph, 
                        ntohl(cap_proto_frame->header.sequence_number), 
                        cbret >= 0, msgstr, chanset_channel);

                /* Free our channel copies */

                free(chanset_channel);

                if (caph->chanfree_cb != NULL)
                    (*(caph->chanfree_cb))(translate_chan);
                else
                    free(translate_chan);

                pthread_mutex_unlock(&(caph->handler_lock));
            }
        } else {
            /* We didn't find a CHANSET, look for CHANHOP.  We only respect one;
             * we'll never look at a CHANHOP if we got a CHANSET */
            r = cf_get_CHANHOP(&chanhop_rate, &chanhop_channels, &chanhop_channels_sz,
                    &chanhop_shuffle, &chanhop_offset, cap_proto_frame);

            if (r < 0 || chanhop_channels_sz == 0) {
                cf_send_configresp(caph, ntohl(cap_proto_frame->header.sequence_number),
                        0, "Unable to parse CHANHOP KV");
                cbret = -1;
            } else if (r > 0) {
                if (caph->chancontrol_cb == NULL) {
                    pthread_mutex_unlock(&(caph->handler_lock));
                    cf_send_configresp(caph, 
                            ntohl(cap_proto_frame->header.sequence_number),
                            0, "Source does not support setting channel");
                    cbret = -1;
                } else {
                    /* Translate all the channels, or dupe them as strings */
                    chanhop_priv_channels = 
                        (void **) malloc(sizeof(void *) * chanhop_channels_sz);

                    for (szi = 0; szi < chanhop_channels_sz; szi++) {
                        if (caph->chantranslate_cb != NULL) {
                            chanhop_priv_channels[szi] = 
                                (*(caph->chantranslate_cb))(caph, 
                                    chanhop_channels[szi]);
                        } else {
                            chanhop_priv_channels[szi] = strdup(chanhop_channels[szi]);
                        }
                    }

                    /* Set the hop data, which will handle our thread */
                    cf_handler_assign_hop_channels(caph, chanhop_channels,
                            chanhop_priv_channels, chanhop_channels_sz, chanhop_rate,
                            chanhop_shuffle, chanhop_offset);

                    /* Return a completion, and we do NOT free the channel lists we
                     * dynamically allocated out of the buffer with cf_get_CHANHOP, as
                     * we're now using them for keeping the channel record in the
                     * caph */
                    cf_send_configresp_chanhop(caph, 
                            ntohl(cap_proto_frame->header.sequence_number), 1, NULL,
                            chanhop_rate, chanhop_channels, chanhop_channels_sz);

                    pthread_mutex_unlock(&(caph->handler_lock));

                    cbret = 1;
                }
            }
        }

    } else if (strncasecmp(cap_proto_frame->header.type, "PING", 16) == 0) {
        caph->last_ping = time(NULL);
        cf_send_pong(caph);
        cbret = 1;

        pthread_mutex_unlock(&(caph->handler_lock));
    } else {
        fprintf(stderr, "DEBUG - got unhandled request - '%.16s'\n", cap_proto_frame->header.type);

        pthread_mutex_unlock(&(caph->handler_lock));
        cf_send_proberesp(caph, ntohl(cap_proto_frame->header.sequence_number),
                false, "Unsupported request", NULL, NULL, 0);
        cbret = -1;

        pthread_mutex_unlock(&(caph->handler_lock));
    }

    free(frame_buf);

    return cbret;
}

int cf_get_DEFINITION(char **ret_definition, simple_cap_proto_frame_t *in_frame) {
    simple_cap_proto_kv_t *def_kv = NULL;
    int def_len;

    def_len = find_simple_cap_proto_kv(in_frame, "DEFINITION", &def_kv);

    if (def_len <= 0) {
        *ret_definition = NULL;
        return def_len;
    }

    *ret_definition = (char *) def_kv->object;
    return def_len;
}

int cf_get_CHANSET(char **ret_definition, simple_cap_proto_frame_t *in_frame) {
    simple_cap_proto_kv_t *ch_kv = NULL;
    int ch_len;

    ch_len = find_simple_cap_proto_kv(in_frame, "CHANSET", &ch_kv);

    if (ch_len <= 0) {
        *ret_definition = NULL;
        return ch_len;
    }

    *ret_definition = (char *) ch_kv->object;
    return ch_len;
}

int cf_get_CHANHOP(double *hop_rate, char ***ret_channel_list,
        size_t *ret_channel_list_sz, int *ret_shuffle, int *ret_offset,
        simple_cap_proto_frame_t *in_frame) {
    simple_cap_proto_kv_t *ch_kv = NULL;
    int ch_len;

    /* msgpuck validation */
    const char *mp_end;
    const char *mp_buf;
    int mp_ret;
    const char *sval;
    uint32_t sval_len;
    uint32_t dict_size, chan_size;
    uint32_t dict_itr, chan_itr;

    *ret_channel_list = NULL;
    *ret_channel_list_sz = 0;
    *hop_rate = 0;
    *ret_offset = 0;
    *ret_shuffle = 0;

    ch_len = find_simple_cap_proto_kv(in_frame, "CHANHOP", &ch_kv);

    if (ch_len <= 0) {
        return ch_len;
    }

    /* Validate the msgpack data before we try to parse it */

    mp_buf = (char *) ch_kv->object;
    mp_end = mp_buf + ntohl(ch_kv->header.obj_sz);

    if ((mp_ret = mp_check(&mp_buf, mp_end)) != 0 ||
            mp_buf != mp_end) {
        /* fprintf(stderr, "debug - chanhop failed mp_check\n"); */
        return -1;
    }

    /* Reset the buffer position to the start of the object */
    mp_buf = (char *) ch_kv->object;

    /* Get all the elements in the dictionary */
    dict_size = mp_decode_map(&mp_buf);
    for (dict_itr = 0; dict_itr < dict_size; dict_itr++) {
        sval = mp_decode_str(&mp_buf, &sval_len);

        if (strncasecmp(sval, "rate", sval_len) == 0) {
            *hop_rate = mp_decode_double(&mp_buf);
        } else if (strncasecmp(sval, "shuffle", sval_len) == 0) {
            *ret_shuffle = mp_decode_uint(&mp_buf);
        } else if (strncasecmp(sval, "offset", sval_len) == 0) {
            *ret_offset = mp_decode_uint(&mp_buf);
        } else if (strncasecmp(sval, "channels", sval_len) == 0) {
            if (*ret_channel_list != NULL) {
                /* fprintf(stderr, "debug - duplicate channels list in chanhop\n"); */
                return -1;
            }

            chan_size = mp_decode_array(&mp_buf);

            if (chan_size > 0) {
                *ret_channel_list = (char **) malloc(sizeof(char *) * chan_size);
                if (*ret_channel_list == NULL) {
                    /* fprintf(stderr, "debug - chanhop failed to allocate channels\n"); */
                    return -1;
                }

                for (chan_itr = 0; chan_itr < chan_size; chan_itr++) {
                    /* Re-use our sval */
                    sval = mp_decode_str(&mp_buf, &sval_len);

                    /* Dupe the channel into our list */
                    (*ret_channel_list)[chan_itr] = strndup(sval, sval_len);
                }

                *ret_channel_list_sz = chan_size;
            } else {
                *ret_channel_list_sz = 0;
                *ret_channel_list = NULL;
            }
        }
    }
    
    return chan_size;
}

int cf_handler_loop(kis_capture_handler_t *caph) {
    fd_set rset, wset;
    int max_fd;
    int read_fd, write_fd;
    struct timeval tm;
    int spindown;
    int ret;
    int rv = 0;

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

        if (time(NULL) - caph->last_ping > 5) {
            fprintf(stderr, "FATAL - Capture source did not get PING from Kismet for "
                    "over 5 seconds; shutting down");
            pthread_mutex_unlock(&(caph->handler_lock));
            rv = -1;
            break;
        }

        /* Copy spindown state outside of lock */
        spindown = caph->spindown;

        pthread_mutex_unlock(&(caph->handler_lock));

        /* Only set read sets if we're not spinning down */
        if (spindown == 0) {
            /* Only set rset if we're not spinning down */
            FD_SET(read_fd, &rset);
            max_fd = read_fd;
        }

        /* Inspect the write buffer - do we have data? */
        pthread_mutex_lock(&(caph->out_ringbuf_lock));

        if (kis_simple_ringbuf_used(caph->out_ringbuf) != 0) {
            // fprintf(stderr, "debug - capf - writebuffer has %lu\n", kis_simple_ringbuf_used(caph->out_ringbuf));
            FD_SET(write_fd, &wset);
            if (max_fd < write_fd)
                max_fd = write_fd;
        } else if (spindown != 0) {
            /* fprintf(stderr, "DEBUG - caphandler finished spinning down\n"); */
            pthread_mutex_unlock(&(caph->out_ringbuf_lock));
            rv = 0;
            break;
        }

        pthread_mutex_unlock(&(caph->out_ringbuf_lock));

        tm.tv_sec = 0;
        tm.tv_usec = 500000;

        if ((ret = select(max_fd + 1, &rset, &wset, NULL, &tm)) < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                fprintf(stderr, 
                        "FATAL:  Error during select(): %s\n", strerror(errno));
                rv = -1;
                break;
            }
        }

        if (ret == 0)
            continue;

        if (FD_ISSET(read_fd, &rset)) {
            /* We use a fixed-length read buffer for simplicity, and we shouldn't
             * ever have too many incoming packets queued because the datasource
             * protocol is very tx-heavy */
            ssize_t amt_read;
            size_t amt_buffered;
            uint8_t rbuf[1024];

            /* We deliberately read as much as we need and try to put it in the 
             * buffer, if the buffer fills up something has gone wrong anyhow */

            if ((amt_read = read(read_fd, rbuf, 1024)) <= 0) {
                if (errno != EINTR && errno != EAGAIN) {
                    /* Bail entirely */
                    if (amt_read == 0) {
                        fprintf(stderr, "FATAL: Remote side closed read pipe\n");
                    } else {
                        fprintf(stderr,
                                "FATAL:  Error during read(): %s\n", strerror(errno));
                    }
                    rv = -1;
                    break;
                }
            }

            amt_buffered = kis_simple_ringbuf_write(caph->in_ringbuf, rbuf, amt_read);

            if ((ssize_t) amt_buffered != amt_read) {
                /* Bail entirely - to do, report error if we can over connection */
                fprintf(stderr,
                        "FATAL:  Error during read(): insufficient buffer space\n");
                rv = -1;
                break;
            }

            // fprintf(stderr, "debug - capframework - read %lu\n", amt_buffered);

            /* See if we have a complete packet to do something with */
            if (cf_handle_rx_data(caph) < 0) {
                /* Enter spindown if processing an incoming packet failed */
                cf_handler_spindown(caph);
            }

        }

        if (FD_ISSET(write_fd, &wset)) {
            /* We can write data - lock the ring buffer mutex and write out
             * whatever we can; we peek the ringbuffer and then flag off what
             * we've successfully written out */
            ssize_t written_sz;
            size_t peek_sz;
            size_t peeked_sz;
            uint8_t *peek_buf;

            pthread_mutex_lock(&(caph->out_ringbuf_lock));

            peek_sz = kis_simple_ringbuf_used(caph->out_ringbuf);

            /* Don't know how we'd get here... */
            if (peek_sz == 0) {
                pthread_mutex_unlock(&(caph->out_ringbuf_lock));
                continue;
            }

            peek_buf = (uint8_t *) malloc(peek_sz);

            if (peek_buf == NULL) {
                pthread_mutex_unlock(&(caph->out_ringbuf_lock));
                fprintf(stderr,
                        "FATAL:  Error during write(): could not allocate write "
                        "buffer space\n");
                rv = -1;
                break;
            }

            peeked_sz = kis_simple_ringbuf_peek(caph->out_ringbuf, peek_buf, peek_sz);

            // fprintf(stderr, "debug - peeked %lu\n", peeked_sz);

            if ((written_sz = write(write_fd, peek_buf, peeked_sz)) < 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    pthread_mutex_unlock(&(caph->out_ringbuf_lock));
                    fprintf(stderr,
                            "FATAL:  Error during write(): %s\n", strerror(errno));
                    free(peek_buf);
                    rv = -1;
                    break;
                }
            }

            free(peek_buf);

            /* Flag it as consumed */
            kis_simple_ringbuf_read(caph->out_ringbuf, NULL, (size_t) written_sz);

            /* Unlock */
            pthread_mutex_unlock(&(caph->out_ringbuf_lock));

            /* Signal to any waiting IO that the buffer has some
             * headroom */
            pthread_cond_signal(&(caph->out_ringbuf_flush_cond));
        }
    }

    /* fprintf(stderr, "FATAL - dropped out of select loop\n"); */
    
    /* Kill the capture thread */
    pthread_mutex_lock(&(caph->out_ringbuf_lock));
    if (caph->capture_running) {
        pthread_cancel(caph->capturethread);
        caph->capture_running = 0;
    }
    pthread_mutex_unlock(&(caph->out_ringbuf_lock));

    return rv;
}

int cf_send_raw_bytes(kis_capture_handler_t *caph, uint8_t *data, size_t len) {
    pthread_mutex_lock(&(caph->out_ringbuf_lock));

    if (kis_simple_ringbuf_available(caph->out_ringbuf) < len) {
        fprintf(stderr, "debug - Insufficient room in write buffer to queue data\n");
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

int cf_stream_packet(kis_capture_handler_t *caph, const char *packtype,
        simple_cap_proto_kv_t **in_kv_list, unsigned int in_kv_len) {

    /* Proto header we write to the buffer */
    simple_cap_proto_t *proto_hdr;
    size_t proto_sz;

    size_t i;

    /* Encode a header */
    proto_hdr = encode_simple_cap_proto_hdr(&proto_sz, packtype, 0, 
            in_kv_list, in_kv_len);

    if (proto_hdr == NULL) {
        fprintf(stderr, "FATAL: Unable to allocate protocol frame header\n");
        for (i = 0; i < in_kv_len; i++) {
            free(in_kv_list[i]);
        }
        free(in_kv_list);
        return -1;
    }

    /* 
     fprintf(stderr, "debug - trying to write streaming packet '%s' len %lu\n", packtype, proto_sz);
     */

    pthread_mutex_lock(&(caph->out_ringbuf_lock));

    if (kis_simple_ringbuf_available(caph->out_ringbuf) < proto_sz) {
        pthread_mutex_unlock(&(caph->out_ringbuf_lock));
        for (i = 0; i < in_kv_len; i++) {
            free(in_kv_list[i]);
        }
        free(in_kv_list);
        free(proto_hdr);
        return 0;
    }

    /* Write the header out */
    kis_simple_ringbuf_write(caph->out_ringbuf, (uint8_t *) proto_hdr, 
            sizeof(simple_cap_proto_t));

    /* Write all the kv pairs out */
    for (i = 0; i < in_kv_len; i++) {
        simple_cap_proto_kv_t *kv = in_kv_list[i];

        kis_simple_ringbuf_write(caph->out_ringbuf, (uint8_t *) kv,
                ntohl(kv->header.obj_sz) + sizeof(simple_cap_proto_kv_t));

        free(in_kv_list[i]);
    }

    if (in_kv_list != NULL)
        free(in_kv_list);

    free(proto_hdr);

    pthread_mutex_unlock(&(caph->out_ringbuf_lock));

    return 1;
}

int cf_send_message(kis_capture_handler_t *caph, const char *msg, unsigned int flags) {
    /* How many KV pairs are we allocating?  1 for success for sure */
    size_t num_kvs = 1;

    /* Actual KV pairs we encode into the packet */
    simple_cap_proto_kv_t **kv_pairs;

    kv_pairs = 
        (simple_cap_proto_kv_t **) malloc(sizeof(simple_cap_proto_kv_t *) * num_kvs);

    kv_pairs[0] = encode_kv_message(msg, flags);

    if (kv_pairs[0] == NULL) {
        free(kv_pairs);
        return -1;
    }

    return cf_stream_packet(caph, "MESSAGE", kv_pairs, 1);
}

int cf_send_warning(kis_capture_handler_t *caph, const char *msg, unsigned int flags,
        const char *warning) {
    /* How many KV pairs are we allocating?  1 for success for sure */
    size_t num_kvs = 2;

    /* Actual KV pairs we encode into the packet */
    simple_cap_proto_kv_t **kv_pairs;

    kv_pairs = 
        (simple_cap_proto_kv_t **) malloc(sizeof(simple_cap_proto_kv_t *) * num_kvs);

    kv_pairs[0] = encode_kv_message(msg, flags);

    if (kv_pairs[0] == NULL) {
        free(kv_pairs);
        return -1;
    }

    kv_pairs[1] = encode_kv_warning(warning);

    if (kv_pairs[1] == NULL) {
        free(kv_pairs[0]);
        free(kv_pairs);
        return -1;
    }

    return cf_stream_packet(caph, "MESSAGE", kv_pairs, 1);
}

int cf_send_error(kis_capture_handler_t *caph, const char *msg) {
    size_t num_kvs = 2;

    /* Actual KV pairs we encode into the packet */
    simple_cap_proto_kv_t **kv_pairs;

    kv_pairs = 
        (simple_cap_proto_kv_t **) malloc(sizeof(simple_cap_proto_kv_t *) * num_kvs);

    kv_pairs[0] = encode_kv_message(msg, MSGFLAG_ERROR);

    if (kv_pairs[0] == NULL) {
        free(kv_pairs);
        return -1;
    }

    kv_pairs[1] = encode_kv_success(0, 0);

    if (kv_pairs[1] == NULL) {
        free(kv_pairs[0]);
        free(kv_pairs);
        return -1;
    }

    return cf_stream_packet(caph, "ERROR", kv_pairs, 2);
}

int cf_send_listresp(kis_capture_handler_t *caph, uint32_t seq, unsigned int success,
        const char *msg, char **interfaces, char **flags, size_t len) {
    /* How many KV pairs are we allocating?  1 for success for sure */
    size_t num_kvs = 1;

    size_t kv_pos = 0;
    size_t i = 0;

    /* Actual KV pairs we encode into the packet */
    simple_cap_proto_kv_t **kv_pairs;

    if (msg != NULL && strlen(msg) != 0)
        num_kvs++;

    if (len != 0)
        num_kvs++;

    kv_pairs = 
        (simple_cap_proto_kv_t **) malloc(sizeof(simple_cap_proto_kv_t *) * num_kvs);

    kv_pairs[kv_pos] = encode_kv_success(success, seq);

    if (kv_pairs[kv_pos] == NULL) {
        fprintf(stderr, "FATAL: Unable to allocate KV SUCCESS pair\n");
        free(kv_pairs);
        return -1;
    }

    kv_pos++;

    if (msg != NULL && strlen(msg) != 0) {
        kv_pairs[kv_pos] = 
            encode_kv_message(msg, success ? MSGFLAG_INFO : MSGFLAG_ERROR);
        if (kv_pairs[kv_pos] == NULL) {
            fprintf(stderr, "FATAL: Unable to allocate KV MESSAGE pair\n");
            for (i = 0; i < kv_pos; i++) {
                free(kv_pairs[i]);
            }
            free(kv_pairs);
            return -1;
        }
        kv_pos++;
    }

    if (len != 0) {
        kv_pairs[kv_pos] =
            encode_kv_interfacelist(interfaces, flags, len);
        if (kv_pairs[kv_pos] == NULL) {
            fprintf(stderr, "FATAL: Unable to allocate KV INTERFACE pair\n");
            for (i = 0; i < kv_pos; i++) {
                free(kv_pairs[i]);
            }
            free(kv_pairs);
            return -1;
        }
        kv_pos++;
    }

    return cf_stream_packet(caph, "LISTRESP", kv_pairs, kv_pos);
}

int cf_send_proberesp(kis_capture_handler_t *caph, uint32_t seq, unsigned int success,
        const char *msg, const char *chanset, char **channels, 
        size_t channels_len) {
    /* How many KV pairs are we allocating?  1 for success for sure */
    size_t num_kvs = 1;

    size_t kv_pos = 0;
    size_t i = 0;

    /* Actual KV pairs we encode into the packet */
    simple_cap_proto_kv_t **kv_pairs;

    if (msg != NULL && strlen(msg) != 0)
        num_kvs++;

    if (chanset != NULL)
        num_kvs++;

    if (channels_len != 0)
        num_kvs++;

    kv_pairs = 
        (simple_cap_proto_kv_t **) malloc(sizeof(simple_cap_proto_kv_t *) * num_kvs);

    kv_pairs[kv_pos] = encode_kv_success(success, seq);

    if (kv_pairs[kv_pos] == NULL) {
        fprintf(stderr, "FATAL: Unable to allocate KV SUCCESS pair\n");
        free(kv_pairs);
        return -1;
    }

    kv_pos++;

    if (msg != NULL && strlen(msg) != 0) {
        kv_pairs[kv_pos] = 
            encode_kv_message(msg, success ? MSGFLAG_INFO : MSGFLAG_ERROR);
        if (kv_pairs[kv_pos] == NULL) {
            fprintf(stderr, "FATAL: Unable to allocate KV MESSAGE pair\n");
            for (i = 0; i < kv_pos; i++) {
                free(kv_pairs[i]);
            }
            free(kv_pairs);
            return -1;
        }
        kv_pos++;
    }

    if (chanset != 0) {
        kv_pairs[kv_pos] = encode_kv_chanset(chanset);
        if (kv_pairs[kv_pos] == NULL) {
            fprintf(stderr, "FATAL: Unable to allocate KV CHANSET pair\n");
            for (i = 0; i < kv_pos; i++) {
                free(kv_pairs[i]);
            }
            free(kv_pairs);
            return -1;
        }
        kv_pos++;
    }

    if (channels_len != 0) {
        kv_pairs[kv_pos] = encode_kv_channels(channels, channels_len);
        if (kv_pairs[kv_pos] == NULL) {
            fprintf(stderr, "FATAL: Unable to allocate KV CHANNELS pair\n");
            for (i = 0; i < kv_pos; i++) {
                free(kv_pairs[i]);
            }
            free(kv_pairs);
            return -1;
        }
        kv_pos++;
    }


    return cf_stream_packet(caph, "PROBERESP", kv_pairs, kv_pos);
}

int cf_send_openresp(kis_capture_handler_t *caph, uint32_t seq, unsigned int success,
        const char *msg, uint32_t dlt, const char *uuid, const char *chanset, 
        char **channels, size_t channels_len, const char *capif) {
    /* How many KV pairs are we allocating?  2 for success + dlt for sure */
    size_t num_kvs = 2;

    size_t kv_pos = 0;
    size_t i = 0;

    /* Actual KV pairs we encode into the packet */
    simple_cap_proto_kv_t **kv_pairs;

    if (msg != NULL && strlen(msg) != 0)
        num_kvs++;

    if (chanset != NULL)
        num_kvs++;

    if (channels_len != 0)
        num_kvs++;

    if (uuid != NULL)
        num_kvs++;

    if (capif != NULL)
        num_kvs++;

    /* fprintf(stderr, "debug - openresp going to allocate %u kvs\n", num_kvs); */

    kv_pairs = 
        (simple_cap_proto_kv_t **) malloc(sizeof(simple_cap_proto_kv_t *) * num_kvs);

    kv_pairs[kv_pos] = encode_kv_success(success, seq);
    if (kv_pairs[kv_pos] == NULL) {
        fprintf(stderr, "FATAL: Unable to allocate KV SUCCESS pair\n");
        free(kv_pairs);
        return -1;
    }
    kv_pos++;

    kv_pairs[kv_pos] = encode_kv_dlt(dlt);
    if (kv_pairs[kv_pos] == NULL) {
        fprintf(stderr, "FATAL: Unable to allocate KV DLT pair\n");
        for (i = 0; i < kv_pos; i++) {
            free(kv_pairs[i]);
        }
        free(kv_pairs);
        return -1;
    }
    kv_pos++;


    if (msg != NULL && strlen(msg) != 0) {
        kv_pairs[kv_pos] = 
            encode_kv_message(msg, success ? MSGFLAG_INFO : MSGFLAG_ERROR);
        if (kv_pairs[kv_pos] == NULL) {
            fprintf(stderr, "FATAL: Unable to allocate KV MESSAGE pair\n");
            for (i = 0; i < kv_pos; i++) {
                free(kv_pairs[i]);
            }
            free(kv_pairs);
            return -1;
        }
        kv_pos++;
    }

    if (uuid != NULL) {
        kv_pairs[kv_pos] = encode_kv_uuid(uuid);
        if (kv_pairs[kv_pos] == NULL) {
            fprintf(stderr, "FATAL: Unable to allocate KV UUID pair\n");
            for (i = 0; i < kv_pos; i++) {
                free(kv_pairs[i]);
            }
            free(kv_pairs);
            return -1;
        }
        kv_pos++;
    }

    if (capif != NULL) {
        kv_pairs[kv_pos] = encode_kv_capif(capif);
        if (kv_pairs[kv_pos] == NULL) {
            fprintf(stderr, "FATAL: Unable to allocate KV CAPIF pair\n");
            for (i = 0; i < kv_pos; i++) {
                free(kv_pairs[i]);
            }
            free(kv_pairs);
            return -1;
        }
        kv_pos++;
    }

    if (chanset != 0) {
        kv_pairs[kv_pos] = encode_kv_chanset(chanset);
        if (kv_pairs[kv_pos] == NULL) {
            fprintf(stderr, "FATAL: Unable to allocate KV CHANSET pair\n");
            for (i = 0; i < kv_pos; i++) {
                free(kv_pairs[i]);
            }
            free(kv_pairs);
            return -1;
        }
        kv_pos++;
    }

    if (channels_len != 0) {
        kv_pairs[kv_pos] = encode_kv_channels(channels, channels_len);
        if (kv_pairs[kv_pos] == NULL) {
            fprintf(stderr, "FATAL: Unable to allocate KV CHANNELS pair\n");
            for (i = 0; i < kv_pos; i++) {
                free(kv_pairs[i]);
            }
            free(kv_pairs);
            return -1;
        }
        kv_pos++;
    }

    return cf_stream_packet(caph, "OPENRESP", kv_pairs, kv_pos);
}

int cf_send_data(kis_capture_handler_t *caph,
        simple_cap_proto_kv_t *kv_message,
        simple_cap_proto_kv_t *kv_signal,
        simple_cap_proto_kv_t *kv_gps,
        struct timeval ts, uint32_t packet_sz, uint8_t *pack) {

    // fprintf(stderr, "debug - cf_send_data starting\n");

    /* How many KV pairs are we allocating?  1 for data for sure */
    size_t num_kvs = 1;

    size_t kv_pos = 0;
    size_t i = 0;

    /* Actual KV pairs we encode into the packet */
    simple_cap_proto_kv_t **kv_pairs;

    if (kv_message != NULL)
        num_kvs++;
    if (kv_signal != NULL)
        num_kvs++;
    if (kv_gps != NULL)
        num_kvs++;

    kv_pairs = 
        (simple_cap_proto_kv_t **) malloc(sizeof(simple_cap_proto_kv_t *) * num_kvs);

    if (kv_message != NULL) {
        kv_pairs[kv_pos] = kv_message;
        kv_pos++;
    }

    if (kv_signal != NULL) {
        kv_pairs[kv_pos] = kv_signal;
        kv_pos++;
    }

    if (kv_gps != NULL) {
        kv_pairs[kv_pos] = kv_gps;
        kv_pos++;
    }

    kv_pairs[kv_pos] = encode_kv_capdata(ts, packet_sz, pack);
    if (kv_pairs[kv_pos] == NULL) {
        fprintf(stderr, "FATAL: Unable to allocate KV DATA pair\n");
        for (i = 0; i < kv_pos; i++) {
            free(kv_pairs[i]);
        }
        free(kv_pairs);
        return -1;
    }
    kv_pos++;

    return cf_stream_packet(caph, "DATA", kv_pairs, kv_pos);
}

int cf_send_configresp(kis_capture_handler_t *caph, unsigned int seqno, 
        unsigned int success, const char *msg) {
    size_t num_kvs = 1;
    size_t kv_pos = 0;
    size_t kvi;

    /* Actual KV pairs we encode into the packet */
    simple_cap_proto_kv_t **kv_pairs;

    if (msg != NULL && strlen(msg) != 0)
        num_kvs++;

    kv_pairs = 
        (simple_cap_proto_kv_t **) malloc(sizeof(simple_cap_proto_kv_t *) * num_kvs);

    if (msg != NULL && strlen(msg) != 0) {
        kv_pairs[kv_pos] = encode_kv_message(msg, 
                success ? MSGFLAG_INFO : MSGFLAG_ERROR);

        if (kv_pairs[kv_pos] == NULL) {
            free(kv_pairs);
            return -1;
        }

        kv_pos++;
    }

    kv_pairs[kv_pos] = encode_kv_success(success, seqno);

    if (kv_pairs[kv_pos] == NULL) {
        for (kvi = 0; kvi < kv_pos; kvi++) 
            free(kv_pairs[kvi]);
        free(kv_pairs);
        return -1;
    }

    return cf_stream_packet(caph, "CONFIGRESP", kv_pairs, num_kvs);
}

int cf_send_configresp_channel(kis_capture_handler_t *caph, unsigned int seqno, 
        unsigned int success, const char *msg, const char *channel) {
    size_t num_kvs = 1;
    size_t kv_pos = 0;
    size_t kvi;

    /* Actual KV pairs we encode into the packet */
    simple_cap_proto_kv_t **kv_pairs;

    if (msg != NULL && strlen(msg) != 0)
        num_kvs++;

    if (channel != NULL)
        num_kvs++;

    kv_pairs = 
        (simple_cap_proto_kv_t **) malloc(sizeof(simple_cap_proto_kv_t *) * num_kvs);

    if (msg != NULL && strlen(msg) != 0) {
        kv_pairs[kv_pos] = encode_kv_message(msg, 
                success ? MSGFLAG_INFO : MSGFLAG_ERROR);

        if (kv_pairs[kv_pos] == NULL) {
            free(kv_pairs);
            return -1;
        }

        kv_pos++;
    }

    if (channel != NULL) {
        kv_pairs[kv_pos] = encode_kv_channel(channel);

        if (kv_pairs[kv_pos] == NULL) {
            for (kvi = 0; kvi < kv_pos; kvi++) 
                free(kv_pairs[kvi]);
            free(kv_pairs);
            return -1;
        }

        kv_pos++;
    }

    kv_pairs[kv_pos] = encode_kv_success(success, seqno);

    if (kv_pairs[kv_pos] == NULL) {
        for (kvi = 0; kvi < kv_pos; kvi++) 
            free(kv_pairs[kvi]);
        free(kv_pairs);
        return -1;
    }

    return cf_stream_packet(caph, "CONFIGRESP", kv_pairs, num_kvs);
}

int cf_send_configresp_chanhop(kis_capture_handler_t *caph, unsigned int seqno, 
        unsigned int success, const char *msg, double hop_rate,
        char **channel_list, size_t channel_list_sz) {
    size_t num_kvs = 1;
    size_t kv_pos = 0;
    size_t kvi;

    /* Actual KV pairs we encode into the packet */
    simple_cap_proto_kv_t **kv_pairs;

    if (msg != NULL && strlen(msg) != 0)
        num_kvs++;

    if (channel_list_sz != 0)
        num_kvs++;

    kv_pairs = 
        (simple_cap_proto_kv_t **) malloc(sizeof(simple_cap_proto_kv_t *) * num_kvs);

    if (msg != NULL && strlen(msg) != 0) {
        kv_pairs[kv_pos] = encode_kv_message(msg, 
                success ? MSGFLAG_INFO : MSGFLAG_ERROR);

        if (kv_pairs[kv_pos] == NULL) {
            free(kv_pairs);
            return -1;
        }

        kv_pos++;
    }

    if (channel_list_sz != 0) {
        kv_pairs[kv_pos] = encode_kv_chanhop_complex(hop_rate, channel_list, 
                channel_list_sz, caph->channel_hop_shuffle, 
                caph->channel_hop_shuffle_spacing, caph->channel_hop_offset);

        if (kv_pairs[kv_pos] == NULL) {
            for (kvi = 0; kvi < kv_pos; kvi++) 
                free(kv_pairs[kvi]);
            free(kv_pairs);
            return -1;
        }

        kv_pos++;
    }

    kv_pairs[kv_pos] = encode_kv_success(success, seqno);

    if (kv_pairs[kv_pos] == NULL) {
        for (kvi = 0; kvi < kv_pos; kvi++) 
            free(kv_pairs[kvi]);
        free(kv_pairs);
        return -1;
    }

    kv_pos++;

    return cf_stream_packet(caph, "CONFIGRESP", kv_pairs, num_kvs);
}

int cf_send_ping(kis_capture_handler_t *caph) {
    return cf_stream_packet(caph, "PING", NULL, 0);
}

int cf_send_pong(kis_capture_handler_t *caph) {
    return cf_stream_packet(caph, "PONG", NULL, 0);
}

