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

kis_capture_handler_t *cf_handler_init() {
    kis_capture_handler_t *ch;
    pthread_mutexattr_t mutexattr;

    ch = (kis_capture_handler_t *) malloc(sizeof(kis_capture_handler_t));

    if (ch == NULL)
        return NULL;

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

    ch->userdata = NULL;

    ch->capture_running = 0;

    return ch;
}

void cf_handler_free(kis_capture_handler_t *caph) {
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

void cf_handler_set_probe_cb(kis_capture_handler_t *capf, 
        cf_callback_probe cb) {
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

void cf_handler_set_capture_cb(kis_capture_handler_t *capf,
        cf_callback_capture cb) {
    pthread_mutex_lock(&(capf->handler_lock));
    capf->capture_cb = cb;
    pthread_mutex_unlock(&(capf->handler_lock));
}

/* Internal capture thread which spawns the capture callback
 */
void *cf_int_capture_thread(void *arg) {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) arg;

    // fprintf(stderr, "debug - inside int_capture_thread\n");

    /* Set us cancelable */
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    if (caph->capture_cb != NULL) {
        // fprintf(stderr, "debug - launching capture callback\n");
        (*(caph->capture_cb))(caph);
    } else {
        fprintf(stderr, "ERROR - No capture handler defined for capture thread\n");
    }

    // fprintf(stderr, "DEBUG - got to end of capture thread\n");
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

    if (pthread_create(&(caph->capturethread), &attr, 
                cf_int_capture_thread, caph) < 0) {
        // fprintf(stderr, "debug - failed to pthread_create %s\n", strerror(errno));
        cf_send_error(caph, "failed to launch capture thread");
        cf_handler_spindown(caph);
        return -1;
    }

    caph->capture_running = 1;
    
    // fprintf(stderr, "debug - capture thread launched\n");

    return 1;
}

void cf_handler_wait_ringbuffer(kis_capture_handler_t *caph) {
    // fprintf(stderr, "debug - waiting for ringbuf_flush_cond\n");
    pthread_cond_wait(&(caph->out_ringbuf_flush_cond),
            &(caph->out_ringbuf_flush_cond_mutex));
    pthread_mutex_unlock(&(caph->out_ringbuf_flush_cond_mutex));
    // fprintf(stderr, "debug - done waiting for ringbuffer to drain\n");
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
    int cbret;

    rb_available = kis_simple_ringbuf_used(caph->in_ringbuf);

    if (rb_available < sizeof(simple_cap_proto_t)) {
        // fprintf(stderr, "DEBUG - insufficient data to represent a frame\n");
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
        fprintf(stderr, "DEBUG - Got LISTINTERFACES request\n");

        if (caph->listdevices_cb == NULL) {
            pthread_mutex_unlock(&(caph->handler_lock));
            cf_send_listresp(caph, ntohl(cap_proto_frame->header.sequence_number),
                    false, "We don't support listing", NULL, NULL, 0);
            cbret = -1;
        } else {
            cbret = (*(caph->listdevices_cb))(caph, 
                    ntohl(cap_proto_frame->header.sequence_number));
            pthread_mutex_unlock(&(caph->handler_lock));
        }
    } else if (strncasecmp(cap_proto_frame->header.type, "PROBEDEVICE", 16) == 0) {
        fprintf(stderr, "DEBUG - Got PROBEDEVICE request\n");

        if (caph->probe_cb == NULL) {
            pthread_mutex_unlock(&(caph->handler_lock));
            cf_send_proberesp(caph, ntohl(cap_proto_frame->header.sequence_number),
                    false, "We don't support probing", NULL, NULL, 0);
            cbret = -1;
        } else {
            char *def, *nuldef = NULL;
            int def_len;
            
            def_len = cf_get_DEFINITION(&def, cap_proto_frame);

            if (def_len > 0) {
                nuldef = strndup(def, def_len);
            }

            cbret = (*(caph->probe_cb))(caph,
                    ntohl(cap_proto_frame->header.sequence_number), nuldef);

            if (nuldef != NULL)
                free(nuldef);

            pthread_mutex_unlock(&(caph->handler_lock));
        }
    } else if (strncasecmp(cap_proto_frame->header.type, "OPENDEVICE", 16) == 0) {
        fprintf(stderr, "DEBUG - Got OPENDEVICE request\n");

        if (caph->open_cb == NULL) {
            pthread_mutex_unlock(&(caph->handler_lock));
            cf_send_openresp(caph, ntohl(cap_proto_frame->header.sequence_number),
                    false, "We don't support opening", 
                    NULL, 0,
                    NULL, 
                    0, NULL, 0);
            cbret = -1;
        } else {
            char *def, *nuldef = NULL;
            int def_len;
            
            def_len = cf_get_DEFINITION(&def, cap_proto_frame);

            if (def_len > 0) {
                nuldef = strndup(def, def_len);
            }

            cbret = (*(caph->open_cb))(caph,
                    ntohl(cap_proto_frame->header.sequence_number), nuldef);

            if (nuldef != NULL)
                free(nuldef);

            pthread_mutex_unlock(&(caph->handler_lock));
        }
    } else {
        fprintf(stderr, "DEBUG - got unhandled request - '%.16s'\n", cap_proto_frame->header.type);

        pthread_mutex_unlock(&(caph->handler_lock));
        cf_send_proberesp(caph, ntohl(cap_proto_frame->header.sequence_number),
                false, "Unsupported request", NULL, NULL, 0);
        cbret = -1;
    }

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

void cf_handler_loop(kis_capture_handler_t *caph) {
    fd_set rset, wset;
    int max_fd;
    int read_fd, write_fd;
    struct timeval tm;
    int spindown;
    int ret;

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
            fprintf(stderr, "DEBUG - caphandler finished spinning down\n");
            pthread_mutex_unlock(&(caph->out_ringbuf_lock));
            break;
        }

        pthread_mutex_unlock(&(caph->out_ringbuf_lock));

        tm.tv_sec = 0;
        tm.tv_usec = 500000;

        if ((ret = select(max_fd + 1, &rset, &wset, NULL, &tm)) < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                fprintf(stderr, 
                        "FATAL:  Error during select(): %s\n", strerror(errno));
                break;
            }
        }

        if (ret == 0)
            continue;

        if (FD_ISSET(read_fd, &rset)) {
            fprintf(stderr, "debug - read set\n");
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
                    break;
                }
            }

            amt_buffered = kis_simple_ringbuf_write(caph->in_ringbuf, rbuf, amt_read);

            if ((ssize_t) amt_buffered != amt_read) {
                /* Bail entirely - to do, report error if we can over connection */
                fprintf(stderr,
                        "FATAL:  Error during read(): insufficient buffer space\n");
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
                break;
            }

            peeked_sz = kis_simple_ringbuf_peek(caph->out_ringbuf, peek_buf, peek_sz);

            // fprintf(stderr, "debug - peeked %lu\n", peeked_sz);

            if ((written_sz = write(write_fd, peek_buf, peeked_sz)) < 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    pthread_mutex_unlock(&(caph->out_ringbuf_lock));
                    fprintf(stderr,
                            "FATAL:  Error during write(): %s\n", strerror(errno));
                    break;
                }
            }

            fprintf(stderr, "debug - capf - wrote %lu of %lu\n", written_sz, peek_sz);

            /* Flag it as consumed */
            kis_simple_ringbuf_read(caph->out_ringbuf, NULL, (size_t) written_sz);

            /* Unlock */
            pthread_mutex_unlock(&(caph->out_ringbuf_lock));

            /* Signal to any waiting IO that the buffer has some
             * headroom */
            pthread_cond_signal(&(caph->out_ringbuf_flush_cond));
        }
    }

    fprintf(stderr, "FATAL - dropped out of select loop\n");
    
    /* Kill the capture thread */
    pthread_mutex_lock(&(caph->out_ringbuf_lock));
    if (caph->capture_running) {
        pthread_cancel(caph->capturethread);
        caph->capture_running = 0;
    }
    pthread_mutex_unlock(&(caph->out_ringbuf_lock));
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
        kis_simple_ringbuf_write(caph->out_ringbuf, (uint8_t *) in_kv_list[i],
                ntohl(in_kv_list[i]->header.obj_sz) + sizeof(simple_cap_proto_kv_t));
        free(in_kv_list[i]);
    }

    free(in_kv_list);
    free(proto_hdr);

    /* fprintf(stderr, "debug - wrote streaming packet '%s' len %lu buffer %lu\n", packtype, proto_sz, kis_simple_ringbuf_used(caph->out_ringbuf)); */

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
        const char *msg, const char **interfaces, const char **flags, size_t len) {
    /* How many KV pairs are we allocating?  1 for success for sure */
    size_t num_kvs = 1;

    size_t kv_pos = 0;
    size_t i = 0;

    /* Actual KV pairs we encode into the packet */
    simple_cap_proto_kv_t **kv_pairs;

    if (msg != NULL)
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

    if (msg != NULL) {
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
            fprintf(stderr, "FATAL: Unable to allocate KV MESSAGE pair\n");
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
        const char *msg, const char *chanset, const char **channels, 
        size_t channels_len) {
    /* How many KV pairs are we allocating?  1 for success for sure */
    size_t num_kvs = 1;

    size_t kv_pos = 0;
    size_t i = 0;

    /* Actual KV pairs we encode into the packet */
    simple_cap_proto_kv_t **kv_pairs;

    if (msg != NULL)
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

    if (msg != NULL) {
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
        const char *msg, 
        const char **channels, size_t channels_len,
        const char *chanset, 
        double hoprate, const char **hop_channels, size_t hop_channels_len) {
    /* How many KV pairs are we allocating?  1 for success for sure */
    size_t num_kvs = 1;

    size_t kv_pos = 0;
    size_t i = 0;

    /* Actual KV pairs we encode into the packet */
    simple_cap_proto_kv_t **kv_pairs;

    if (msg != NULL)
        num_kvs++;

    if (chanset != NULL)
        num_kvs++;

    if (channels_len != 0)
        num_kvs++;

    if (hop_channels_len != 0)
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

    if (msg != NULL) {
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

    if (hop_channels_len != 0) {
        kv_pairs[kv_pos] = encode_kv_chanhop(hoprate, hop_channels, hop_channels_len);
        if (kv_pairs[kv_pos] == NULL) {
            fprintf(stderr, "FATAL: Unable to allocate KV CHANHOP pair\n");
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
        struct timeval ts, int dlt, uint32_t packet_sz, uint8_t *pack) {

    // fprintf(stderr, "debug - cf_send_data starting\n");

    /* How many KV pairs are we allocating?  1 for data for sure */
    size_t num_kvs = 1;

    size_t kv_pos = 0;
    size_t i = 0;

    /* Actual KV pairs we encode into the packet */
    simple_cap_proto_kv_t **kv_pairs;

    if (kv_message != NULL)
        kv_pos++;
    if (kv_signal != NULL)
        kv_signal++;
    if (kv_gps != NULL)
        kv_gps++;

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

    kv_pairs[kv_pos] = encode_kv_capdata(ts, dlt, packet_sz, pack);
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
