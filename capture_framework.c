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

#include "capture_framework.h"

kis_capture_handler_t *cf_handler_init() {
    kis_capture_handler_t *ch;

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

    pthread_mutex_init(&(ch->out_ringbuf_lock), NULL);

    ch->shutdown = 0;
    pthread_mutex_init(&(ch->handler_lock), NULL);

    return ch;
}

void cf_handler_free(kis_capture_handler_t *caph) {
    if (caph == NULL)
        return;

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

int cf_handle_rx_data(kis_capture_handler_t *caph) {
    size_t rb_available;

    simple_cap_proto_t *cap_proto_frame;

    /* Buffer of just the packet header */
    uint8_t hdr_buf[sizeof(simple_cap_proto_t)];

    /* Buffer of entire frame, dynamic */
    uint8_t *frame_buf;

    /* Incoming size */
    uint32_t packet_sz;

    rb_available = kis_simple_ringbuf_used(caph->in_ringbuf);

    if (rb_available < sizeof(simple_cap_proto_t)) {
        fprintf(stderr, "DEBUG - insufficient data to represent a frame\n");
        return 0;
    }

    if (kis_simple_ringbuf_peek(caph->in_ringbuf, hdr_buf, 
                sizeof(simple_cap_proto_t)) != sizeof(simple_cap_proto_t)) {
        return 0;
    }

    cap_proto_frame = (simple_cap_proto_t *) hdr_buf;

    /* Check the signature */
    if (ntohl(cap_proto_frame->signature) != KIS_CAP_SIMPLE_PROTO_SIG) {
        fprintf(stderr, "FATAL: Invalid frame header received\n");
        return -1;
    }

    /* If the signature passes, see if we can read the whole frame */
    packet_sz = ntohl(cap_proto_frame->packet_sz);

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

    // Peek our ring buffer
    if (kis_simple_ringbuf_peek(caph->in_ringbuf, frame_buf, packet_sz) != packet_sz) {
        fprintf(stderr, "FATAL: Failed to read packet from ringbuf\n");
        free(frame_buf);
        return -1;
    }

    // Clear it out from the buffer
    kis_simple_ringbuf_read(caph->in_ringbuf, NULL, packet_sz);

    return -1;
}

void cf_handler_loop(kis_capture_handler_t *caph) {
    fd_set rset, wset;
    int max_fd;
    int read_fd, write_fd;
    struct timeval tm;

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
        pthread_mutex_lock(&(caph->handler_lock));
        if (caph->shutdown) {
            fprintf(stderr, "FATAL: Shutting down main select loop\n");
            break;
        }
        pthread_mutex_unlock(&(caph->handler_lock));

        FD_ZERO(&rset);

        FD_SET(read_fd, &rset);
        max_fd = read_fd;

        FD_ZERO(&wset);

        /* Inspect the write buffer - do we have data? */
        pthread_mutex_lock(&(caph->out_ringbuf_lock));
        if (kis_simple_ringbuf_used(caph->out_ringbuf) != 0) {
            FD_SET(write_fd, &wset);
            if (max_fd < write_fd)
                max_fd = write_fd;
        }
        pthread_mutex_unlock(&(caph->out_ringbuf_lock));

        tm.tv_sec = 0;
        tm.tv_usec = 500000;

        if (select(max_fd + 1, &rset, &wset, NULL, &tm) < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                fprintf(stderr, 
                        "FATAL:  Error during select(): %s\n", strerror(errno));
                break;
            }
        }

        if (FD_ISSET(read_fd, &rset)) {
            /* We use a fixed-length read buffer for simplicity, and we shouldn't
             * ever have too many incoming packets queued because the datasource
             * protocol is very tx-heavy */
            ssize_t amt_read;
            size_t amt_buffered;
            uint8_t rbuf[1024];

            /* We deliberately read as much as we need and try to put it in the 
             * buffer, if the buffer fills up something has gone wrong anyhow */

            if ((amt_read = read(read_fd, rbuf, 1024)) < 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    fprintf(stderr,
                            "FATAL:  Error during read(): %s\n", strerror(errno));
                    break;
                }
            }

            amt_buffered = kis_simple_ringbuf_write(caph->in_ringbuf, rbuf, amt_read);

            if ((ssize_t) amt_buffered != amt_read) {
                fprintf(stderr,
                        "FATAL:  Error during read(): insufficient buffer space\n");
                break;
            }

            /* See if we have a complete packet to do something with */
            if (cf_handle_rx_data(caph) < 0)
                break;

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

            if ((written_sz = write(write_fd, peek_buf, peeked_sz)) < 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    pthread_mutex_unlock(&(caph->out_ringbuf_lock));
                    fprintf(stderr,
                            "FATAL:  Error during read(): %s\n", strerror(errno));
                    break;
                }
            }

            /* Flag it as consumed */
            kis_simple_ringbuf_read(caph->out_ringbuf, NULL, (size_t) written_sz);

            /* Unlock */
            pthread_mutex_unlock(&(caph->out_ringbuf_lock));
        }
    }
}

