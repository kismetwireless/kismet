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

/* capture_pcapfile
 *
 * Basic capture binary, written in pure C, which interfaces via the Kismet
 * simple capture protocol and feeds packets from a pcap file.
 *
 * This could have been implemented in C++ but serves as an example of a simple,
 * very low resource capture method.
 *
 * This uses some of the pure-C code included in Kismet - pure-c implementations
 * of the datasource protocol, a basic ringbuffer implementation, and the msgpuck
 * library which is a pure-c simple msgpack library.
 *
 * This uses basic threading to show how to do an asynchronous read from a source;
 * while a pcapfile will never stall, other sources could.  
 *
 * The select() loop for IO with the IPC channel is performed in the primary
 * thread, and an IO thread is spawned to process data from the pcap file.  This
 * allows us to expand to interesting options, like realtime pcap replay which
 * delays the IO as if they were real packets.
 *
 * The DLT is automatically propagated from the pcap file, or can be overridden
 * with a source command.
 *
 * The communications channel is a file descriptor pair, passed via command
 * line arguments, --in-fd= and --out-fd=
 *
 * We parse additional options from the source definition itself, such as a DLT
 * override, once we open the protocol
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

#include <unistd.h>
#include <errno.h>


#include "simple_datasource_proto.h"
#include "simple_ringbuf_c.h"
#include "msgpuck_buffer.h"

/* Pcap file */
pcap_t *pd;
/* Pcap DLT */
int datalink_type;
/* Overridden DLT */
int override_dlt;

/* Descriptor pair */
int in_fd;
int out_fd;

/* Incoming buffer */
kis_simple_ringbuf_t *in_ringbuf;
/* Outgoing buffer */
kis_simple_ringbuf_t *out_ringbuf;

/* Outgoing buffer mutex */
pthread_mutex_t out_ringbuf_lock;

/* Handle data in our incoming ringbuffer and dispatch parsing it / handling
 * commands from it.  Triggered from the main select() loop and called whenever
 * there is new data in the ringbuffer */
int handle_rx_data(kis_simple_ringbuf_t *ringbuf) {
    fprintf(stderr, "DEBUG - handle rx data %lu\n", kis_simple_ringbuf_used(ringbuf));

    return -1;
}

int parse_opts(int argc, char *argv[]) {
    int option_idx;

    optind = 0;
    opterr = 0;
    option_idx = 0;

    static struct option longopt[] = {
        { "in-fd", required_argument, 0, 1 },
        { "out-fd", required_argument, 0, 2 },
        { 0, 0, 0, 0 }
    };

    while (1) {
        int r = getopt_long(argc, argv, "-", longopt, &option_idx);

        if (r < 0)
            break;

        if (r == 1) {
            if (sscanf(optarg, "%d", &in_fd) != 1) {
                fprintf(stderr, "FATAL: Unable to parse incoming file descriptor\n");
                return -1;
            }
        } else if (r == 2) {
            if (sscanf(optarg, "%d", &out_fd) != 1) {
                fprintf(stderr, "FATAL: Unable to parse outgoing file descriptor\n");
                return -1;
            }

        }

    }

    if (in_fd == -1 || out_fd == -1)
        return -1;

    return 1;
}

int main(int argc, char *argv[]) {
    in_fd = -1;
    out_fd = -1;
    in_ringbuf = NULL;
    out_ringbuf = NULL;

    fd_set rset, wset;
    int max_fd;

    /* Warn after parsing options */
    if (parse_opts(argc, argv) < 0) {
        fprintf(stderr, 
                "FATAL: Failed to parse arguments.  This tool should be automatically\n"
                "launched by Kismet as part of the capture process, running it \n"
                "manually is likely not what you're looking to do.\n");
        return 1;
    }

    /* Input is fairly small */
    in_ringbuf = kis_simple_ringbuf_create(1024 * 8);

    if (in_ringbuf == NULL) {
        fprintf(stderr, 
                "FATAL:  Could not allocate memory for protocol buffers, your system\n"
                "is extremely low on RAM or something is wrong.\n");
        return 1;
    }

    /* Output needs to be more generous because we're reading TCP frames */
    out_ringbuf = kis_simple_ringbuf_create(1024 * 128);

    if (out_ringbuf == NULL) {
        fprintf(stderr, 
                "FATAL:  Could not allocate memory for protocol buffers, your system\n"
                "is extremely low on RAM or something is wrong.\n");
        return 1;
    }

    /* Allocate the mutex */
    pthread_mutex_init(&out_ringbuf_lock, NULL);

    /* Set our descriptors as nonblocking */
    fcntl(in_fd, F_SETFL, fcntl(in_fd, F_GETFL, 0) | O_NONBLOCK);
    fcntl(out_fd, F_SETFL, fcntl(out_fd, F_GETFL, 0) | O_NONBLOCK);

    /* Basic select loop using ring buffers; we fill in from the read descriptor
     * and try to make frames; similarly we populate the outbound descriptor from
     * anything that comes in from our IO thread */
    while (1) {
        FD_ZERO(&rset);
        FD_SET(in_fd, &rset);
        max_fd = in_fd;

        FD_ZERO(&wset);

        /* Inspect the write buffer - do we have data? */
        pthread_mutex_lock(&out_ringbuf_lock);
        if (kis_simple_ringbuf_used(out_ringbuf) != 0) {
            FD_SET(out_fd, &wset);
            if (max_fd < out_fd)
                max_fd = out_fd;
        }
        pthread_mutex_unlock(&out_ringbuf_lock);

        if (select(max_fd + 1, &rset, &wset, NULL, NULL) < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                fprintf(stderr, 
                        "FATAL:  Error during select(): %s\n", strerror(errno));
                break;
            }
        }

        if (FD_ISSET(in_fd, &rset)) {
            /* We use a fixed-length read buffer for simplicity, and we shouldn't
             * ever have too many incoming packets queued because the datasource
             * protocol is very tx-heavy */
            ssize_t amt_read;
            size_t amt_buffered;
            uint8_t rbuf[1024];

            /* We deliberately read as much as we need and try to put it in the 
             * buffer, if the buffer fills up something has gone wrong anyhow */

            if ((amt_read = read(in_fd, rbuf, 1024)) < 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    fprintf(stderr,
                            "FATAL:  Error during read(): %s\n", strerror(errno));
                    break;
                }
            }

            amt_buffered = kis_simple_ringbuf_write(in_ringbuf, rbuf, amt_read);

            if ((ssize_t) amt_buffered != amt_read) {
                fprintf(stderr,
                        "FATAL:  Error during read(): insufficient buffer space\n");
                break;
            }

            /* See if we have a complete packet to do something with */
            if (handle_rx_data(in_ringbuf) < 0)
                break;

        }

        if (FD_ISSET(out_fd, &wset)) {
            /* We can write data - lock the ring buffer mutex and write out
             * whatever we can; we peek the ringbuffer and then flag off what
             * we've successfully written out */
            ssize_t written_sz;
            size_t peek_sz;
            size_t peeked_sz;
            uint8_t *peek_buf;

            pthread_mutex_lock(&out_ringbuf_lock);

            peek_sz = kis_simple_ringbuf_used(out_ringbuf);

            /* Don't know how we'd get here... */
            if (peek_sz == 0) {
                pthread_mutex_unlock(&out_ringbuf_lock);
                continue;
            }

            peek_buf = (uint8_t *) malloc(peek_sz);

            if (peek_buf == NULL) {
                pthread_mutex_unlock(&out_ringbuf_lock);
                fprintf(stderr,
                        "FATAL:  Error during write(): could not allocate write "
                        "buffer space\n");
                break;
            }

            peeked_sz = kis_simple_ringbuf_peek(out_ringbuf, peek_buf, peek_sz);

            if ((written_sz = write(out_fd, peek_buf, peeked_sz)) < 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    pthread_mutex_unlock(&out_ringbuf_lock);
                    fprintf(stderr,
                            "FATAL:  Error during read(): %s\n", strerror(errno));
                    break;
                }
            }

            /* Flag it as consumed */
            kis_simple_ringbuf_read(out_ringbuf, NULL, (size_t) written_sz);

            /* Unlock */
            pthread_mutex_unlock(&out_ringbuf_lock);
        }
    }

    fprintf(stderr, "FATAL: Exited main select() loop\n");

    return 1;
}

