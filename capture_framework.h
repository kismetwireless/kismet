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

#ifndef __CAPTURE_FRAMEWORK_H__
#define __CAPTURE_FRAMEWORK_H__

/* A simple pure-c implementation of a datasource handler.
 *
 * This should provide a simple way to implement pure-c capture binaries with
 * a minimum of code duplication.
 *
 * This uses the simple datasource protocol to communicate over IPC or TCP,
 * and a basic ringbuffer to allocate the data.
 *
 * In this model, the actual data capture happens asynchronously in a capture
 * thread, while the protocol IO and incoming commands are handled by the
 * thread which calls the cf_handler_loop(..) function.
 */

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

#include <arpa/inet.h>

#include "simple_datasource_proto.h"
#include "simple_ringbuf_c.h"
#include "msgpuck_buffer.h"

struct kis_capture_handler;
typedef struct kis_capture_handler kis_capture_handler_t;

typedef int (*cf_callback_listdevices)(kis_capture_handler_t *, uint32_t);
typedef int (*cf_callback_probe)(kis_capture_handler_t *, uint32_t, const char *);
typedef int (*cf_callback_open)(kis_capture_handler_t *, uint32_t, const char *);
typedef int (*cf_callback_unknown)(kis_capture_handler_t *, uint32_t, 
        simple_cap_proto_frame_t *);

struct kis_capture_handler {
    /* Descriptor pair */
    int in_fd;
    int out_fd;

    /* Remote host if connecting */
    char *remote_host;

    /* TCP connection */
    int tcp_fd;

    /* Die when we hit the end of our write buffer */
    int spindown;

    /* Buffers */
    kis_simple_ringbuf_t *in_ringbuf;
    kis_simple_ringbuf_t *out_ringbuf;

    /* Lock for output buffer */
    pthread_mutex_t out_ringbuf_lock;

    /* Are we shutting down? */
    int shutdown;
    pthread_mutex_t handler_lock;

    /* Callbacks called for various incoming packets */
    cf_callback_listdevices listdevices_cb;
    cf_callback_probe probe_cb;
    cf_callback_open open_cb;
};

/* Parse an interface name from a definition string.
 * Returns a pointer to the start of the interface name in the definition in
 * ret_interface, and the length of the interface name.  
 *
 * CALLERS SHOULD ALLOCATE AN ADDITIONAL BYTE FOR NULL TERMINATION when extracting
 * this string, the LENGTH RETURNED IS THE ABSOLUTE LENGTH INSIDE THE DEFINITION.
 *
 * Returns:
 * -1   Error
 *  1+  Length of interface name in the definition
 */
int cf_parse_interface(char **ret_interface, char *definition);

/* Parse a definition string looking for a specific flag and returns a pointer to
 * the start of the flag value in definition in ret_value, and the length of the
 * flag.
 *
 * CALLERS SHOULD ALLOCATE AN ADDITIONAL BYTE FOR NULL TERMINATION when extracting
 * this string, the LENGTH RETURNED IS THE ABSOLUTE LENGTH INSIDE THE DEFINITION.
 *
 * Returns:
 * -1   Error
 *  0   Flag not found
 *  1+  Length of flag value in definition
 */
int cf_parse_flag(char **ret_value, const char *flag, char *definition);

/* Initialize a caphandler
 *
 * Returns:
 * Pointer to handler or NULL on failure to allocate
 */
kis_capture_handler_t *cf_handler_init();

/* Destroy a caphandler
 *
 * Closes any sockets/descriptors and destroys ringbuffers
 */
void cf_handler_free(kis_capture_handler_t *caph);

/* Shutdown immediately - dies at the start of the next select() loop, regardless
 * of pending data.
 *
 * It is not safe to destroy the capture_handler record until the select() blocking
 * loop has exited.
 */
void cf_handler_shutdown(kis_capture_handler_t *caph);

/* Spindown gracefully - flushes any pending data in the write buffer and then
 * exits the select() loop.
 *
 * It is not safe to destroy the capture_handler record until the select() blocking
 * loop has exited.
 */
void cf_handler_spindown(kis_capture_handler_t *caph);

/* Parse command line options
 *
 * Parse command line for --in-fd, --out-fd, --connect, and populate.
 * 
 * Returns:
 * -1   Missing in-fd/out-fd or --connect
 *  1   Success, using interproc IPC
 *  2   Success, using TCP
 */
int cf_handler_parse_opts(kis_capture_handler_t *caph, int argc, char *argv[]);

/* Set callbacks; pass NULL to remove a callback. */
void cf_handler_set_listdevices_cb(kis_capture_handler_t *capf, 
        cf_callback_listdevices cb);
void cf_handler_set_probe_cb(kis_capture_handler_t *capf,
        cf_callback_probe cb);
void cf_handler_set_open_cb(kis_capture_handler_t *capf, 
        cf_callback_open cb);

/* Handle data in the rx ringbuffer; called from the select/poll loop.
 * Calls callbacks for packet types automatically when a complete packet is
 * received.
 */
int cf_handle_rx_data(kis_capture_handler_t *caph);

/* Extract a definition string from a packet, assuming it contains a 
 * 'DEFINITION' KV pair.
 *
 * If available, returns a pointer to the definition in the packet in
 * ret_definition, and returns the length of the definition.
 *
 * CALLERS SHOULD ALLOCATE AN ADDITIONAL BYTE FOR NULL TERMINATION when extracting
 * this string, the LENGTH RETURNED IS THE ABSOLUTE LENGTH INSIDE THE DEFINITION.
 *
 * Returns:
 * -1   Error
 *  0   No DEFINITION key found
 *  1+  Length of definition
 */
int cf_get_DEFINITION(char *ret_definition, simple_cap_proto_t *in_frame);

/* Handle the sockets in a select() loop; this function will block until it
 * encounters an error or gets a shutdown command.
 *
 * For capture drivers that want to perform the IO in a dedicated thread,
 * this function should be initiated from that thread; for all others it can
 * be called from main();
 *
 */
void cf_handler_loop(kis_capture_handler_t *caph);

/* Send a blob of data.  This must be a formatted packet created by one of the
 * other functions.
 *
 * May be called from any thread.
 *
 * Returns:
 * -1   An error occurred
 *  1   Success
 */
int cf_send_raw_bytes(kis_capture_handler_t *caph, uint8_t *data, size_t len);

/* 'stream' a packet to the ringbuf - given a list of KVs, assemble a packet with
 * as little memory copying as possible and place it into the ringbuf.
 *
 * Upon completion, *REGARDLESS OF SUCCESS OR FAILURE*, the provided kv pairs
 * *WILL BE FREED*.
 *
 * Returns:
 * -1   An error occurred
 *  1   Success
 */
int cf_stream_packet(kis_capture_handler_t *caph, const char *packtype,
        simple_cap_proto_kv_t **in_kv_list, unsigned int in_kv_len);

/* Send a LISTRESP response
 * Can be called from any thread.
 *
 * interfaces and flags are expected to be of equal lengths: if there are no
 * corresponding flags for an interface, a NULL should be placed in that slot.
 *
 * Returns:
 * -1   An error occurred writing the frame
 *  1   Success
 */
int cf_send_listresp(kis_capture_handler_t *caph, uint32_t seq, unsigned int success,
        const char *msg, const char **interfaces, const char **flags, size_t len);

/* Send a PROBERESP response
 * Call be called from any thread
 *
 * Returns:
 * -1   An error occurred while probing
 *  1   Success
 */
int cf_send_proberesp(kis_capture_handler_t *caph, uint32_t seq, unsigned int success,
        const char *msg, const char *chanset, const char **channels, size_t channels_len);

#endif

