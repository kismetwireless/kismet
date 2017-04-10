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
 *
 * Capture may be completely blocking - for example using pcap_loop directly - 
 * because it is isolated from the protocol control thread.
 *
 * Callbacks:
 *  list_devices
 *      If present, called when the capture binary receives a LISTDEVICES command.
 *      Is responsible for generating a list of all supported devices, (or none), and
 *      any flags needed to uniquely identify the device.
 *
 *  probe
 *      If present, called when the capture binary receives a PROBEDEVICE command.
 *      This is part of the autoprobe system - it is responsible for determining if
 *      this datasource can handle a device specified with no type.
 *
 *  open
 *      If present, called when the capture binary receives an OPENDEVICE command.
 *      This occurs once Kismet has identified what datasource handles a source
 *      definition, and should actually open the device.
 *
 *  chanset
 *      If present, called when the capture binary receives a CHANSET command.
 *      This is called when the source is locked to a single channel, and the
 *      channel is sent as a complex channel string definition - for instance
 *      '2412MHz', '2.412GHz', '1', '1HT40+' would all be valid channel strings;
 *      it is up to the source to interpret them.
 *
 *  chanhop
 *      If present, called when the capture binary receives a CHANHOP command.
 *      This configures the basic channel hopping pattern.  Channels are passed
 *      as complex strings.
 *      Sources are encouraged to translate the channels to an internal format
 *      and populate the callback framework channel cache.  These parsed
 *      strings will then be passed to the hw_channel_set callback, to prevent
 *      a full string parse every hop event.
 *      Internal formats are best described by a custom struct, and are stored in
 *      the framework as a void*
 *
 *  chancontrol
 *      If present, called when the capture binary sets a channel; this is called
 *      with the interpreted channel data passed as a void*
 *
 *  chanfree
 *      If present, called when the capture binary needs to purge the list of
 *      internally formatted channels.  Called once for each custom channel.
 *      If the custom channel format is a simple struct which can be freed
 *      entirely with 'free(...)', a chanfree callback is not required.
 *
 *  capture
 *      Called once the source is opened, and run in its own thread.  The thread
 *      is marked cancellable; the callback does not need to perform any special
 *      actions.
 *      When the capture callback ends, the source is placed into error mode.
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

#include <unistd.h>
#include <errno.h>

#include <arpa/inet.h>

#include "simple_datasource_proto.h"
#include "simple_ringbuf_c.h"
#include "msgpuck_buffer.h"

struct kis_capture_handler;
typedef struct kis_capture_handler kis_capture_handler_t;

typedef int (*cf_callback_listdevices)(kis_capture_handler_t *, uint32_t);
typedef int (*cf_callback_probe)(kis_capture_handler_t *, uint32_t, char *);
typedef int (*cf_callback_open)(kis_capture_handler_t *, uint32_t, char *);

typedef int (*cf_callback_chanset)(kis_capture_handler_t *, uint32_t, char *);
typedef int (*cf_callback_chanhop)(kis_capture_handler_t *, uint32_t,
        double, char **, size_t);
typedef int (*cf_callback_chancontrol)(kis_capture_handler_t *, void *);
typedef void (*cf_callback_chanfree)(void *);

typedef int (*cf_callback_unknown)(kis_capture_handler_t *, uint32_t, 
        simple_cap_proto_frame_t *);

typedef void (*cf_callback_capture)(kis_capture_handler_t *);

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

    /* conditional waiter for ringbuf flushing data */
    pthread_cond_t out_ringbuf_flush_cond;
    pthread_mutex_t out_ringbuf_flush_cond_mutex;

    /* Are we shutting down? */
    int shutdown;
    pthread_mutex_t handler_lock;

    /* Callbacks called for various incoming packets */
    cf_callback_listdevices listdevices_cb;
    cf_callback_probe probe_cb;
    cf_callback_open open_cb;

    cf_callback_chanset chanset_cb;
    cf_callback_chanhop chanhop_cb;
    cf_callback_chancontrol chancontrol_cb;
    cf_callback_chanfree chanfree_cb;

    cf_callback_unknown unknown_cb;

    cf_callback_capture capture_cb;


    /* Arbitrary data blob */
    void *userdata;

    /* Capture thread */
    int capture_running;
    pthread_t capturethread;

    /* Channel list */
    char **channel_hop_list;
    void **custom_channel_hop_list;
    size_t channel_hop_list_sz;
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
int cf_find_flag(char **ret_value, const char *flag, char *definition);

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
void cf_handler_set_probe_cb(kis_capture_handler_t *capf, cf_callback_probe cb);
void cf_handler_set_open_cb(kis_capture_handler_t *capf, cf_callback_open cb);

void cf_handler_set_chanset_cb(kis_capture_handler_t *capf, cf_callback_chanset cb);
void cf_handler_set_chanhop_cb(kis_capture_handler_t *capf, cf_callback_chanhop cb);
void cf_handler_set_chancontrol_cb(kis_capture_handler_t *capf, 
        cf_callback_chancontrol cb);
void cf_handler_set_chanfree_cb(kis_capture_handler_t *capf, cf_callback_chanfree cb);

void cf_handler_set_unknown_cb(kis_capture_handler_t *capf, cf_callback_unknown cb);

/* Set the capture function, which runs inside its own thread */
void cf_handler_set_capture_cb(kis_capture_handler_t *capf, cf_callback_capture cb);

/* Set random data blob */
void cf_handler_set_userdata(kis_capture_handler_t *capf, void *userdata);

/* Initiate the capture thread, which will call the capture callback function in
 * its own thread */
int cf_handler_launch_capture_thread(kis_capture_handler_t *caph);

/* Perform a blocking wait, waiting for the ringbuffer to free data */
void cf_handler_wait_ringbuffer(kis_capture_handler_t *caph);

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
 * Length is suitable for passing to strndup().
 *
 * Returns:
 * -1   Error
 *  0   No DEFINITION key found
 *  1+  Length of definition
 */
int cf_get_DEFINITION(char **ret_definition, simple_cap_proto_frame_t *in_frame);

/* Extract a channel set string from a packet, assuming it contains a
 * 'CHANSET' KV pair.
 *
 * If available, returns a pointer to the channel in the packet in
 * ret_channel, and returns the length of the channel.
 *
 * Length is suitable for passing to strndup() to copy the channel string.
 *
 * Returns:
 * -1   Error
 *  0   No CHANSET key found
 *  1+  Length of channel string
 */
int cf_get_CHANSET(char **ret_definition, simple_cap_proto_frame_t *in_frame);

/* Extract a channel hop command from a packet, assuming it contains a 'CHANHOP'
 * kv pair.
 *
 * Returns the hop rate in *ret_hop_rate.
 *
 * *ALLOCATES* a new array of strings in **ret_channel_list *which the caller is 
 * responsible for freeing*.  The caller must free both the channel string and the
 * overall list.
 *
 * Returns the number of channels in *ret_channel_list_sz.
 *
 * Returns:
 * -1   Error
 *  0   No CHANHOP key found or no channels found
 *  1+  Number of channels in chanhop command
 */
int cf_get_CHANHOP(double *hop_rate, char ***ret_channel_list, 
        size_t *ret_channel_list_sz, simple_cap_proto_frame_t *in_frame);

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
 *  0   Insufficient space in buffer
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
 *  0   Insufficient space in buffer
 *  1   Success
 */
int cf_stream_packet(kis_capture_handler_t *caph, const char *packtype,
        simple_cap_proto_kv_t **in_kv_list, unsigned int in_kv_len);

/* Send a MESSAGE
 * Can be called from any thread.
 *
 * Flags are expected to match the MSGFLAG_ flags in simple_datasource.h
 *
 * Returns:
 * -1   An error occurred writing the frame
 *  0   Insufficient space in buffer
 *  1   Success
 */
int cf_send_message(kis_capture_handler_t *caph, const char *message, 
        unsigned int flags);

/* Send an ERROR
 * Can be called from any thread
 *
 * Send an error message indicating this source is now closed
 *
 * Returns:
 * -1   An error occurred writing the frame
 *  0   Insufficient space in buffer
 *  1   Success
 */
int cf_send_error(kis_capture_handler_t *caph, const char *message);

/* Send a LISTRESP response
 * Can be called from any thread.
 *
 * interfaces and flags are expected to be of equal lengths: if there are no
 * corresponding flags for an interface, a NULL should be placed in that slot.
 *
 * Returns:
 * -1   An error occurred writing the frame
 *  0   Insufficient space in buffer
 *  1   Success
 */
int cf_send_listresp(kis_capture_handler_t *caph, uint32_t seq, unsigned int success,
        const char *msg, char **interfaces, char **flags, size_t len);

/* Send a PROBERESP response
 * Call be called from any thread
 *
 * Returns:
 * -1   An error occurred while creating the packet
 *  0   Insufficient space in buffer
 *  1   Success
 */
int cf_send_proberesp(kis_capture_handler_t *caph, uint32_t seq, unsigned int success,
        const char *msg, const char *chanset, char **channels, size_t channels_len);

/* Send an OPENRESP response
 * Can be called from any thread
 *
 * To send supported channels list, provide channels and channels_len, otherwise set 
 * channels_len to 0
 *
 * To set initial state 'hopping', populate hoprate, hop_channels, and hop_channels_len
 * and set chanset to NULL.
 *
 * To set initial state locked, populate chanset and set hop_channels_len to 0.
 *
 * Returns:
 * -1   An error occurred while creating the packet
 *  0   Insufficient space in buffer
 *  1   Success
 */
int cf_send_openresp(kis_capture_handler_t *caph, uint32_t seq, unsigned int success,
        const char *msg, 
        char **channels, size_t channels_len,
        const char *chanset, 
        double hoprate, 
        char **hop_channels, size_t hop_channels_len);

/* Send a DATA frame with packet data
 * Can be called from any thread
 *
 * If present, include message_kv, signal_kv, or gps_kv along with the packet data.
 * On failure or transmit, provided accessory KV pairs will be freed.
 *
 * Returns:
 * -1   An error occurred 
 *  0   Insufficient space in buffer
 *  1   Success
 */
int cf_send_data(kis_capture_handler_t *caph,
        simple_cap_proto_kv_t *kv_message,
        simple_cap_proto_kv_t *kv_signal,
        simple_cap_proto_kv_t *kv_gps,
        struct timeval ts, int dlt, uint32_t packet_sz, uint8_t *pack);

/* Send a CONFIGRESP with only a success and optional message
 *
 * Returns:
 * -1   An error occurred
 *  0   Insufficient space in buffer
 *  1   Success
 */
int cf_send_configresp(kis_capture_handler_t *caph, unsigned int seq,
        unsigned int success, const char *msg);

/* Send a CONFIGRESP with a fixed channel and optional message 
 *
 * Returns:
 * -1   An error occurred
 *  0   Insufficient space in buffer
 *  1   Success
 */
int cf_send_configresp_channel(kis_capture_handler_t *caph,
        unsigned int seq, unsigned int success, const char *msg, const char *channel);

/* Send a CONFIGRESP with a channel hop and optional message.
 *
 * Returns:
 * -1   An error occurred
 *  0   Insufficient space in buffer
 *  1   Success
 */
int cf_send_configresp_chanhop(kis_capture_handler_t *caph,
        unsigned int seq, unsigned int success, const char *msg, 
        double hop_rate, char **channel_list, size_t channel_list_sz);

#endif

