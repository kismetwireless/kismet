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
 */

#include "config.h"

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

#ifdef HAVE_LIBWEBSOCKETS
#include <libwebsockets.h>
#endif

#include "simple_ringbuf_c.h"

#include "kis_external_packet.h"

struct kis_capture_handler;
typedef struct kis_capture_handler kis_capture_handler_t;

struct cf_params_interface;
typedef struct cf_params_interface cf_params_interface_t;

struct cf_params_list_interface;
typedef struct cf_params_list_interface cf_params_list_interface_t;

struct cf_params_spectrum;
typedef struct cf_params_spectrum cf_params_spectrum_t;

struct cf_ipc;
typedef struct cf_ipc cf_ipc_t;

#ifdef HAVE_LIBWEBSOCKETS
struct cf_ws_msg {
    char *payload;
    size_t len;
};
#endif

#define CAP_FRAMEWORK_RINGBUF_IN_SZ     (1024 * 64)
#define CAP_FRAMEWORK_RINGBUF_OUT_SZ    (1024 * 1024 * 4)
#define CAP_FRAMEWORK_WS_BUF_SZ         (1024 * 4)

/* List devices callback
 * Called to list devices available
 *
 * *msg is allocated by the framework and can hold STATUS_MAX characters and should
 * be populated with any message the listcb wants to return.
 * **interfaces must be allocated by the list cb and should contain valid
 * list_iterface_t objects
 *
 * Return values:
 * -1   error occurred while listing
 *  0   no error occurred but no interfaces found
 *  1+  number of interfaces present in *interfaces
 */
typedef int (*cf_callback_listdevices)(kis_capture_handler_t *, uint32_t seqno,
        char *msg, cf_params_list_interface_t ***interfaces);

/* Probe definition callback
 * Called to determine if definition is supported by this datasource; the complete command
 * is passed to the datasource in case a future custom definition needs access to data
 * stored there.
 *
 * *msg is allocated by the framework and can hold STATUS_MAX characters and should
 * be populated with any message the listcb wants to return.
 *
 * **ret_interface and **ret_spectrum are to be allocated by the callback
 * function if the results are populated.
 *
 * **uuid should be allocated by the callback if it is populated during
 * probing of the device.
 *
 * Return values:
 * -1   error occurred while probing
 *  0   no error occurred, interface is not supported
 *  1   interface supported
 */
typedef int (*cf_callback_probe)(kis_capture_handler_t *, uint32_t seqno,
        char *definition, char *msg, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum);

/* Open callback
 * Called to open a datasource
 *
 * *msg is allocated by the framework and can hold STATUS_MAX characters and should
 * be populated with any message the listcb wants to return
 *
 * *dlt is allocated by the framework, and should be filled with the interface DLT
 * or link type (typically from pcap_get_linktype or a known fixed value);
 *
 * **uuid is to be allocated by the cb and should hold the interface UUID
 *
 * **ret_interface and **ret_spectrum are to be allocated by the callback function
 * if the results are populated.  They will be freed by the framework.
 *
 * Return values:
 * -1   error occurred while opening
 *  0   success
 */
typedef int (*cf_callback_open)(kis_capture_handler_t *, uint32_t seqno,
        char *definition, char *msg, uint32_t *dlt, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum);

/* Channel translate
 * Called to translate a channel from a generic string to a local representation
 * suitable for controlling a capture interface.  This is used to prevent
 * constant heavy parsing of strings during channel hopping, etc.
 *
 * The callback should allocate a custom structure containing the information and
 * return it as a void*.  This structure will be passed to future callback operations.
 *
 * If the structure is complex and cannot be freed with a simple free() operation,
 * the datasource binary must provide cf_callback_chanfree.
 *
 * Returns:
 * NULL     Unable to translate channel
 * Pointer  callback-allocated structure containing the channel info.
 */
typedef void *(*cf_callback_chantranslate)(kis_capture_handler_t *, const char *chanstr);

/* Channel set
 * Actually set a physical channel on an interface.
 *
 * Called as part of a channel hopping pattern (seqno == 0) or in response to a
 * direct channel set command (seqno != 0).
 *
 * Appropriate classification of tuning errors is left to the discretion of the
 * callback; typically an error during hopping may be allowable while an error
 * during an explicit channel set is not.
 *
 * msg is allocated by the framework and can hold up to STATUS_MAX characters.  It
 * will be transmitted along with success or failure if seqno != 0.
 *
 * In all other situations, the callback may communicate to the user status
 * changes via cf_send_message(...)
 *
 * Returns:
 * -1   Fatal error occurred
 *  0   Unable to tune to this channel, exclude it from future channel hopping
 *      attempts
 *  1+  Success
 */
typedef int (*cf_callback_chancontrol)(kis_capture_handler_t *, uint32_t seqno,
        void *privchan, char *msg);

/* Channel free
 * Called to free an allocated private channel struct.
 *
 * This callback is needed only when the private channel structure defined by the
 * datasource cannot be deallocated with a simple free()
 */
typedef void (*cf_callback_chanfree)(void *);

/* Unknown frame callback
 * Called when an unknown frame is received on the protocol
 *
 * This callback is only needed to handle custom frames.  This allows a capture
 * handler to define its own custom frames and receive them from the comms later.
 *
 * Callbacks are passed:
 *    - Capture framework
 *    - Sequence
 *    - Command number
 *    - Data
 *    - Data length
 *
 * Returns:
 * -1   Error occurred, close source
 *  0   Success, or frame ignored
 */
typedef int (*cf_callback_unknown)(kis_capture_handler_t *, uint32_t,
        unsigned int, const char *, uint32_t);

/* Capture callback
 * Called inside the capture thread as the primary capture mechanism for the source.
 *
 * This callback should loop as long as the source is running, and will be placed
 * in its own thread.  This callback may block, and does not need to be aware of
 * other network IO.
 *
 * This callback should perform locking on the handler_lock mutexes if changing
 * data in the handler.
 *
 * Returns:
 *      On returning, the capture thread is cancelled and the source is closed.
 */
typedef void (*cf_callback_capture)(kis_capture_handler_t *);

/* Spectrum configure callback
 * Configures the basic parameters of a spectrum-capable device
 *
 * Called in response to a SPECSET block in a CONFIGURE command
 *
 * msg is allocated by the framework and can hold up to STATUS_MAX characters.  It
 * will be transmitted along with the success or failure value if seqno != 0
 *
 * In all other situations, the callback may communicate status to the user
 * via cf_send_message(...)
 *
 * Returns:
 * -1   Error occurred
 *  0   Success
 */
typedef int (*cf_callback_spectrumconfig)(kis_capture_handler_t *, uint32_t seqno,
    uint64_t start_mhz, uint64_t end_mhz, uint64_t num_per_freq, uint64_t bin_width,
    unsigned int amp, uint64_t if_amp, uint64_t baseband_amp);

struct kis_capture_handler {
    /* Capture source type */
    char *capsource_type;

    /* Does this driver support remote capture?  Most should, and it defaults to true. */
    int remote_capable;

    /* Last time we got a ping */
    time_t last_ping;

    /* Sequence number counter */
    uint32_t seqno;

    /* Descriptor pair in IPC mode*/
    int in_fd;
    int out_fd;

	/* Child process in monitor mode */
	pid_t monitor_pid;

	/* Child process in ipc mode */
	pid_t child_pid;

    /* Use legacy tcp mode */
    int use_tcp;

    /* Use IPC mode */
    int use_ipc;

    /* Use websockets mode */
    int use_ws;

    /* Remote host and port if acting as a remote drone in TCP mode, also used to
     * synthesize the websocket info */
    char *remote_host;
    unsigned int remote_port;

    /* Remote host for websocket api */
#ifdef HAVE_LIBWEBSOCKETS
    struct lws_context *lwscontext;
    struct lws_vhost *lwsvhost;
    const struct lws_protocols *lwsprotocol;

    struct lws_ring *lwsring;
    uint32_t lwstail;

    struct lws_client_connect_info lwsci;
    struct lws *lwsclientwsi;

    int lwsestablished;

    char *lwsuri;

    int lwsusessl;
    char *lwssslcapath;

    struct lws_context_creation_info lwsinfo;

    char *lwsuuid;
#endif


    /* Announced UUID, if one is required */
    char *announced_uuid;


    /* Specified commandline source, used for remote cap */
    char *cli_sourcedef;

    /* Retry remote connections */
    int remote_retry;

    /* Kick into daemon mode for remote connections */
    int daemonize;

    /* TCP client connection */
    int tcp_fd;

    /* Die when we hit the end of our write buffer */
    int spindown;

    /* TCP/IPC buffers */
    kis_simple_ringbuf_t *in_ringbuf;
    kis_simple_ringbuf_t *out_ringbuf;

    /* websocket packet queue */
#ifdef HAVE_LIBWEBSOCKETS
    struct lws_ring *ring;
    uint32_t tail;
#endif


    /* Lock for output buffer or output ws ring */
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

    cf_callback_chantranslate chantranslate_cb;
    cf_callback_chancontrol chancontrol_cb;
    cf_callback_chanfree chanfree_cb;

    cf_callback_unknown unknown_cb;

    cf_callback_capture capture_cb;

    cf_callback_spectrumconfig spectrumconfig_cb;

    /* Arbitrary data blob for capture specific content */
    void *userdata;

    /* Capture thread */
    int capture_running;
    pthread_t capturethread;

    /* Signal reaping thread */
    pthread_t signalthread;
	int signal_running;

    /* Non-hopping channel */
    char *channel;

    /* Hopping thread */
    int hopping_running;
    pthread_t hopthread;

    /* Hop information:  Original channel list, custom converted hop list (which
     * MUST be the same length as channel hop list; if a channel cannot be parsed,
     * put a NULL), hop list size, and rate. */
    char **channel_hop_list;
    void **custom_channel_hop_list;
    size_t channel_hop_list_sz;
    double channel_hop_rate;

    /* Maximum hop rate; if 0, ignored, if not zero, hop commands are forced to this
     * rate.
     */
    double max_channel_hop_rate;

    /* Linked list of failed channel sets so we can flush the channel array out */
    void *channel_hop_failure_list;
    size_t channel_hop_failure_list_sz;

    /* Do we shuffle?  Do we have a shuffle spacing from the driver? */
    int channel_hop_shuffle;
    unsigned int channel_hop_shuffle_spacing;

    int channel_hop_offset;

    /* Fixed GPS location from command line */
    double gps_fixed_lat, gps_fixed_lon, gps_fixed_alt;

    /* Fixed GPS name */
    char *gps_name;

    /* Are we in remote/verbose mode */
    int verbose;


    /* Any exec'd child processes we monitor */
    cf_ipc_t *ipc_list;
};


struct cf_params_interface {
    char *capif;
    char *chanset;
    char **channels;
    size_t channels_len;
    char *hardware;
};

struct cf_params_list_interface {
    char *interface;
    char *flags;
    char *hardware;
};

struct cf_params_spectrum {
    uint64_t start_mhz;
    uint64_t end_mhz;
    uint64_t samples_per_freq;
    uint64_t bin_width;
    uint8_t amp;
    uint64_t if_amp;
    uint64_t baseband_amp;
};

struct cf_params_gps {
    double lat;
    double lon;
    float alt;
    unsigned int fix;
    float speed;
    double heading;
    float precision;
    uint64_t ts_sec;
    uint32_t ts_usec;
    char *gps_type;
    char *gps_name;
    char *gps_uuid;
};

struct cf_params_signal {
    uint32_t signal_dbm;
    uint32_t noise_dbm;
    uint32_t signal_rssi;
    uint32_t noise_rssi;
    uint64_t freq_khz;
    uint64_t datarate;
    char *channel;
};

/* Exceedingly simple linked list structure for errors setting channels
 * so we can screen them out */
struct cf_channel_error {
    unsigned long channel_pos;
    struct cf_channel_error *next;
};

/* Set remote capability flags.
 * Most sources should support remote capture as nearly no extra work is required,
 * however sources which for some reason cannot can set the flag to 0.
 *
 */
void cf_set_remote_capable(kis_capture_handler_t *caph, int in_capable);

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
 * Parameter lists may include quoted strings; the quotes will not be returned;
 * for instance channels="1,2,3,4",foo=bar will return 1,2,3,4 for 'channels'.
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

/* Count how many flags of the same name are in a source definition
 *
 * Returns:
 * -1   Error
 *  0   Flag not found
 *  1+  Number of instances of flag found in definition
 */
int cf_count_flag(const char *flag, char *definition);


/* Parse a comma separated list of strings, such as channels, into an array of char*.
 *
 * Expects the size of the incoming string in in_sz, allowing for direct passing
 * of values extracted via cf_find_flag which are not null terminated
 *
 * Parsed list is placed into *ret_splitlist and the length is placed into
 * *ret_splitlist_sz.  The caller is responsible for freeing the strings and
 * the array.
 *
 * Returns:
 * -1   Error
 *  0   Success
 */
int cf_split_list(char *in_str, size_t in_sz, char in_split, char ***ret_splitlist,
        size_t *ret_splitlist_sz);

/* Merge two string arrays of strings, such as channels, into a single array of
 * unique values.
 *
 * Passed elements *are copied*.  Caller is responsible for freeing original
 * copies.
 *
 * The resulting list is dynamically allocated.  Caller is responsible for
 * freeing returned list after use.
 *
 * Strings are compared with a case-insensitive compare.
 *
 * Returns:
 *  0   Error / Empty lists passed
 *  sz  Size of *ret_list
 */
size_t cf_append_unique_chans(char **in_list1, size_t in_list1_sz,
        char **in_list2, size_t in_list2_sz, char ***ret_list);


/* Initialize a caphandler
 *
 * Returns:
 * Pointer to handler or NULL on failure to allocate
 */
kis_capture_handler_t *cf_handler_init(const char *in_type);

/* Destroy a caphandler
 *
 * Closes any sockets/descriptors and destroys ringbuffers
 */
void cf_handler_free(kis_capture_handler_t *caph);


/* Initialize an interface param
 *
 * Returns:
 * Pointer to interface parameter struct or NULL
 */
cf_params_interface_t *cf_params_interface_new();

/* Destroy an interface parameter and it's internal fields */
void cf_params_interface_free(cf_params_interface_t *pi);

/* Initialize a spectrum param
 *
 * Returns:
 * Pointer to spectrum parameter struct or NULL
 */
cf_params_spectrum_t *cf_params_spectrum_new();

/* Destroy an interface parameter and it's internal fields */
void cf_params_spectrum_free(cf_params_spectrum_t *si);


/* shutdown immediately - dies at the start of the next select() loop, regardless
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

/* Pivot into a new namespace and remount root as read-only - this should be
 * used whenever possible by data sources on Linux which can be installed as suidroot;
 * this pivots into a new namespace and remounts root as readonly.
 *
 * Returns
 * -1   Error pivoting into restricted namespace
 *  0   Not compiled on Linux
 *  1   Success
 */
int cf_jail_filesystem(kis_capture_handler_t *caph);

/* Drop most root capabilities - this should be used whenever possible by data
 * sources which can be installed as suidroot; this removes all capabilities except
 * NET_ADMIN and NET_RAW.
 *
 * Returns:
 * -1   Error dropping capabilities
 *  0   Capability support not compiled in
 *  1   Success
 */
int cf_drop_most_caps(kis_capture_handler_t *caph);

/* Assign a channel hopping list processed by a capture binary */
void cf_handler_assign_hop_channels(kis_capture_handler_t *caph, char **stringchans,
        void **privchans, size_t chan_sz, double rate, int shuffle, int shuffle_spacing,
        int offset);

/* Set a channel hop shuffle spacing */
void cf_handler_set_hop_shuffle_spacing(kis_capture_handler_t *capf, int spacing);


/* Parse command line options
 *
 * Parse command line for --in-fd, --out-fd, --connect, --source, --host, and populate
 * the caph config.
 *
 * Returns:
 * -1   Missing in-fd/out-fd or --connect, or unknown argument, caller should print
 *      help and exit
 *  1   Success, using interproc IPC
 *  2   Success, using TCP remote connection
 *  3   Success, using TCP reverse (server) remote connection
 */
int cf_handler_parse_opts(kis_capture_handler_t *caph, int argc, char *argv[]);

/* Print the standard help header */
void cf_print_help(kis_capture_handler_t *caph, const char *argv0);

/* Set callbacks; pass NULL to remove a callback. */
void cf_handler_set_listdevices_cb(kis_capture_handler_t *capf,
        cf_callback_listdevices cb);
void cf_handler_set_probe_cb(kis_capture_handler_t *capf, cf_callback_probe cb);
void cf_handler_set_open_cb(kis_capture_handler_t *capf, cf_callback_open cb);

void cf_handler_set_chantranslate_cb(kis_capture_handler_t *capf,
        cf_callback_chantranslate cb);
void cf_handler_set_chancontrol_cb(kis_capture_handler_t *capf,
        cf_callback_chancontrol cb);
void cf_handler_set_chanfree_cb(kis_capture_handler_t *capf, cf_callback_chanfree cb);

void cf_handler_set_spectrumconfig_cb(kis_capture_handler_t *capf,
        cf_callback_spectrumconfig cb);

void cf_handler_set_unknown_cb(kis_capture_handler_t *capf, cf_callback_unknown cb);

/* Set the capture function, which runs inside its own thread */
void cf_handler_set_capture_cb(kis_capture_handler_t *capf, cf_callback_capture cb);


/* Set random data blob */
void cf_handler_set_userdata(kis_capture_handler_t *capf, void *userdata);


/* Initiate the capture thread, which will call the capture callback function in
 * its own thread */
int cf_handler_launch_capture_thread(kis_capture_handler_t *caph);

/* Initiate the channel hopping thread, which will call the channel set function
 * its own thread */
int cf_handler_launch_hopping_thread(kis_capture_handler_t *caph);


/* Perform a blocking wait, waiting for the ringbuffer to free data */
void cf_handler_wait_ringbuffer(kis_capture_handler_t *caph);


/* Handle content in a data frame; called from rb rx or ws rx
 */
int cf_handle_rx_content(kis_capture_handler_t *caph, const uint8_t *buffer, size_t len);

/* Handle data in the rx ringbuffer; called from the select/poll loop.
 * Calls callbacks for packet types automatically when a complete packet is
 * received.
 */
int cf_handle_rb_rx_data(kis_capture_handler_t *caph);


/* Connect to a network socket, if remote connection is specified; this should
 * not be needed by capture tools using the framework; the capture loop will
 * be managed directly via cf_handler_remote_capture
 *
 * Returns:
 * -1   Error, could not connect, process should exit
 *  0   No remote connection specified
 *  1   Successful remote connection
 */
int cf_handler_tcp_remote_connect(kis_capture_handler_t *caph);

/* Connect to a websocket endpoint, if remote connection in ws mode;
 * this should not be needed by capture tools using the framework, the
 * capture loop will be managed directly via cf_handler_remote_capture
 *
 * Returns:
 * -1   Error, could not connect, process should exit
 *  0   No remote connection specified
 *  1   Successful remote connection
 */
int cf_handler_ws_remote_connect(kis_capture_handler_t *caph);


/* Set up a fork loop for remote capture processes.  The normal capture code
 * is run in an independently executed process, allowing for one-shot privilege
 * dropping and eliminating potential memory leaks from interfering with reloading
 * the capture process.
 *
 * Capture drivers should call this after configuring callbacks and parsing options,
 * but before dropping privileges, setting up any unique state inside the main loop,
 * or running cf_handler_loop.
 */
void cf_handler_remote_capture(kis_capture_handler_t *caph);

/* Handle the sockets in a select() loop; this function will block until it
 * encounters an error or gets a shutdown command.
 *
 * Capture drivers should typically define their IO in a callback which will
 * be run in a thread automatically via cf_handler_set_capture_cb.
 * cf_handler_loop() should be called in the main() function.
 *
 * Returns:
 * -1   Error, process should exit
 *  0   No error, process should wait to be killed
 */
int cf_handler_loop(kis_capture_handler_t *caph);


/* Frame metadata, passed around by the prepare/commit system.
 * Callers should only expect *frame to be available or sensical. */
typedef struct _cf_frame_metadata {
    void *metadata;
    void (*free_record)(kis_capture_handler_t *caph,
            struct _cf_frame_metadata *meta);
    kismet_external_frame_v3_t *frame;
} cf_frame_metadata;


/* Prepare a frame; it may go over IPC, TCP, or websockets.
 *
 * The packet *must* be committed for transmission or cancelled.
 *
 * For the duration of the packet being prepared, the capture framework
 * handler will be locked.
 *
 * The estimated length must be long enough to contain the serialized
 * data, and can not be grown dynamically.
 *
 * The packet must be committed with the final size of the payload.
 *
 * Returns:
 *  cf_frame_metadata   *frame is considered valid for use
 *  NULL                Unable to prepare frame
 */
cf_frame_metadata *cf_prepare_packet(kis_capture_handler_t *caph,
        unsigned int command, uint32_t seqno, uint16_t code,
        size_t estimated_len);

/* Cancel a frame; this frees any memory associated with it and
 * unlocks the capture framework */
void cf_cancel_packet(kis_capture_handler_t *caph,
        cf_frame_metadata *meta);

/* Commit a frame, this queues the frame for transmission and
 * unlocks the capture framework.
 *
 * The final length of the content is updated in the protoco frame
 * before transmission.
 *
 * At the end of queing, the meta data is freed and is no longer
 * valid for use.
 *
 * Returns:
 *  0       No error
 *  other   Queuing could not be completed.
 */
int cf_commit_packet(kis_capture_handler_t *caph, cf_frame_metadata *meta,
        size_t final_len);

/* Lock-safe way to get the next sequence number
 *
 * Returns:
 *  Next sequence number
 */
uint32_t cf_get_next_seqno(kis_capture_handler_t *caph);


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

/* Wrap a serialized sub-packet into a v2 frame, and send it.
 * May be called from any thread.
 *
 * The supplied data buffer will be put into the command payload.
 *
 * The supplied data WILL BE FREED regardless of the success of transmitting
 * the packet.
 *
 * Returns:
 * -1   An error occurred
 *  0   Insufficient space in buffer
 *  1   Success
 */
int cf_send_packet(kis_capture_handler_t *caph, unsigned int packtype,
        uint16_t code, uint8_t *data, size_t len);

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

/* Send a MESSAGE+WARNING
 * Can be called from any thread.
 *
 * Flags are expected to match the MSGFLAG_ flags in simple_datasource.h
 * Additionally a WARNING message may be attached which will be stored in the
 * source warning field
 *
 * Returns:
 * -1   An error occurred writing the frame
 *  0   Insufficient space in buffer
 *  1   Success
 */
int cf_send_warning(kis_capture_handler_t *caph, const char *warning);

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
int cf_send_error(kis_capture_handler_t *caph, uint32_t in_seqno, const char *message);

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
        const char *msg, cf_params_list_interface_t **interfaces, size_t len);

/* Send a PROBERESP response; can contain traditional interface data, spectrum interface
 * data, both, or neither in the case of an error.
 *
 * Can be called from any thread
 *
 * Returns:
 * -1   An error occurred while creating the packet
 *  0   Insufficient space in buffer
 *  1   Success
 */
int cf_send_proberesp(kis_capture_handler_t *caph, uint32_t seq, unsigned int success,
        const char *msg, cf_params_interface_t *interface, cf_params_spectrum_t *spectrum);

/* Send an OPENRESP response
 * Can be called from any thread
 *
 * To send supported channels list, provide channels and channels_len, otherwise set
 * channels_len to 0
 *
 * Returns:
 * -1   An error occurred while creating the packet
 *  0   Insufficient space in buffer
 *  1   Success
 */
int cf_send_openresp(kis_capture_handler_t *caph, uint32_t seq, unsigned int success,
        const char *msg, const uint32_t dlt, const char *uuid,
        cf_params_interface_t *interface, cf_params_spectrum_t *spectrum);

/* Send a DATA frame with packet data
 * Can be called from any thread
 *
 * If present, include message_kv, signal_kv, or gps_kv along with the packet data.
 *
 * original_sz is the original length (such as reported by libpcap)
 * packet_sz is the actual captured size, if trimmed (such as caplen reported
 * by libpcap, or other trimmed data not sending the entire content)
 *
 * Returns:
 * -1   An error occurred
 *  0   Insufficient space in buffer
 *  1   Success
 */
int cf_send_data(kis_capture_handler_t *caph,
        const char *msg, unsigned int msg_type,
        struct cf_params_signal *signal, struct cf_params_gps *gps,
        struct timeval ts, uint32_t dlt, uint32_t original_sz,
        uint32_t packet_sz, uint8_t *pack);

/* Send a DATA frame with JSON non-packet data
 * Can be called from any thread
 *
 * If present, include message_kv, signal_kv, or gps_kv along with the json data.
 *
 * Returns:
 * -1   An error occurred
 *  0   Insufficient space in buffer, try again
 *  1   Success
 */
int cf_send_json(kis_capture_handler_t *caph,
        const char *msg, unsigned int msg_type,
        struct cf_params_signal *signal,
        struct cf_params_gps *gps,
        struct timeval ts, const char *type,
        const char *json);

/* Send a CONFIGRESP with only a success and optional message
 *
 * Returns:
 * -1   An error occurred
 *  0   Insufficient space in buffer
 *  1   Success
 */
int cf_send_configresp(kis_capture_handler_t *caph, unsigned int seq,
        unsigned int success, const char *msg);

/* Send a PING request
 *
 * Returns:
 * -1   An error occurred
 *  0   Insufficient space in buffer
 *  1   Success
 */
int cf_send_ping(kis_capture_handler_t *caph);

/* Send a PONG response
 *
 * Returns:
 * -1   An error occurred
 *  0   Insufficient space in buffer
 *  1   Success
 */
int cf_send_pong(kis_capture_handler_t *caph, uint32_t in_seqno);

/* Send a NEWSOURCE command to initiate connecting to a remote server
 *
 * Returns:
 * -1   An error occurred
 *  0   Insufficient space in buffer
 *  1   Success
 */
int cf_send_newsource(kis_capture_handler_t *caph, const char *uuid);

/* Simple frequency parser, returns the frequency in khz from multiple input
 * formats, such as:
 * 123KHz
 * 123000Hz
 * 1.23MHz
 * 1.23e5KHz
 */
double cf_parse_frequency(const char *freq);

/* Set verbosity */
void cf_set_verbose(kis_capture_handler_t *caph, int verbosity);

/* Simple redefinition of message flags */
#define MSGFLAG_DEBUG  KIS_EXTERNAL_V3_MSG_DEBUG
#define MSGFLAG_INFO   KIS_EXTERNAL_V3_MSG_INFO
#define MSGFLAG_ERROR  KIS_EXTERNAL_V3_MSG_ERROR
#define MSGFLAG_ALERT  KIS_EXTERNAL_V3_MSG_ALERT
#define MSGFLAG_FATAL  KIS_EXTERNAL_V3_MSG_FATAL

uint32_t adler32_append_csum(uint8_t *in_buf, size_t in_len, uint32_t cs);
uint32_t adler32_csum(uint8_t *in_buf, size_t in_len);

/* Wait for an announcement from a Kismet server, populate the connection info */
int cf_wait_announcement(kis_capture_handler_t *caph);

/* websockets interface */
#ifdef HAVE_LIBWEBSOCKETS
static void ws_connect_client(kis_capture_handler_t *caph);

static int ws_remotecap_broker(struct lws *wsi, enum lws_callback_reasons reason,
        void *user, void *in, size_t len);

static void ws_destroy_msg(void *in_msg);
#endif

/* IPC RX callback
 *
 * Called when new data comes from an exec'd process
 *
 * Return values:
 * -1   error occurred with processing data, kill ipc exec
 *  0   no error occurred, continue processing
 */
typedef int (*cf_callback_ipc_data)(kis_capture_handler_t *, cf_ipc_t *, uint32_t read_sz);

/* IPC termination callback
 *
 * Called if a spawned process terminates
 */
typedef void (*cf_callback_ipc_term)(kis_capture_handler_t *, cf_ipc_t *, int rc);

/* fork-exec handlers */
struct cf_ipc {
    pid_t pid;

    int running;

    int in_fd;
    int out_fd;
    int err_fd;

    kis_simple_ringbuf_t *in_ringbuf;
    kis_simple_ringbuf_t *out_ringbuf;
    kis_simple_ringbuf_t *err_ringbuf;

    int retry_rx;

    pthread_mutex_t out_ringbuf_lock;

    cf_callback_ipc_data rx_callback;
    cf_callback_ipc_data err_callback;
    cf_callback_ipc_term term_callback;

    struct cf_ipc *next;
};

#define wrap_cond_signal(n, m) pthread_mutex_lock(m); pthread_cond_signal(n); pthread_mutex_unlock(m)
#define wrap_cond_wait(n, m) pthread_mutex_lock(m); pthread_cond_wait(n, m); pthread_mutex_unlock(m)

/* Find a program in $PATH
 *
 * Search the $PATH environment for the given executable, and see if it IS executable.
 *
 * Returns 1 (success) or 0 (failure)
 */
int cf_ipc_find_exec(kis_capture_handler_t *caph, char *program);

/* Launch an IPC process with file descriptors mapped to stdin/out
 *
 * Returns a populated struct of the child information.
 * Caller is responsible for free()ing this data.
 *
 */
cf_ipc_t *cf_ipc_exec(kis_capture_handler_t *, int argc, char **argv);

/* Free an IPC record
 */
void cf_ipc_free(kis_capture_handler_t *, cf_ipc_t *);

/* Kill (or signal) a process
 */
void cf_ipc_signal(kis_capture_handler_t *, cf_ipc_t *, int signal);

/* Set an IPC read handler
 */
void cf_ipc_set_rx(kis_capture_handler_t *, cf_ipc_t *, cf_callback_ipc_data cb);

/* Set an IPC termination handler
 */
void cf_ipc_set_term(kis_capture_handler_t *, cf_ipc_t *, cf_callback_ipc_term cb);

/* Add the IPC to the central tracking
 */
void cf_ipc_add_process(kis_capture_handler_t *, cf_ipc_t *);

/* Remove an IPC process from the central tracking; this process should already
 * be killed.  This will close the file descriptors and free the buffers.
 */
void cf_ipc_remove_process(kis_capture_handler_t *, cf_ipc_t *);

/* Clean and sanitize a sdtring for use in JSON.
 *
 * Returns either a pointer to a new string which must be free'd by the caller,
 * or the pointer to the string provided if no copying was necessary.
 */
char *json_sanitize_string(char *s);

#endif

