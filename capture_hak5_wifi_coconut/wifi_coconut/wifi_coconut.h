/*
 * GPL-2.0-or-later
 *
 * Userspace port (C) 2019 Hak5 LLC
 *
 */

#ifndef __WIFI_COCONUT_H__
#define __WIFI_COCONUT_H__ 

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifndef _WIN32
#include <sys/time.h>
#include <unistd.h>
#else
#include <Windows.h>
#define sleep(x) Sleep(x*1000)
#define usleep(x) Sleep((x) < 1000 ? 1 : (x) / 1000)
#endif

#include "kernel/cfg80211.h"
#include "kernel/endian.h"
#include "kernel/ieee80211.h"
#include "kernel/ieee80211_radiotap.h"

#include <libusb-1.0/libusb.h>

#include "userspace/userspace.h"

/* 
 * Diagnostics struct
 */
struct wifi_coconut_diagnostics {
    pthread_mutex_t mutex;

    unsigned int total_packets[14];
    unsigned int total_data[14];
    int total_min_signal[14];
    int total_max_signal[14];

    time_t last_sec;
    int sec_packets[14];
    int sec_data[14];
    int sec_min_signal[14];
    int sec_max_signal[14];
};

/*
 * A wifi coconut always has 14 radios; each radio is configured for its 
 * own channel and the device reports packets as an aggregate
 * A Wi-Fi Coconut device; can be a linked list or a single device 
 */
struct wifi_coconut {
    struct wifi_coconut *next;

    struct wifi_coconut_context *coconut_context;
    struct userspace_wifi_probe_dev *probed_devices[14];
    struct userspace_wifi_dev *active_devices[14];

    /* 
     * How many devices have we found / allocated, either during scan or in case we can't
     * allocate all devices and decide to continue anyhow
     */
    int device_num;

    /* Per-bus counts */
    int bus_count[4];

    /*
     * What number coconut is this (base hub id)
     */
    int coconut_number;

    /* 
     * What is the USB serial number of the first device in the coconut?  This should be
     * predictable on most platforms but macos catalina seems to have some problems with
     * libusb
     */
    unsigned char first_usb_serial[64];


    /*
     * Is this coconut valid or did we error out?
     */
    bool valid;
};

/* 
 * Wifi coconut global context 
 */
struct wifi_coconut_context {
    /*
     * USB context
     */
    struct userspace_wifi_context *context;

    /* 
     * All coconuts 
     * */
    struct wifi_coconut *coconuts;

    /*
     * The coconut we're operating on
     */
    struct wifi_coconut *coconut;

    /*
     * Diagnostics
     */
    struct wifi_coconut_diagnostics diagnostics;

    /*
     * Runtime options
     */
    bool disable_leds;
    bool disable_blink;
    bool invert_leds;
    bool quiet;
    bool ht40;

    /* 
     * Target coconut device if we have multiple ones
     */
    int coconut_number;
};

/*
 * Search through a list of radios to try to find what looks like a 
 * wifi coconut.
 *
 * - A coconut will have 14 radios
 * - All radios in a coconut are connected via hubs; they will either be
 *   on hub/subhub/radio or hub/radio
 * - All radios in a coconut will be on the same base hub
 * - All radios in a coconut will be rt2800usb
 * - All radios in a coconut will be vid/pid 148f/5370
 * - Radios will be organized as:
 *   {/foo}/base/1/[1..4]
 *   {/foo}/base/2/[1..4]
 *   {/foo}/base/3/[1..2]
 *   {/foo}/base/[4..7]
 *
 * We do a somewhat inefficient clustering of radios to try to find 
 * coconut groups.
 *
 * Coconuts will be numbered by their root hub ID because a user may 
 * plug in additional coconut devices later, which will get a higher
 * root ID because of the USB topology
 *
 * We take control of the devicelist and parse it ourselves instead of 
 * using the for_each API.
 *
 */

struct wifi_coconut_context *init_coconut_context();

/*
 * Map the bus positions to device numbers so we can open
 * them in order.
 */
const extern int device_number_map[7][4];

/*
 * Find a coconut; returns negative on hard failure and one of the following
 * on success or logical failure
 */
#define WIFI_COCONUT_FIND_CLUSTER_OK            0
#define WIFI_COCONUT_FIND_CLUSTER_NONE          1
#define WIFI_COCONUT_FIND_CLUSTER_PARTIAL       2
int find_coconuts_cluster(struct wifi_coconut_context *coconut_context,
        struct userspace_wifi_probe_dev *devicelist,
        struct wifi_coconut **coconut);

void free_coconuts(struct wifi_coconut *coconuts);
void print_wifi_coconuts(struct wifi_coconut *coconuts);

/* 
 * Open all the devices in a wifi coconut, setting each one to a channel
 */
int open_wifi_coconut(struct wifi_coconut_context *coconut_context, struct wifi_coconut *coconut);

/*
 * Scan for coconuts.  Optionally wait for a coconut to be found, and optionally
 * call a callback function reporting the status of the search.
 *
 * When a coconut has been found, it will be assigned to the coconut context.
 *
 * When a proper coconut has been found, it will be opened.  Final activation
 * is deferred to the caller.
 *
 * This can be used by a tool to shim the searching methods.
 *
 * If a callback function is available it will be called with state updated 
 * during each phase, allowing it to format the user output as appropriate.
 *
 * In some situations, the callback function may return a 0 to continue operation
 * or a negative to abort; these situations are:
 *      WIFI_COCONUT_SEARCH_STATE_NO_RADIOS (No usb devices found); allow the 
 *          callback to cancel the normal behavior controlled by wait_for_coconut
*       WIFI_COCONUT_SEARCH_STATE_NO_COCONUT (No complete coconut found); allow the
*           callback to cancel the normal behavior controlled by wait_for_coconut
 *      WIFI_COCONUT_SEARCH_STATE_DEV_ERROR (Failure to open a device)
 */

/* Generic error */
#define WIFI_COCONUT_SEARCH_STATE_ERROR         -1

/* Successful find and open of coconut */
#define WIFI_COCONUT_SEARCH_STATE_DONE          0

/* No USB radios of any sort detected */
#define WIFI_COCONUT_SEARCH_STATE_NO_RADIOS     1

/* No complete wifi coconut detected */
#define WIFI_COCONUT_SEARCH_STATE_NO_COCONUT    2

/* No coconut matching the specified coconut_number found */
#define WIFI_COCONUT_SEARCH_STATE_MISMATCH      3

/* Status update - target coconut has been found */
#define WIFI_COCONUT_SEARCH_STATE_FOUND         4

/* Status update - coconut device (in cb devnum) opened */
#define WIFI_COCONUT_SEARCH_STATE_DEV_OPENED    5

/* Status update - coconut device (in cb devnum) failed to open */
#define WIFI_COCONUT_SEARCH_STATE_DEV_ERROR     6

/* Status update - coconut device (in cb devnum) was not found */
#define WIFI_COCONUT_SEARCH_STATE_NO_DEV        7

/* Status update - one or more coconuts found, returned as list in cb coconut_list */
#define WIFI_COCONUT_SEARCH_STATE_LIST          8

int coconut_search_and_open(struct wifi_coconut_context *coconut_context,
        bool wait_for_coconut, int coconut_number,
        int (*status_callback)(struct wifi_coconut_context *, void *cb_aux, 
            int state, int devnum, struct wifi_coconut *coconut_list),
        void *cb_aux);


/*
 * Activate all the devices in a wifi coconut
 */
int start_wifi_coconut_capture(struct wifi_coconut_context *coconut_context);


#endif /* ifndef WIFI_COCONUT_H */
