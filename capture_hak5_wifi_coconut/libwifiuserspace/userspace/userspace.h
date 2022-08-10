/*
 * GPL-2.0-or-later
 *
 * Userspace port (C) 2019 Hak5 LLC
 *
 */

#ifndef __USERSPACE_H__
#define __USERSPACE_H__ 

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>


#include <libusb.h>

#include "kernel/nl80211.h"
#include "kernel/types.h"
#include "kernel/usb.h"

/*
 * Userspace wifi USB context; this is used to store a bunch of state info
 * like the USB device list which we need to keep until we shut down
 */

/* 
 * Forward definitions of various stuff we need
 */
struct userspace_wifi_dev;
struct userspace_wifi_command;
struct userspace_wifi_dev_led;
struct userspace_wifi_rx_signal;

struct userspace_wifi_context {
    struct libusb_context *libusb_context;
    struct libusb_device **devs;
    ssize_t devs_cnt;

    /*
     * Libusb async can't handle scheduling multiple things at once so we have to guard it
     */
    pthread_mutex_t libusb_mutex;

    pthread_t async_service_thread;
    bool service_thread_enabled;
    bool service_thread_active;
    int service_device_count;

    /*
     * We can't perform operations on the service thread so we have to process them
     * through a helper thread
     */
    pthread_t cmd_thread;
    bool cmd_thread_enabled;
    pthread_mutex_t cmd_mutex;

    pthread_mutex_t cmd_wakeup_mutex;
    pthread_cond_t cmd_wakeup_cond;
    struct userspace_wifi_command *cmd_queue;
    struct userspace_wifi_command *cmd_queue_last;
    unsigned long long work_id;

    /* 
     * Optional, where to find the firmware.  Can be set by the consumer
     * to pass an alternate firmware directory.  By default, firmware fetches
     * look in the default directory set at install time.
     */
    char *firmware_directory;

    /*
     * Helper function called BY the drivers, to load firmware of a given name.  Can be
     * overridden in the future.  Can include 'hints' from the driver to help find
     * nested firmware (for instance in the linux firmware tree).
     *
     * Returns 0 and firmware_blob as an allocated chunk and blob_len as length,
     * or negative error
     */
    int (*load_firmware_file)(const struct userspace_wifi_context *context,
            const char *file_name, const char **file_hints, size_t hints_len,
            uint8_t **firmware_blob, size_t *blob_len);

    /*
     * Helper functions supplied by the consumer, called by the
     * driver
     */

    /*
     * Record used by the consumer to store state
     */
    void *local_data;

    /*
     * Called on error, with a string and numerical error code.  This being 
     * called indicates an unrecoverable error condition.
     *
     * error_str will be null terminated, but may be a pointer to a stack
     * variable of the calling function.  Any storage of this value must be
     * copied (via strdup, etc)
     */
    void (*handle_error)(const struct userspace_wifi_context *context,
            struct userspace_wifi_dev *dev,
            const char *error_str, int error_code);

    /* 
     * Handle an incoming packet and l1 signal data
     */
    int (*handle_packet_rx)(struct userspace_wifi_context *context,
            struct userspace_wifi_dev *dev, 
            struct userspace_wifi_rx_signal *signal,
            unsigned char *data, unsigned int len);

    /* 
     * Blinking LEDs takes a surprising amount of work!  We need to run
     * another thread that knows when to turn them off.
     */
    pthread_t led_thread;
    bool led_thread_enable;

    /*
     * Trigger condition for waking up a sleeping LED control thread
     */
    pthread_mutex_t led_cond_mutex;
    pthread_cond_t led_cond;

    /*
     * Access control mutex for adding/removing devices from the LED control list
     */
    pthread_mutex_t led_ts_mutex;
    struct userspace_wifi_dev_led *led_devs;
};

/*
 * We need to track each device we control for LEDs; we need to know when to turn
 * the LED on or off, and what state to return it to.
 */
struct userspace_wifi_dev_led {
    struct userspace_wifi_dev_led *next;

    struct userspace_wifi_dev *dev;
    struct timeval trigger_ts;
    bool restore_state;
};

static inline void userspace_wifi_lock(struct userspace_wifi_context *context) {
    pthread_mutex_lock(&context->libusb_mutex);
}

static inline void userspace_wifi_unlock(struct userspace_wifi_context *context) {
    pthread_mutex_unlock(&context->libusb_mutex);
}

/*
 * Command thread interactions take place using a generic structure which the command
 * handlers fill in
 */
struct userspace_wifi_command {
    struct userspace_wifi_command *next;

    struct userspace_wifi_dev *device;
    void (*callback)(struct userspace_wifi_context *context,
            struct userspace_wifi_dev *device,
            void *param);
    void *param;

    unsigned long long id;
};

void userspace_wifi_queue_work(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *dev,
        void (*callback)(struct userspace_wifi_context *context,
            struct userspace_wifi_dev *device,
            void *param), void *param);

/*
 * Userspace USB device list populated by the scanning function, and used
 * to open a userspace USB Wi-Fi device
 */
struct userspace_wifi_probe_dev {
    /*
     * Context to pass along
     */
    struct userspace_wifi_context *context;

    /*
     * Device that we matched against from the raw hw list 
     */
    const struct usb_device_id *device_id_match;

    /* 
     * Libusb device we could open as a device_handle
     */
    libusb_device *dev;

    /* 
     * Arbitrary name and type
     */
    char *driver_name;
    char *device_type;

	/*
	 * Bus and device location
	 */
	int usb_bus;
    int usb_port;
	int usb_device;

    /* 
     * USB serial number of device
     */
    unsigned char usb_serial[64];

    /* 
     * USB bus path
     */
    uint8_t usb_bus_path[8];
    int usb_bus_path_len;

    /*
     * Opening function supplied by the driver that found us, opens a *dev into a userspace dev
     */
    int (*open_device)(struct userspace_wifi_probe_dev *dev, struct userspace_wifi_dev **udev);

    /*
     * Linked list of N possible devices to open
     */
    struct userspace_wifi_probe_dev *next;
};

/*
 * Userspace USB wifi device after it's been opened, with helper functions added by the 
 * userspace driver
 */
struct userspace_wifi_dev {
    /*
     * overall context, needed for locks
     */
    struct userspace_wifi_context *context;

    /*
     * Arbitrary device id
     */
    int dev_id;

    /*
     * device hardware/eeprom MAC, if available
     */
    uint8_t dev_mac[6];

    /* 
     * USB serial number of device
     */
    unsigned char usb_serial[64];

    /*
     * Record used by the driver (often to hold the usb device state)
     */
    void *dev_data;

    /*
     * Libusb device we could open as a device_handle 
     */
    libusb_device *dev;

    /*
     * Do we continue queuing transfers?
     */
    bool usb_transfer_active;

    /* 
     * USB data buffer allocated by the driver
     */
    unsigned char *usb_transfer_buffer;

    /* 
     * USB async transfer record allocated by the driver
     */
    struct libusb_transfer *usb_transfer;

    /*
     * Helper functions supplied by the driver
     */

    int (*start_capture)(struct userspace_wifi_dev *dev);
    void (*stop_capture)(struct userspace_wifi_dev *dev);

    int (*set_channel)(struct userspace_wifi_dev *dev, int channel, enum nl80211_chan_width width);
    int (*set_led)(struct userspace_wifi_dev *dev, bool enable);

    /*
     * Pointer to the LED control object, if one exists
     */
    struct userspace_wifi_dev_led *led_control;

};

/*
 * Signal data extracted from radio
 */
struct userspace_wifi_rx_signal {
    bool crc_valid;
    unsigned int channel;
    enum nl80211_band band;
    int signal;
    enum nl80211_chan_width chan_width;
    bool short_gi;
    unsigned int mcs;
};

/*
 * Initialize the userspace usb driver system; this calls libusb init and 
 * allocates a context in **context.  This context should be freed and 
 * the system shut down with free_userspace_wifi_system
 */
int userspace_wifi_init(struct userspace_wifi_context **context);

/*
 * Clean up the userspace usb driver system
 */
void userspace_wifi_free(struct userspace_wifi_context *context);

/*
 * Scan for any supported wifi devices; returns negative error or total number
 * of devices found in the probe, and populates **devices with a linked list
 * of probe results.
 */
int userspace_wifi_probe(struct userspace_wifi_context *context,
        struct userspace_wifi_probe_dev **devices);

/*
 * Free the results of a probe list 
 */
void userspace_wifi_free_probe(struct userspace_wifi_probe_dev *devices);

/* 
 * Call a function for each result of a probe list (obscuring the linked list 
 * internals).
 * Callback should return 0 to continue or non-0 to break
 */
void userspace_wifi_for_each_probe(struct userspace_wifi_context *context,
		struct userspace_wifi_probe_dev *devices,
		int (*cb)(struct userspace_wifi_context *, struct userspace_wifi_probe_dev *));

/* 
 * Set an error handling callback
 */
static inline void userspace_wifi_set_error_cb(struct userspace_wifi_context *context,
        void (*cb)(const struct userspace_wifi_context *, struct userspace_wifi_dev *,
            const char *, int)) {
    context->handle_error = cb;
}

/*
 * Trigger an error
 */
static inline void userspace_wifi_error(const struct userspace_wifi_context *context,
        struct userspace_wifi_dev *dev,
        int errnum, const char *fmt, ...) {
    char buf[2048];
    va_list arg_ptr;

    va_start(arg_ptr, fmt);
    vsnprintf(buf, 2048, fmt, arg_ptr);
    va_end(arg_ptr);

    if (context->handle_error != NULL) {
        (*context->handle_error)(context, dev, buf, errnum);
        return;
    }

    fprintf(stderr, "ERROR: %s\n", buf);
}


/*
 * Set a callback for handling packets
 */
static inline void userspace_wifi_set_packet_cb(struct userspace_wifi_context *context,
        int (*cb)(struct userspace_wifi_context *context,
            struct userspace_wifi_dev *dev, 
            struct userspace_wifi_rx_signal *signal,
            unsigned char *data, unsigned int len)) {
    context->handle_packet_rx = cb;
}


/*
 * Open a userspace device via the open function supplied by the driver
 * Returns 0 on success, non-zero on failure.  On success, allocates a usb device in *device.
 */
int userspace_wifi_device_open(struct userspace_wifi_context *context,
        struct userspace_wifi_probe_dev *probedevice,
        struct userspace_wifi_dev **device);

int userspace_wifi_device_start_capture(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *dev);
int userspace_wifi_device_stop_capture(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *dev);
int userspace_wifi_device_set_channel(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *dev,
        int channel, enum nl80211_chan_width width);
int userspace_wifi_device_set_led(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *dev, bool enable);

static inline void userspace_wifi_device_set_id(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *dev,
        int id) {
    dev->dev_id = id;
}

static inline int userspace_wifi_device_get_id(const struct userspace_wifi_context *context,
        struct userspace_wifi_dev *dev) {
    return dev->dev_id;
}

/*
 * Enable LED controls for a specific device; this will enable the LED control thread
 * if it is not already running. 
 */
int userspace_wifi_device_enable_led_control(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *device);
void userspace_wifi_device_disable_led_control(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *device);
/*
 * Blink a LED for duration_ms (setting led to !restore_state), then restore it.
 * If extending, extend any existing timer by an additional duration_ms 
 */
int userspace_wifi_device_blink_led(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *device,
        unsigned int duration_ms, bool restore_state, bool extend);


#endif /* ifndef USERSPACE_H */
