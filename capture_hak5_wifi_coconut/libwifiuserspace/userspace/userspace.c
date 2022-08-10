/*
 * GPL-2.0-or-later
 *
 * Userspace port (C) 2019 Hak5 Inc
 *
 */

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef _WIN32
#include <sys/time.h>
#include <unistd.h>
#else
#include <Windows.h>
#define usleep(x) Sleep((x) < 1000 ? 1 : (x) / 1000)
#define sleep(x) Sleep(x * 1000)
#endif

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#include "userspace.h"
#include "rt2800usb/rt2800usb.h"

#ifdef _WIN32
 /*
  * Kluge a windows time into a user time
  */
int gettimeofday(struct timeval* tp, struct timezone* tzp) {
	static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

	SYSTEMTIME  system_time;
	FILETIME    file_time;
	uint64_t    time;

	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);
	time = ((uint64_t)file_time.dwLowDateTime);
	time += ((uint64_t)file_time.dwHighDateTime) << 32;

	tp->tv_sec = (long)((time - EPOCH) / 10000000L);
	tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
	return 0;
}

#define	timercmp(a, b, CMP) \
  (((a)->tv_sec == (b)->tv_sec) ? \
   ((a)->tv_usec CMP (b)->tv_usec) : \
   ((a)->tv_sec CMP (b)->tv_sec))

#define	timeradd(a, b, result) \
  do { \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec; \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec; \
    if ((result)->tv_usec >= 1000000) \
      { \
	++(result)->tv_sec; \
	(result)->tv_usec -= 1000000; \
      } \
  } while (0)

#define	timersub(a, b, result) \
  do { \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec; \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
    if ((result)->tv_usec < 0) { \
      --(result)->tv_sec; \
      (result)->tv_usec += 1000000; \
    } \
  } while (0)
#endif

void *userspace_wifi_service_thread(void *ctx) {
    struct userspace_wifi_context *context = (struct userspace_wifi_context *) ctx;
    int r;

    while (context->service_thread_enabled) {
        r = libusb_handle_events_completed(context->libusb_context, NULL);

        if (r != 0) {
            userspace_wifi_error(context, NULL, r, "Failed to handle USB events: %s",
                    libusb_error_name(r));
        }
    }

    return NULL;
}

void *userspace_wifi_cmd_service_thread(void *ctx) {
    struct userspace_wifi_context *context = (struct userspace_wifi_context *) ctx;
    struct userspace_wifi_command *command;

    while (context->cmd_thread_enabled) {
        pthread_mutex_lock(&context->cmd_wakeup_mutex);
        pthread_cond_wait(&context->cmd_wakeup_cond, &context->cmd_wakeup_mutex);

        while (1) {
            pthread_mutex_lock(&context->cmd_mutex);
            command = context->cmd_queue;

            if (command != NULL) {
                context->cmd_queue = command->next;
                if (context->cmd_queue == NULL)
                    context->cmd_queue_last = NULL;
             
                /* We must unlock BEFORE calling the callback */
                pthread_mutex_unlock(&context->cmd_mutex);

                (command->callback)(context, command->device, command->param);

                free(command);

                continue;
            } 

            pthread_mutex_unlock(&context->cmd_mutex);

            break;
        }

        pthread_mutex_unlock(&context->cmd_wakeup_mutex);
    }

    return NULL;
}

#ifdef __APPLE__
/* Find the last instance of the / in the path and slice everything 
 * after it off by chopping with a \0.  Modifies the passed path. */
void chop_after_last_slash(char *path) {
    char *last = path;
    char *pos = NULL;

    while ((pos = strstr(last + 1, "/")) != NULL) {
        last = pos;
    }

    last[0] = 0;
}
#endif

/* 
 * Standard firmware loader which looks in the specified firmware dir (if any), various
 * system directories, and the libwifiuserspace share directory
 */
int userspace_load_firmware_file(const struct userspace_wifi_context *context, const char *file_name, 
        const char **file_hints, size_t hints_len,
        uint8_t **firmware_blob, size_t *blob_len) {
    FILE *fwfile = NULL;
    int fwfd = -1;
    struct stat statbuf;
    char fw_path[2048];
    size_t i;

#ifdef __APPLE__
    char exe_path[2048];
    uint32_t exe_path_sz = 2048;
#endif

    /* Start by looking at the context dir, if any */
    if (context->firmware_directory != NULL) {
        snprintf(fw_path, 2048, "%s/%s", context->firmware_directory, file_name);
        if ((fwfile = fopen(fw_path, "rb")) != NULL)
            goto got_file;
        
        /* Look at all the hints */
        for (i = 0; i < hints_len; i++) {
            snprintf(fw_path, 2048, "%s/%s/%s", context->firmware_directory, file_hints[i], file_name);
            if ((fwfile = fopen(fw_path, "rb")) != NULL)
                goto got_file;
        }
    }

	/* Look at the current directory */
	snprintf(fw_path, 2048, "%s", file_name);
	if ((fwfile = fopen(fw_path, "rb")) != NULL)
		goto got_file;

	/* Look at all the hints */
	for (i = 0; i < hints_len; i++) {
		snprintf(fw_path, 2048, "%s/%s", file_hints[i], file_name);
		if ((fwfile = fopen(fw_path, "rb")) != NULL)
			goto got_file;
	}

    /* Look at the share firmware dir */
    snprintf(fw_path, 2048, "%s/%s", FIRMWAREDIR, file_name);
    if ((fwfile = fopen(fw_path, "rb")) != NULL)
        goto got_file;

    /* Look at all the hints */
    for (i = 0; i < hints_len; i++) {
        snprintf(fw_path, 2048, "%s/%s/%s", FIRMWAREDIR, file_hints[i], file_name);
        if ((fwfile = fopen(fw_path, "rb")) != NULL)
            goto got_file;
    }

    /* Look at the stock linux firmware dir */
    snprintf(fw_path, 2048, "%s/%s", "/lib/firmware/", file_name);
    if ((fwfile = fopen(fw_path, "rb")) != NULL)
        goto got_file;

    /* Look at all the hints */
    for (i = 0; i < hints_len; i++) {
        snprintf(fw_path, 2048, "%s/%s/%s", "/lib/firmware/", file_hints[i], file_name);
        if ((fwfile = fopen(fw_path, "rb")) != NULL)
            goto got_file;
    }

    /* Look in our path in case we're on OSX and the firmware is in our framework */
#ifdef __APPLE__
    if (_NSGetExecutablePath(exe_path, &exe_path_sz) == 0) {
        chop_after_last_slash(exe_path);
        snprintf(fw_path, 2048, "%s/%s/%s", exe_path, "../Resources/firmware/", file_name);
        if ((fwfile = fopen(fw_path, "rb")) != NULL)
            goto got_file;

        /* Look at all the hints */
        for (i = 0; i < hints_len; i++) {
            snprintf(fw_path, 2048, "%s/%s/%s/%s", exe_path, "../Resources/firmware/", file_hints[i], file_name);
            if ((fwfile = fopen(fw_path, "rb")) != NULL)
                goto got_file;
        }
    }

#endif


    goto no_file;

got_file:
    fwfd = fileno(fwfile);
    if (fstat(fwfd, &statbuf) != 0) {
        fclose(fwfile);

        userspace_wifi_error(context, NULL, -ENOENT, "Could not find firmware file '%s'",
                file_name);

        return -ENOENT;
    }

#ifndef _WIN32
	if (!S_ISREG(statbuf.st_mode)) {
		fclose(fwfile);

        userspace_wifi_error(context, NULL, -ENOENT, "Firmware file '%s' not a normal file",
                file_name);

		return -ENOENT;
	}
#endif

    (*firmware_blob) = (uint8_t *) malloc(statbuf.st_size);
    if ((*firmware_blob) == NULL) {
        fclose(fwfile);
        goto no_mem;
    }

    *blob_len = statbuf.st_size;

    fread((*firmware_blob), *blob_len, 1, fwfile);

    fclose(fwfile);

    return 0;

no_file:
    userspace_wifi_error(context, NULL, -ENOENT, "Could not find firmware file '%s' in "
            "any of the standard locations.  Make sure you've installed the required "
            "firmware files.", file_name);
    return -ENOENT;

no_mem:
    userspace_wifi_error(context, NULL, -ENOENT, "Could not allocate memory to load "
            "firmware file '%s'", file_name);
    return -ENOMEM;

}

int userspace_wifi_init(struct userspace_wifi_context **context) {
    /* int status; */

    *context = (struct userspace_wifi_context *) malloc(sizeof(struct userspace_wifi_context));

    if (*context == NULL)
        return -1;

    memset(*context, 0, sizeof(struct userspace_wifi_context));

    (*context)->devs = NULL;
    (*context)->devs_cnt = 0;
    (*context)->service_device_count = 0;

    (*context)->load_firmware_file = &userspace_load_firmware_file;

    /*
    status = libusb_init(&(*context)->libusb_context);
    if (status < 0)
        return status;
        */

    pthread_mutex_init(&(*context)->libusb_mutex, NULL);

    (*context)->cmd_thread_enabled = true;
    pthread_mutex_init(&(*context)->cmd_mutex, NULL);
    pthread_mutex_init(&(*context)->cmd_wakeup_mutex, NULL);
    pthread_cond_init(&(*context)->cmd_wakeup_cond, NULL);
    pthread_create(&(*context)->cmd_thread, NULL, userspace_wifi_cmd_service_thread, (*context));

    pthread_mutex_init(&(*context)->led_ts_mutex, NULL);
    pthread_mutex_init(&(*context)->led_cond_mutex, NULL);
    pthread_cond_init(&(*context)->led_cond, NULL);
    (*context)->led_devs = NULL;
    (*context)->led_thread_enable = false;

    return 0;
}

void userspace_wifi_free(struct userspace_wifi_context *context) {
    if (context != NULL) {
        context->service_thread_enabled = false;

        if (context->devs != NULL) {
            libusb_free_device_list(context->devs, 1);
        }

        if (context->libusb_context != NULL)
            libusb_exit(context->libusb_context);

        if (context->service_thread_active) {
            pthread_join(context->async_service_thread, NULL);
        }

        free(context);
    }
}

int userspace_wifi_probe(struct userspace_wifi_context *context,
        struct userspace_wifi_probe_dev **devices) {
    struct userspace_wifi_probe_dev *probe_dev;
    int i, ret;
    struct libusb_device_descriptor desc;
    struct libusb_device_handle *handle;
    int probed_count = 0;

    if (context->devs != NULL)
        libusb_free_device_list(context->devs, 1);

    if (context->libusb_context != NULL)
        libusb_exit(context->libusb_context);

    libusb_init(&context->libusb_context);

    context->devs = NULL;

    *devices = NULL;

    context->devs_cnt = libusb_get_device_list(context->libusb_context, &(context->devs));

    if (context->devs_cnt <= 0)
        return context->devs_cnt;

    /* 
     * Scan via each of the userspace drivers
     */
    for (i = 0; context->devs[i]; ++i) {
        ret = libusb_get_device_descriptor(context->devs[i], &desc);

        if (ret != 0)
            continue;

        ret = libusb_open(context->devs[i], &handle);

        if (ret != 0)
            continue;

        /*
         * For each supported driver, probe until we get a match.
         * For each match, add it to our count and our linked list 
         */
        if (rt2800usb_probe_device(&desc, &probe_dev) > 0) {
            probe_dev->context = context;

            probe_dev->dev = context->devs[i];

            /*
             * Collect as much info about the device as we can, we need it to
             * identify grouped devices for some platforms 
             */
			probe_dev->usb_bus = libusb_get_bus_number(context->devs[i]);
            probe_dev->usb_port = libusb_get_port_number(context->devs[i]);
			probe_dev->usb_device = libusb_get_device_address(context->devs[i]);
    
            ret = libusb_get_port_numbers(context->devs[i], probe_dev->usb_bus_path, 8);
            if (ret > 0) {
                probe_dev->usb_bus_path_len = ret;
            }

            if (desc.iSerialNumber) {
                libusb_get_string_descriptor_ascii(handle, desc.iSerialNumber,
                        probe_dev->usb_serial, 64);
            }

            probe_dev->next = *devices;
            *devices = probe_dev;
            probe_dev = NULL;

            probed_count++;
        }

        libusb_close(handle);

    }

    return probed_count;
}

void userspace_wifi_free_probe(struct userspace_wifi_probe_dev *devices) {
    struct userspace_wifi_probe_dev *next;

    while (devices != NULL) {
        next = devices->next;

        if (devices->driver_name)
            free(devices->driver_name);
        if (devices->device_type)
            free(devices->device_type);

        free(devices);
        devices = next;
    }
}

void userspace_wifi_for_each_probe(struct userspace_wifi_context *context,
        struct userspace_wifi_probe_dev *devices,
		int (*cb)(struct userspace_wifi_context *, struct userspace_wifi_probe_dev *)) {
    struct userspace_wifi_probe_dev *next = devices;
    int r;

    while (next != NULL) {
        r = (*cb)(context, next);

        if (r)
            return;

        next = next->next;
    }
}

void userspace_wifi_handle_usbio(struct userspace_wifi_context *context) {
    context->service_thread_enabled = true;
    int r;

    while (context->service_thread_enabled) {
        r = libusb_handle_events_completed(context->libusb_context, NULL);

        if (r < 0) {
            userspace_wifi_error(context, NULL, r, "Handling USB IO queue failed: %s",
                    libusb_error_name(r));
            break;
        }
    }
}

int userspace_wifi_device_open(struct userspace_wifi_context *context,
        struct userspace_wifi_probe_dev *probedevice,
        struct userspace_wifi_dev **device) {
    int r;
   
    if (!context->service_thread_enabled) {
        context->service_thread_enabled = true;
        context->service_thread_active = true;
        pthread_create(&context->async_service_thread, NULL, userspace_wifi_service_thread, context);
    }

    r = (*(probedevice->open_device))(probedevice, device);

    if (r < 0) {
        userspace_wifi_error(context, *device, r, "Opening device failed");
        return r;
    }

#if 0
    if (!context->service_thread_active) {
        context->service_thread_enabled = true;
        context->service_thread_active = true;
        context->service_device_count++;

        pthread_create(&(context->async_service_thread), NULL, userspace_wifi_service_thread, context);
    }
#endif

    return r;
}

/*
 * Queue work to the end of the worker queue
 */
void userspace_wifi_queue_work(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *device,
        void (*callback)(struct userspace_wifi_context *context,
            struct userspace_wifi_dev *device,
            void *param), void *param) {

    struct userspace_wifi_command *cmd = 
        (struct userspace_wifi_command *) malloc(sizeof(struct userspace_wifi_command));

    cmd->next = NULL;
    cmd->device = device;
    cmd->callback = callback;
    cmd->param = param;

    pthread_mutex_lock(&context->cmd_mutex);

    cmd->id = context->work_id++;

    if (context->cmd_queue == NULL) {
        context->cmd_queue = cmd;
        context->cmd_queue_last = cmd;
    } else {
        context->cmd_queue_last->next = cmd;
        context->cmd_queue_last = cmd;
    }

    /* Signal the worker thread */
    pthread_cond_signal(&context->cmd_wakeup_cond);

    pthread_mutex_unlock(&context->cmd_mutex);

}

void _userspace_wifi_start_capture_cb(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *device, 
        void *param) {

    /*
     * TODO handle error and backpropagate
     */
    device->start_capture(device);
}

int userspace_wifi_device_start_capture(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *device) {
    userspace_wifi_queue_work(context, device, &_userspace_wifi_start_capture_cb, NULL);
    return 0;
}

void _userspace_wifi_stop_capture_cb(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *device, 
        void *param) {

    device->start_capture(device);
}

int userspace_wifi_device_stop_capture(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *device) {
    userspace_wifi_queue_work(context, device, &_userspace_wifi_stop_capture_cb, NULL);
    return 0;
}

struct _userspace_wifi_channel_param {
    int channel;
    enum nl80211_chan_width width;
};

void _userspace_wifi_channel_cb(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *device,
        void *param) {
    struct _userspace_wifi_channel_param *ch = (struct _userspace_wifi_channel_param *) param;
    int r;

    /*
     * TODO handle error and backpropagate
     */

    r = device->set_channel(device, ch->channel, ch->width);

    if (r < 0)
        userspace_wifi_error(context, device, r, "Setting channel %d:%d failed: %d / %s",
                ch->channel, ch->width, r, strerror(r));

    free(ch);
}

int userspace_wifi_device_set_channel(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *dev,
        int channel, enum nl80211_chan_width width) {
    struct _userspace_wifi_channel_param *p = 
        (struct _userspace_wifi_channel_param *) malloc(sizeof(struct _userspace_wifi_channel_param));

    if (p == NULL)
        return -ENOMEM;

    p->channel = channel;
    p->width = width;

    userspace_wifi_queue_work(context, dev, &_userspace_wifi_channel_cb, p);

    return 0;
}

void _userspace_wifi_led_on(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *device,
        void *param) {
    device->set_led(device, true);
}

void _userspace_wifi_led_off(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *device,
        void *param) {
    device->set_led(device, false);
}

int userspace_wifi_device_set_led(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *dev, bool enable) {
    if (enable)
        userspace_wifi_queue_work(context, dev, &_userspace_wifi_led_on, NULL);
    else
        userspace_wifi_queue_work(context, dev, &_userspace_wifi_led_off, NULL);

    return 0;
}

void *_userspace_wifi_led_thread(void *ctx) {
    struct userspace_wifi_context *context = (struct userspace_wifi_context *) ctx;

    struct userspace_wifi_dev_led *led;

    struct timeval now;
    struct timeval diff_ts;
    struct timeval sleep_ts;

    while (context->led_thread_enable) {
        sleep_ts.tv_sec = 0;
        sleep_ts.tv_usec = 0;

        diff_ts.tv_sec = 0;
        diff_ts.tv_usec = 0;

        pthread_mutex_lock(&context->led_ts_mutex);
        gettimeofday(&now, NULL);

        led = context->led_devs;

        while (led) {
            if (led->trigger_ts.tv_sec == 0) {
                led = led->next;
                continue;
            }

            /*
             * Did we miss the timer?
             */
            if (timercmp(&led->trigger_ts, &now, <=)) {
                /*
                 * Zero out the trigger
                 */
                led->trigger_ts.tv_sec = 0;

                userspace_wifi_device_set_led(context, led->dev, led->restore_state);

                led = led->next;
                continue;
            }

            /* 
             * Otherwise we're still waiting; Figure out when to wake up.  We want to find
             * the most likely next timer.
             */
            timersub(&led->trigger_ts, &now, &diff_ts);

            if (timercmp(&sleep_ts, &diff_ts, <)) {
                sleep_ts.tv_sec = diff_ts.tv_sec;
                sleep_ts.tv_usec = diff_ts.tv_usec;

                if (sleep_ts.tv_sec > 0) {
                    printf("something weird in sleep for device %d: %lu secs\n", led->dev->dev_id, sleep_ts.tv_sec);
                }
            }

            led = led->next;
        }
        pthread_mutex_unlock(&context->led_ts_mutex);

        /*
         * Sleep the shortest amount of time and try all the timers again without
         * waiting for a cond signal
         */
        if (sleep_ts.tv_sec != 0 || sleep_ts.tv_usec != 0) {
            sleep(sleep_ts.tv_sec);
            usleep(sleep_ts.tv_usec);
            continue;
        }

        /*
         * Otherwise we've handled all extant timers, sleep the thread until we get a
         * conditional kick
         */

        pthread_mutex_lock(&context->led_cond_mutex);
        pthread_cond_wait(&context->led_cond, &context->led_cond_mutex);
        pthread_mutex_unlock(&context->led_cond_mutex);
    }

    return NULL;
}

void _userspace_wifi_start_led_thread(struct userspace_wifi_context *context) {
    context->led_thread_enable = true;
    pthread_create(&context->led_thread, NULL, _userspace_wifi_led_thread, context);
    pthread_cond_signal(&context->led_cond);
}

void _userspace_wifi_kill_led_thread(struct userspace_wifi_context *context) {
    context->led_thread_enable = false;
    pthread_cond_signal(&context->led_cond);
    pthread_join(context->led_thread, NULL);
}

int userspace_wifi_device_enable_led_control(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *device) {

    struct userspace_wifi_dev_led *led =
        (struct userspace_wifi_dev_led *) malloc(sizeof(struct userspace_wifi_dev_led));

    if (led == NULL)
        return -ENOMEM;

    memset(led, 0, sizeof(struct userspace_wifi_dev_led));

    device->led_control = led;
    led->dev = device;
    led->next = NULL;

    pthread_mutex_lock(&context->led_ts_mutex);
    led->next = context->led_devs;
    context->led_devs = led;

    if (!context->led_thread_enable)
        _userspace_wifi_start_led_thread(context);

    pthread_mutex_unlock(&context->led_ts_mutex);

    return 0;
}

void userspace_wifi_device_disable_led_control(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *device) {

    struct userspace_wifi_dev_led *led = NULL, *removal = NULL;

    pthread_mutex_lock(&context->led_ts_mutex);
    led = context->led_devs;

    if (led == device->led_control) {
        context->led_devs = led->next;
        removal = led;
    } else {
        while (led) {
            if (led->next == device->led_control) {
                led->next = device->led_control->next;
                removal = led;
                break;
            }

            led = led->next;
        }
    }

    if (!removal) {
        pthread_mutex_unlock(&context->led_ts_mutex);
        return;
    }

    free(removal);
    device->led_control = NULL;

    if (context->led_devs == NULL)
        _userspace_wifi_kill_led_thread(context);

    pthread_mutex_unlock(&context->led_ts_mutex);
}

int userspace_wifi_device_blink_led(struct userspace_wifi_context *context,
        struct userspace_wifi_dev *device,
        unsigned int duration_us, bool restore_state,
        bool extend) {

    struct timeval add_ts = {
        .tv_sec = 0,
        .tv_usec = duration_us
    };
    struct timeval now;

    if (device->led_control == NULL)
        return -ENODEV;

    pthread_mutex_lock(&context->led_ts_mutex);

    /* 
     * Only toggle the LED if we're not in a timer
     */
    if (device->led_control->trigger_ts.tv_sec == 0) {
        userspace_wifi_device_set_led(context, device, !restore_state);
    }

    /*
     * If we're extending the timer or there is no timer
     */
    if (extend || device->led_control->trigger_ts.tv_sec == 0) {
        gettimeofday(&now, NULL);
        timeradd(&now, &add_ts, &device->led_control->trigger_ts);
        device->led_control->restore_state = restore_state;

        /*
         * Wake up the thread if it isn't already in a processing state
         */
        pthread_cond_signal(&context->led_cond);
    }

    pthread_mutex_unlock(&context->led_ts_mutex);

    return 0;
}

