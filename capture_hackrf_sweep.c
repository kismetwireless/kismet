/*
    This file is part of Kismet and of HackRF
   
    HackRF sweep components based on hackrf_sweep.c from the HackRF
    project, 

    Copyright 2016 Dominic Spill <dominicgs@gmail.com>
    Copyright 2016 Mike Walters <mike@flomp.net>
    Copyright 2017 Michael Ossmann <mike@ossmann.com>

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

/* capture_hackrf_sweep
 *
 * Capture binary which interfaces to the HackRF radio to gather spectrum
 * measurement which is then reported to Kismet via the SPECTRUM kv pairs.
 *
 * This binary only needs to run as root if the hackrf device is not writeable
 * by the user (as configured in udev); user access is assumed.
 *
 */

#include <getopt.h>
#include <pthread.h>
#include <fcntl.h>

#include <sched.h>

/* According to POSIX.1-2001, POSIX.1-2008 */
#include <sys/select.h>

/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include <unistd.h>
#include <errno.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <ifaddrs.h>

#include "config.h"

#include "simple_datasource_proto.h"
#include "capture_framework.h"


#ifndef BUILD_CAPTURE_HACKRF_SWEEP

/* If the required libraries (hackrf and fftw3) are not available, build the 
 * capture binary, but only return errors.
 */


int open_callback(kis_capture_handler_t *, uint32_t, char *,
        char *msg, uint32_t *, char **, simple_cap_proto_frame_t *,
        cf_params_interface_t **, cf_params_spectrum_t **) {

    snprintf(msg, STATUS_MAX, "Kismet was not compiled with the hackrf libraries, "
            "cannot use hackrf_sweep; check the results of ./configure or consult "
            "your distribution documentation"); 
    return -1;
}

int probe_callback(kis_capture_handler_t *, uint32_t, char *,
        char *msg, char **, simple_cap_proto_frame_t *,
        cf_params_interface_t **, cf_params_spectrum_t **) {

    snprintf(msg, STATUS_MAX, "Kismet was not compiled with the hackrf libraries, "
            "cannot use hackrf_sweep; check the results of ./configure or consult "
            "your distribution documentation"); 
    return -1;
}

int list_callback(kis_capture_handler_t *, uint32_t,
        char *, char ***interfaces, char ***flags) {

    *interfaces = NULL;
    *flags = NULL;
    return 0;
}

void capture_thread(kis_capture_handler_t *) {
    return;
}

#else

#include <libhackrf/hackrf.h>
#include <fftw3.h>
#include <inttypes.h>
#include <math.h>

/* Copied directly from hackrf_sweep.c */
#define FD_BUFFER_SIZE (8*1024)

#define FREQ_ONE_MHZ (1000000ull)

#define FREQ_MIN_MHZ (0)    /*    0 MHz */
#define FREQ_MAX_MHZ (7250) /* 7250 MHz */

#define DEFAULT_SAMPLE_RATE_HZ (20000000) /* 20MHz default sample rate */
#define DEFAULT_BASEBAND_FILTER_BANDWIDTH (15000000) /* 5MHz default */

#define TUNE_STEP (DEFAULT_SAMPLE_RATE_HZ / FREQ_ONE_MHZ)
#define OFFSET 7500000

#define BLOCKS_PER_TRANSFER 16
#define THROWAWAY_BLOCKS 2

#if defined _WIN32
	#define sleep(a) Sleep( (a*1000) )
#endif

uint32_t num_samples = SAMPLES_PER_BLOCK;
int num_ranges = 0;
uint16_t frequencies[MAX_SWEEP_RANGES*2];
int step_count;

static float TimevalDiff(const struct timeval *a, const struct timeval *b) {
   return (a->tv_sec - b->tv_sec) + 1e-6f * (a->tv_usec - b->tv_usec);
}

int parse_u32(char* s, uint32_t* const value) {
	uint_fast8_t base = 10;
	char* s_end;
	uint64_t ulong_value;

	if( strlen(s) > 2 ) {
		if( s[0] == '0' ) {
			if( (s[1] == 'x') || (s[1] == 'X') ) {
				base = 16;
				s += 2;
			} else if( (s[1] == 'b') || (s[1] == 'B') ) {
				base = 2;
				s += 2;
			}
		}
	}

	s_end = s;
	ulong_value = strtoul(s, &s_end, base);
	if( (s != s_end) && (*s_end == 0) ) {
		*value = (uint32_t)ulong_value;
		return HACKRF_SUCCESS;
	} else {
		return HACKRF_ERROR_INVALID_PARAM;
	}
}

int parse_u32_range(char* s, uint32_t* const value_min, uint32_t* const value_max) {
	int result;

	char *sep = strchr(s, ':');
	if (!sep)
		return HACKRF_ERROR_INVALID_PARAM;

	*sep = 0;

	result = parse_u32(s, value_min);
	if (result != HACKRF_SUCCESS)
		return result;
	result = parse_u32(sep + 1, value_max);
	if (result != HACKRF_SUCCESS)
		return result;

	return HACKRF_SUCCESS;
}

volatile bool do_exit = false;

FILE* fd = NULL;
volatile uint32_t byte_count = 0;
volatile uint64_t sweep_count = 0;

struct timeval time_start;
struct timeval t_start;
struct timeval time_stamp;

bool amp = false;
uint32_t amp_enable;

bool antenna = false;
uint32_t antenna_enable;

bool binary_output = false;
bool ifft_output = false;
bool one_shot = false;
volatile bool sweep_started = false;

int fftSize = 20;
double fft_bin_width;
fftwf_complex *fftwIn = NULL;
fftwf_complex *fftwOut = NULL;
fftwf_plan fftwPlan = NULL;
fftwf_complex *ifftwIn = NULL;
fftwf_complex *ifftwOut = NULL;
fftwf_plan ifftwPlan = NULL;
uint32_t ifft_idx = 0;
float* pwr;
float* window;

float logPower(fftwf_complex in, float scale)
{
	float re = in[0] * scale;
	float im = in[1] * scale;
	float magsq = re * re + im * im;
	return log2f(magsq) * 10.0f / log2(10.0f);
}


int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid, simple_cap_proto_frame_t *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    char *placeholder = NULL;
    int placeholder_len;
    char *interface = NULL;
    char *serial = NULL;
    char errstr[STATUS_MAX];
    hackrf_device_list_t *list;
    int x;

    *ret_spectrum = cf_params_spectrum_new();
    *ret_interface = NULL;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    // All hackrfsweeps use 'hackrf' as the interface
    if (strcmp(interface, "hackrf") != 0) {
        snprintf(msg, STATUS_MAX, "Doesn't look like a hackrf");
        return 0;
    }


    if (hackrf_init() != HACKRF_SUCCESS) {
        snprintf(msg, STATUS_MAX, "hackrf_sweep could not initialize libhackrf");
        return 0;
    }

    list = hackrf_device_list();

    if (list == NULL) {
        return 0;
    }

    if (list->devicecount == 0)
        return 0;


    // Figure out if we have a serial #
    if ((placeholder_len = cf_find_flag(&placeholder, "serial", definition)) > 0) {
        serial = strndup(placeholder, placeholder_len);
    } 

    if (serial == NULL && list->devicecount != 1) {
        snprintf(msg, STATUS_MAX, "multiple hackrf devices found, specify serial number");
        hackrf_device_list_free(list);
        hackrf_exit();
        return 0;
    }

    for (x = 0; x < list->devicecount; x++) {
        if (strcmp(serial, list->serial_numbers[x]) == 0) {
            unsigned long s;
            if (sscanf(serial, "%lx", &s) == 1) {
                /* Make a spoofed, but consistent, UUID based on the adler32 of the 
                 * capture name and the serial of the device */
                snprintf(errstr, STATUS_MAX, "%08X-0000-0000-%04lX-%12lX",
                        adler32_csum((unsigned char *) "kismet_cap_hackrf_sweep", 
                            strlen("kismet_cap_hackrf_sweep")) & 0xFFFFFFFF,
                        (s >> 48) & 0xFFFF, s & 0xFFFFFFFFFFFF);
                *uuid = strdup(errstr);

                hackrf_device_list_free(list);
                hackrf_exit();

                return 1;
            }

        }

    }

    hackrf_device_list_free(list);
    hackrf_exit();

    return 0;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid, simple_cap_proto_frame_t *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {

    return 0;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno,
        char *msg, char ***interfaces, char ***flags) {

    char errstr[STATUS_MAX];
    hackrf_device_list_t *list;

    *interfaces = NULL;
    *flags = NULL;

    int x = 0;

    if (hackrf_init() != HACKRF_SUCCESS) {
        snprintf(msg, STATUS_MAX, "hackrf_sweep could not initialize libhackrf");
        return 0;
    }

    list = hackrf_device_list();

    if (list == NULL) {
        return 0;
    }

    if (list->devicecount == 0)
        return 0;

    *interfaces = (char **) malloc(sizeof(char *) * list->devicecount);
    *flags = (char **) malloc(sizeof(char *) * list->devicecount);

    for (x = 0; x < list->devicecount; x++) {
        *interfaces[x] = strdup("hackrf");

        snprintf(errstr, STATUS_MAX, "serial=%s", list->serial_numbers[x]);
        *flags[x] = strdup(errstr);
    }

    x = list->devicecount;

    hackrf_device_list_free(list);

    hackrf_exit();

    return x;
}

void capture_thread(kis_capture_handler_t *caph) {


}

#endif


int main(int argc, char *argv[]) {
#if 0
    local_wifi_t local_wifi = {
        .pd = NULL,
        .interface = NULL,
        .cap_interface = NULL,
        .datalink_type = -1,
        .override_dlt = -1,
        .use_mac80211_vif = 1,
        .use_mac80211_channels = 1,
        .mac80211_cache = NULL,
        .mac80211_handle = NULL,
        .mac80211_family = NULL,
        .seq_channel_failure = 0,
        .reset_nm_management = 0,
    };
#endif

    kis_capture_handler_t *caph = cf_handler_init("hackrfsweep");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

#if 0
    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &local_wifi);
#endif

    /* Set the callback for opening  */
    cf_handler_set_open_cb(caph, open_callback);

    /* Set the callback for probing an interface */
    cf_handler_set_probe_cb(caph, probe_callback);

    /* Set the list callback */
    cf_handler_set_listdevices_cb(caph, list_callback);

    /* Set the capture thread */
    cf_handler_set_capture_cb(caph, capture_thread);

    if (cf_handler_parse_opts(caph, argc, argv) < 1) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    cf_handler_loop(caph);

    cf_handler_shutdown(caph);

    cf_handler_free(caph);

    return 1;
}

