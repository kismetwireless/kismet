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

#include "config.h"
#include "simple_ringbuf_c.h"
#include <pthread.h>
#include <sys/select.h>

#ifdef SYS_LINUX
#define _GNU_SOURCE 1
#endif

#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <math.h>

#ifdef HAVE_CAPABILITY
#include <sys/capability.h>
#include <sys/prctl.h>
#include <pwd.h>
#include <grp.h>
#endif

#ifdef SYS_LINUX
#include <linux/sched.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

#include <limits.h>

#include "capture_framework.h"

#ifdef SYS_LINUX
#include <sys/utsname.h>
#endif
#include "kis_external_packet.h"
#include "kis_endian.h"
#include "remote_announcement.h"

#include "mpack/mpack.h"

#include "version.h"

int unshare(int);

/* Default: no per-binary suffix.  See capture_framework.h. */
const char *cf_version_extra = NULL;

void cf_version_string(char *buf, size_t len) {
    snprintf(buf, len, "%s.%s.%s-%s%s%s",
            VERSION_MAJOR, VERSION_MINOR, VERSION_TINY, VERSION_GIT_COMMIT,
            cf_version_extra == NULL ? "" : "-",
            cf_version_extra == NULL ? "" : cf_version_extra);
}

uint32_t adler32_append_csum(uint8_t *in_buf, size_t in_len, uint32_t cs) {
    size_t i;
    uint32_t ls1 = cs & 0xFFFF;
    uint32_t ls2 = (cs >> 16) & 0xFFFF;

    const uint32_t *buf = (const uint32_t *) in_buf;
	const uint8_t *sub_buf = NULL;

    if (in_len < 4)
        return 0;

    for (i = 0; i < (in_len - 4); i += 4, buf++) {
        ls2 += (4 * (ls1 + ((*buf) & 0xFF))) +
            (3 * ((*buf >> 8) & 0xFF)) +
            (2 * ((*buf >> 16) & 0xFF)) +
            ((*buf >> 24) & 0xFF);

        ls1 += ((*buf >> 24) & 0xFF) +
            ((*buf >> 16) & 0xFF) +
            ((*buf >> 8) & 0xFF) +
            ((*buf) & 0xFF);
    }

    switch (in_len - i) {
        case 4:
            ls1 += ((*buf) & 0xFF);
            ls2 += ls1;
            ls1 += ((*buf >> 8) & 0xFF);
            ls2 += ls1;
            ls1 += ((*buf >> 16) & 0xFF);
            ls2 += ls1;
            ls1 += ((*buf >> 24) & 0xFF);
            ls2 += ls1;
            break;
        case 3:
			sub_buf = (uint8_t *) buf;
            // ls1 += ((*buf) & 0xFF);
			ls1 += sub_buf[0];
            ls2 += ls1;
            // ls1 += ((*buf >> 8) & 0xFF);
			ls1 += sub_buf[1];
            ls2 += ls1;
            // ls1 += ((*buf >> 16) & 0xFF);
			ls1 += sub_buf[2];
            ls2 += ls1;
            break;
        case 2:
			sub_buf = (uint8_t *) buf;
            // ls1 += ((*buf) & 0xFF);
			ls1 += sub_buf[0];
            ls2 += ls1;
            // ls1 += ((*buf >> 8) & 0xFF);
			ls1 += sub_buf[1];
            ls2 += ls1;
            break;
        case 1:
			sub_buf = (uint8_t *) buf;
            // ls1 += ((*buf) & 0xFF);
			ls1 += sub_buf[0];
            ls2 += ls1;
            break;
    }

    return (ls1 & 0xffff) + (ls2 << 16);
}

uint32_t adler32_csum(uint8_t *in_buf, size_t in_len) {
    return adler32_append_csum(in_buf, in_len, 0);
}

size_t cf_system_firmware_dirs(char dirs[CF_FIRMWARE_MAX_DIRS][CF_FIRMWARE_PATH_LEN]) {
#ifdef SYS_LINUX
    struct utsname un;
    char custom[CF_FIRMWARE_PATH_LEN * 2];
    bool release = false;
    size_t n = 0;
    FILE *f;

    /* A release with a path separator can't be part of a directory name */
    if (uname(&un) == 0 && un.release[0] != 0 && strchr(un.release, '/') == NULL &&
            strcmp(un.release, "..") != 0 && strcmp(un.release, ".") != 0)
        release = true;

    /* Set on the kernel command line or by the distribution; empty if unset */
    if ((f = fopen("/sys/module/firmware_class/parameters/path", "r")) != NULL) {
        if (fgets(custom, sizeof(custom), f) != NULL) {
            custom[strcspn(custom, "\n")] = 0;

            if (custom[0] == '/' && strlen(custom) < CF_FIRMWARE_PATH_LEN &&
                    strstr(custom, "..") == NULL)
                snprintf(dirs[n++], CF_FIRMWARE_PATH_LEN, "%s", custom);
        }

        fclose(f);
    }

    if (release)
        snprintf(dirs[n++], CF_FIRMWARE_PATH_LEN, "/lib/firmware/updates/%s", un.release);
    snprintf(dirs[n++], CF_FIRMWARE_PATH_LEN, "/lib/firmware/updates");
    if (release)
        snprintf(dirs[n++], CF_FIRMWARE_PATH_LEN, "/lib/firmware/%s", un.release);
    snprintf(dirs[n++], CF_FIRMWARE_PATH_LEN, "/lib/firmware");

    return n;
#else
    (void) dirs;
    return 0;
#endif
}

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
    char *colonpos, *flagpos, *comma, *equals, *quote, *equote;

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
        if (strncasecmp(flag, flagpos, (equals - flagpos)) == 0 &&
                strlen(flag) == (equals - flagpos)) {
            /* Find the next comma */
            comma = strstr(equals, ",");
            /* Find the next quote */
            quote = strstr(equals, "\"");

            /* If it's null we're the last flag, so use the total length after
             * the equals as the value */
            if (comma == NULL && quote == NULL) {
                *ret_value = equals + 1;
                return strlen(equals) - 1;
            }

            /* If we've got a quote inside the string, before the terminating comma,
             * find the next quote and return that as the length */
            if (quote != NULL) {
                if ((comma != NULL && quote < comma) || comma == NULL) {
                    equote = strstr(quote + 1, "\"");

                    /* unterminated quote */
                    if (equote == NULL) {
                        *ret_value = NULL;
                        return -1;
                    }

                    *ret_value = quote + 1;
                    return (equote - (quote + 1));
                } else {
                    /* */
                }
            }

            /* Otherwise return until the next comma */
            *ret_value = equals + 1;
            return (comma - (equals + 1));
        }

        /* Otherwise find the next comma */
        comma = strstr(flagpos, ",");
        /* Find the next quote */
        quote = strstr(equals, "\"");

        /* No comma, no more flags, nothing to find */
        if (comma == NULL && quote == NULL) {
            *ret_value = NULL;
            return 0;
        }

        /* If we have a quote */
        if (quote != NULL) {
            /* And it contains the current flag */
            if ((comma != NULL && quote < comma) || comma == NULL) {
                /* Jump to the end of the quote */
                equote = strstr(quote + 1, "\"");

                if (equote == NULL) {
                    *ret_value = NULL;
                    return -1;
                }

                /* Find a trailing comma */
                comma = strstr(equote, ",");

                /* bail if this was the last */
                if (comma == NULL) {
                    *ret_value = NULL;
                    return 0;
                }
            }
        }

        /* Jump past the flagpos */
        flagpos = comma + 1;
    }

    *ret_value = NULL;
    return 0;
}


int cf_count_flag(const char *flag, char *definition) {
    int n_flags = 0;
    char *placeholder = NULL;
    char *last_holder = definition;
    int len;

    do {
        len = cf_find_flag(&placeholder, flag, last_holder);

        if (len == 0 || placeholder == NULL)
            break;

        n_flags++;
        last_holder = placeholder + len;
    } while (placeholder != NULL);

    return n_flags;
}


int cf_split_list(char *in_str, size_t in_sz, char in_split, char ***ret_splitlist,
        size_t *ret_splitlist_sz) {

    char *start = in_str;
    char *end = in_str;
    size_t num_fields = 0;

    *ret_splitlist = NULL;
    *ret_splitlist_sz = 0;

    /* Count all the fields */
    while ((size_t) (end - in_str) <= in_sz) {
        if (*start == in_split)
            start++;

        if (*end == in_split || *end == 0 || end == in_str + in_sz) {
            if (end != start) {
                num_fields++;
            }

            start = end + 1;
            end = start;
        }

        end++;
    }

    if (num_fields == 1) {
        *ret_splitlist = (char **) malloc(sizeof(char *));

        if (*ret_splitlist == NULL)
            return -1;

        (*ret_splitlist)[0] = strndup(in_str, in_sz);
        *ret_splitlist_sz = 1;
        return 0;
    }

    *ret_splitlist = (char **) malloc(sizeof(char *) * num_fields);

    start = in_str;
    end = in_str;

    *ret_splitlist_sz = num_fields;

    num_fields = 0;
    while ((size_t) (end - in_str) <= in_sz && num_fields <= *ret_splitlist_sz) {
        if (*start == in_split)
            start++;

        if (*end == in_split || *end == 0 || end == in_str + in_sz) {
            if (end != start) {
                (*ret_splitlist)[num_fields++] = strndup(start, end - start);
            }

            start = end + 1;
            end = start;
        }

        end++;
    }

    return 0;
}

size_t cf_append_unique_chans(char **in_list1, size_t in_list1_sz,
        char **in_list2, size_t in_list2_sz, char ***ret_list) {
    size_t max_sz = in_list1_sz + in_list2_sz;
    size_t i, n, offt;
    int skip = 0;

    if (max_sz == 0) {
        *ret_list = NULL;
        return 0;
    }

    /* Make a max-size list; we only lose a few char* sizes so we don't care */
    *ret_list = (char **) malloc(sizeof(char *) * max_sz);

    if (*ret_list == NULL)
        return 0;

    /* dupe all of the first list */
    for (i = 0; i < in_list1_sz; i++) {
        (*ret_list)[i] = strdup(in_list1[i]);
    }

    offt = in_list1_sz;

    /* Dupe uniques of the second list */
    for (i = 0; i < in_list2_sz; i++) {
        skip = 0;
        for (n = 0; n < in_list1_sz; n++) {
            if (strcasecmp(in_list1[n], in_list2[i]) == 0) {
                skip = 1;
                break;
            }
        }

        if (skip)
            continue;

        (*ret_list)[offt++] = strdup(in_list2[i]);
    }

    return offt;
}

#define CF_NS_PER_SEC               1000000000ULL

/* Shortest and longest dwell on a channel */
#define CF_HOP_MIN_DWELL_NS         50000000ULL
#define CF_HOP_MAX_DWELL_NS         (86400ULL * CF_NS_PER_SEC)

/* Clock sync: a burst of exchanges, keeping the one with the shortest round trip */
#define CF_SYNC_BURST               5
#define CF_SYNC_BURST_SPACING_NS    25000000ULL
#define CF_SYNC_BURST_WAIT_NS       500000000ULL
#define CF_SYNC_MIN_INTERVAL_NS     (10ULL * CF_NS_PER_SEC)
#define CF_SYNC_MAX_INTERVAL_NS     (120ULL * CF_NS_PER_SEC)
/* A sync this far from the prediction is a clock step: start the estimate over */
#define CF_SYNC_STEP_NS             50000000LL
#define CF_SYNC_HISTORY             8
#define CF_SYNC_DRIFT_MIN_SPAN_NS   (30ULL * CF_NS_PER_SEC)
#define CF_SYNC_MAX_DRIFT_PPB       500000LL
/* Clock values past 2^62 ns (2116) are refused */
#define CF_SYNC_MAX_CLOCK_NS        (1ULL << 62)
/* Drift is applied over at most this long since the last sync */
#define CF_SYNC_MAX_DRIFT_SPAN_US   (1LL << 40)

#define CF_SWITCH_WINDOWS           8

struct cf_switch_window {
    _Atomic unsigned int seq;
    _Atomic uint64_t start_ns;
    _Atomic uint64_t end_ns;
};

struct cf_switch_stats {
    uint64_t total;
    uint32_t count;
    uint64_t sum_us;
    uint32_t min_us;
    uint32_t max_us;
    /* smoothed duration, for starting a synced switch early */
    uint64_t ewma_ns;
};

struct cf_hop_timing {
    struct cf_switch_stats chan;
    struct cf_switch_stats band;
    int band_known;
    unsigned int last_band;
    uint64_t missed;
    uint64_t failed;
    uint64_t next_report_ns;
    /* last channel tuned, so a synced source rejoining the schedule skips a no-op switch */
    char last_chan[64];
};

struct cf_hop_clock {
    int state;

    /* server realtime = local monotonic + offset, plus drift since ref */
    int64_t offset_ns;
    int64_t drift_ppb;
    uint64_t ref_mono_ns;
    uint32_t sync_err_us;

    unsigned int burst_sent;
    uint64_t burst_start_ns;
    uint64_t next_req_ns;
    uint64_t burst_done_ns;
    int best_valid;
    uint64_t best_rtt_ns;
    int64_t best_offset_ns;
    uint64_t best_mono_ns;

    uint64_t next_sync_ns;
    uint64_t interval_ns;

    unsigned int hist_n;
    uint64_t hist_mono[CF_SYNC_HISTORY];
    int64_t hist_offset[CF_SYNC_HISTORY];
    uint64_t hist_rtt[CF_SYNC_HISTORY];
};

/* Keeps SIGCHLD off SIG_DFL, which macOS discards at generation even when
 * blocked, so sigwait never saw it; and off SIG_IGN */
static void cf_sigchld_noop(int sig) {
    (void) sig;
}

/* Written once, then only read (sigwait in the signal thread) */
static sigset_t cf_core_signal_mask;
static pthread_once_t cf_core_signal_once = PTHREAD_ONCE_INIT;

static void cf_core_signal_mask_init(void) {
    sigemptyset(&cf_core_signal_mask);
    sigaddset(&cf_core_signal_mask, SIGALRM);
    sigaddset(&cf_core_signal_mask, SIGQUIT);
    sigaddset(&cf_core_signal_mask, SIGCHLD);
    sigaddset(&cf_core_signal_mask, SIGPIPE);
}

/* Blocks the core set in the calling thread, so every thread it starts later
 * leaves those signals to the signal thread's sigwait; a thread that didn't
 * block them took every SIGCHLD and the reaper never ran.  SIGCHLD gets a
 * handler unless the helper set its own: an inherited SIG_IGN reaps children
 * itself, so waitpid fails with ECHILD.  SIGINT and SIGTERM keep their default
 * action. */
static void cf_block_core_signals(void) {
    struct sigaction sa;

    pthread_once(&cf_core_signal_once, cf_core_signal_mask_init);
    pthread_sigmask(SIG_BLOCK, &cf_core_signal_mask, NULL);

    if (sigaction(SIGCHLD, NULL, &sa) == 0 && !(sa.sa_flags & SA_SIGINFO) &&
            (sa.sa_handler == SIG_DFL || sa.sa_handler == SIG_IGN)) {
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = cf_sigchld_noop;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        sigaction(SIGCHLD, &sa, NULL);
    }
}

kis_capture_handler_t *cf_handler_init(const char *in_type) {
    kis_capture_handler_t *ch;
    pthread_mutexattr_t mutexattr;
    pthread_condattr_t condattr;

    /* Before any helper or framework thread exists */
    cf_block_core_signals();

    ch = (kis_capture_handler_t *) malloc(sizeof(kis_capture_handler_t));

    if (ch == NULL)
        return NULL;

    ch->last_ping = time(0);
    ch->seqno = 1;

    /* Shutdown signals these when set */
    ch->monitor_pid = 0;
    ch->child_pid = 0;

    ch->capsource_type = strdup(in_type);

    ch->remote_capable = 1;

    ch->remote_host = NULL;
    ch->remote_port = 0;

    ch->use_tcp = 0;
    ch->remote_rx_valid = 0;
    ch->use_ipc = 0;
    ch->use_ws = 0;

#ifdef HAVE_LIBWEBSOCKETS
    ch->lwscontext = NULL;
    ch->lwsvhost = NULL;
    ch->lwsprotocol = NULL;
    ch->lwsring = NULL;
    ch->lwstail = 0;
    ch->lwswake = 0;
    ch->lwsclientwsi = NULL;
    ch->lwsestablished = 0;
    ch->lwsusessl = 0;
    ch->lwssslcapath = NULL;
    ch->lwsuri = NULL;
    ch->lwsuuid = NULL;
#endif

	ch->announced_uuid = NULL;
    ch->source_label[0] = 0;

    ch->cli_sourcedef = NULL;

    ch->in_fd = -1;
    ch->out_fd = -1;
    ch->tcp_fd = -1;

    /* Disable retry by default */
    ch->remote_retry = 0;

    /* Disable daemon mode by default */
    ch->daemonize = 0;

    /* Zero the GPS */
    ch->gps_fixed_lat = 0;
    ch->gps_fixed_lon = 0;
    ch->gps_fixed_alt = 0;
    ch->gps_name = NULL;

    ch->in_ringbuf = NULL;
    ch->out_ringbuf = NULL;

    ch->ipc_list = NULL;

    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(ch->out_ringbuf_lock), &mutexattr);

    pthread_cond_init(&(ch->out_ringbuf_flush_cond), NULL);
    pthread_mutex_init(&(ch->out_ringbuf_flush_cond_mutex), NULL);

    if (pipe(ch->out_ringbuf_wake) == 0) {
        fcntl(ch->out_ringbuf_wake[0], F_SETFL,
                fcntl(ch->out_ringbuf_wake[0], F_GETFL, 0) | O_NONBLOCK);
        fcntl(ch->out_ringbuf_wake[1], F_SETFL,
                fcntl(ch->out_ringbuf_wake[1], F_GETFL, 0) | O_NONBLOCK);
        fcntl(ch->out_ringbuf_wake[0], F_SETFD, FD_CLOEXEC);
        fcntl(ch->out_ringbuf_wake[1], F_SETFD, FD_CLOEXEC);
    } else {
        ch->out_ringbuf_wake[0] = -1;
        ch->out_ringbuf_wake[1] = -1;
    }
    ch->out_ringbuf_wake_armed = 0;

    ch->out_ctl_dropped = 0;
    ch->out_ctl_dropped_reported = 0;
    ch->out_ctl_drop_log_ns = 0;
    ch->out_ctl_reporting = 0;

    ch->shutdown = 0;
    ch->spindown = 0;

    ch->close_grace_ms = 0;
    ch->close_requested = 0;
    ch->close_deadline_ms = 0;

    pthread_mutex_init(&(ch->handler_lock), &mutexattr);

    ch->listdevices_cb = NULL;
    ch->probe_cb = NULL;
    ch->open_cb = NULL;
    ch->unknown_cb = NULL;

    ch->chantranslate_cb = NULL;
    ch->chanfree_cb = NULL;
    ch->chancontrol_cb = NULL;

    ch->spectrumconfig_cb = NULL;

    ch->capture_cb = NULL;

    ch->userdata = NULL;

    ch->capture_running = 0;
    ch->capture_live = 0;
    ch->signal_live = 0;
    ch->hop_live = 0;
    ch->capture_exit_timed_out = 0;
    ch->signal_exit_timed_out = 0;
    ch->hop_exit_timed_out = 0;
    ch->exit_deadline_ns = 0;
    ch->shutdown_done = 0;
    ch->shutdown_busy = 0;

    /* Exit waits run on the monotonic clock where the platform has it */
    ch->thread_exit_clock = CLOCK_REALTIME;
    pthread_condattr_init(&condattr);
#if defined(__linux__)
    if (pthread_condattr_setclock(&condattr, CLOCK_MONOTONIC) == 0)
        ch->thread_exit_clock = CLOCK_MONOTONIC;
#endif
    pthread_mutex_init(&(ch->thread_exit_lock), NULL);
    pthread_cond_init(&(ch->thread_exit_cond), &condattr);
    pthread_condattr_destroy(&condattr);
    ch->ipcthread_running = 0;
    ch->ipcthread_stop = 0;
    ch->hopping_running = 0;
	ch->signal_running = 0;

    ch->channel = NULL;
    ch->channel_hop_list = NULL;
    ch->custom_channel_hop_list = NULL;
    ch->channel_hop_list_sz = 0;
    ch->channel_hop_shuffle = 0;
    ch->channel_hop_shuffle_spacing = 1;
    ch->channel_hop_rate = 0;
    ch->channel_hop_offset = 0;
    ch->channel_hop_failure_list = NULL;
    ch->channel_hop_failure_list_sz = 0;
    ch->max_channel_hop_rate = 0;

    ch->hop_generation = 0;
    ch->chanband_cb = NULL;
    ch->hop_sync = 0;
    ch->hop_sync_epoch_ns = 0;
    ch->hop_report_ms = 0;
    ch->env_report_ms = 0;
    ch->env_last_report_ms = 0;
    ch->hop_clock = (struct cf_hop_clock *) calloc(1, sizeof(struct cf_hop_clock));
    ch->hop_timing = (struct cf_hop_timing *) calloc(1, sizeof(struct cf_hop_timing));
    ch->switch_windows =
        (struct cf_switch_window *) calloc(CF_SWITCH_WINDOWS, sizeof(struct cf_switch_window));
    atomic_init(&ch->switch_window_pos, 0);
    atomic_init(&ch->switch_busy_start_ns, 0);
    atomic_init(&ch->switch_last_end_ns, 0);

    ch->verbose = 0;

    return ch;
}

#ifdef HAVE_LIBWEBSOCKETS
static const struct lws_protocols kismet_lws_protocols[] = {
    {"kismet-remote", ws_remotecap_broker, 0, 0},
    {NULL, NULL, 0, 0}
};
#endif

void cf_set_remote_capable(kis_capture_handler_t *caph, int in_capable) {
    caph->remote_capable = in_capable;
}

/* Wake cf_handler_loop() out of select(); a full pipe already has a wakeup pending */
static void cf_handler_wake_loop(kis_capture_handler_t *caph) {
    uint8_t b = 0;
    ssize_t r;

    if (caph->out_ringbuf_wake[1] < 0)
        return;

    r = write(caph->out_ringbuf_wake[1], &b, 1);
    (void) r;
}

/* Only wake a loop parked in select, so a busy source costs one write per loop
 * pass instead of one per packet */
static void cf_handler_wake_commit(kis_capture_handler_t *caph) {
    if (__atomic_exchange_n(&caph->out_ringbuf_wake_armed, 0, __ATOMIC_SEQ_CST))
        cf_handler_wake_loop(caph);
}

/* With the mutex held, so a waiter that checked the ring under it can't miss it */
static void cf_handler_signal_flush(kis_capture_handler_t *caph) {
    pthread_mutex_lock(&(caph->out_ringbuf_flush_cond_mutex));
    pthread_cond_broadcast(&(caph->out_ringbuf_flush_cond));
    pthread_mutex_unlock(&(caph->out_ringbuf_flush_cond_mutex));
}

static void cf_unlock_mutex_cleanup(void *arg) {
    pthread_mutex_unlock((pthread_mutex_t *) arg);
}

/* How long shutdown waits for a cancelled capture thread to leave, at least */
#define CF_CAPTURE_EXIT_WAIT_MS 1000

/* The capture thread is cancelled asynchronously.  Cancel it only while holding
 * both framework locks so it can't die owning one, and only while it is still
 * running: a finished thread clears capture_running under the same locks before
 * it exits.  Lock order is handler_lock -> out_ringbuf_lock. */
static void cf_cancel_capture_thread(kis_capture_handler_t *caph) {
    pthread_mutex_lock(&(caph->handler_lock));
    pthread_mutex_lock(&(caph->out_ringbuf_lock));

    if (caph->capture_running) {
        /* A capture callback shutting its own source down returns on its own */
        if (!pthread_equal(pthread_self(), caph->capturethread))
            pthread_cancel(caph->capturethread);
        caph->capture_running = 0;
    }

    pthread_mutex_unlock(&(caph->out_ringbuf_lock));
    pthread_mutex_unlock(&(caph->handler_lock));
}

/* How often an exit wait rechecks: a cancelled thread's exit isn't signalled */
#define CF_THREAD_EXIT_POLL_MS 10

/* Least time a wait gives a thread no wait has given up on yet */
#define CF_THREAD_EXIT_MIN_MS 100

/* A framework thread's last touch of the handler: a waiter may free it as soon
 * as thread_exit_lock is released */
static void cf_thread_exited(kis_capture_handler_t *caph, unsigned int *live) {
    pthread_mutex_lock(&(caph->thread_exit_lock));
    if (__atomic_load_n(live, __ATOMIC_ACQUIRE) > 0)
        __atomic_sub_fetch(live, 1, __ATOMIC_ACQ_REL);
    pthread_cond_broadcast(&(caph->thread_exit_cond));
    pthread_mutex_unlock(&(caph->thread_exit_lock));
}

/* The same from a cancellation cleanup handler: the unwind there skips the
 * sanitizers' stack bookkeeping (ASan reports, and hangs on, a false stack
 * overflow in any call made from it), so the handler makes no calls and the
 * waiters poll.  The decrement is the thread's last touch of the handler. */
static void cf_thread_exited_unwound(unsigned int *live) {
    __atomic_sub_fetch(live, 1, __ATOMIC_RELEASE);
}

static void cf_thread_started(unsigned int *live) {
    __atomic_add_fetch(live, 1, __ATOMIC_ACQ_REL);
}

static unsigned int cf_thread_live(unsigned int *live) {
    return __atomic_load_n(live, __ATOMIC_ACQUIRE);
}

/* Which framework threads an exit wait covers */
#define CF_EXIT_CAPTURE 0x1
#define CF_EXIT_SIGNAL  0x2
#define CF_EXIT_HOP     0x4
#define CF_EXIT_ALL     (CF_EXIT_CAPTURE | CF_EXIT_SIGNAL | CF_EXIT_HOP)

static uint64_t cf_clock_ns(clockid_t clk);
static void cf_out_ctl_drop_report(kis_capture_handler_t *caph);

/* Under thread_exit_lock: threads in the set still live, and with pending only
 * those no earlier wait gave up on */
static int cf_threads_live_locked(kis_capture_handler_t *caph, int threads, int pending) {
    return ((threads & CF_EXIT_CAPTURE) && cf_thread_live(&caph->capture_live) &&
            !(pending && caph->capture_exit_timed_out)) ||
        ((threads & CF_EXIT_SIGNAL) && cf_thread_live(&caph->signal_live) &&
         !(pending && caph->signal_exit_timed_out)) ||
        ((threads & CF_EXIT_HOP) && cf_thread_live(&caph->hop_live) &&
         !(pending && caph->hop_exit_timed_out));
}

/* Under thread_exit_lock: the exit budget, started by the first close or
 * shutdown and shared by every wait after it */
static uint64_t cf_exit_deadline_locked(kis_capture_handler_t *caph) {
    uint64_t wait_ms;

    if (caph->exit_deadline_ns == 0) {
        wait_ms = caph->close_grace_ms > CF_CAPTURE_EXIT_WAIT_MS ?
            caph->close_grace_ms : CF_CAPTURE_EXIT_WAIT_MS;
        caph->exit_deadline_ns = cf_clock_ns(caph->thread_exit_clock) +
            wait_ms * (CF_NS_PER_SEC / 1000);
    }

    return caph->exit_deadline_ns;
}

static void cf_exit_deadline_start(kis_capture_handler_t *caph) {
    pthread_mutex_lock(&(caph->thread_exit_lock));
    cf_exit_deadline_locked(caph);
    pthread_mutex_unlock(&(caph->thread_exit_lock));
}

/* Under thread_exit_lock: the wait for these threads is over */
static void cf_exit_give_up_locked(kis_capture_handler_t *caph, int threads) {
    if ((threads & CF_EXIT_CAPTURE) && cf_thread_live(&caph->capture_live))
        caph->capture_exit_timed_out = 1;
    if ((threads & CF_EXIT_SIGNAL) && cf_thread_live(&caph->signal_live))
        caph->signal_exit_timed_out = 1;
    if ((threads & CF_EXIT_HOP) && cf_thread_live(&caph->hop_live))
        caph->hop_exit_timed_out = 1;
}

/* With shutdown and spindown, for a new connection: a new budget, and threads
 * that never left are waited for again */
static void cf_exit_wait_reset(kis_capture_handler_t *caph) {
    pthread_mutex_lock(&(caph->thread_exit_lock));
    caph->capture_exit_timed_out = 0;
    caph->signal_exit_timed_out = 0;
    caph->hop_exit_timed_out = 0;
    caph->exit_deadline_ns = 0;
    pthread_mutex_unlock(&(caph->thread_exit_lock));
}

/* A new connection: not shutting down any more */
static void cf_handler_reset_shutdown(kis_capture_handler_t *caph) {
    pthread_mutex_lock(&(caph->handler_lock));
    pthread_mutex_lock(&(caph->out_ringbuf_lock));
    caph->spindown = 0;
    caph->shutdown = 0;
    caph->shutdown_done = 0;
    pthread_mutex_unlock(&(caph->out_ringbuf_lock));
    pthread_mutex_unlock(&(caph->handler_lock));

    cf_exit_wait_reset(caph);
}

/* Wait for the framework threads in the set (CF_EXIT_*) to leave.  A cancel can
 * be ignored (the capture thread may be past its callback with cancels
 * disabled), so the wait is bounded by the one exit budget, and a thread that a
 * wait already gave up on isn't waited for again.  Call with neither framework
 * lock held: the threads' tails take them.  Returns 1 once they're gone, 0 if
 * one is still live or the caller is one of them. */
static int cf_wait_threads_exit(kis_capture_handler_t *caph, int threads) {
    pthread_t self = pthread_self();
    uint64_t deadline, now, slice_ns;
    struct timespec slice;
    int self_thread, gone, gave_up = 0;

    /* The thread ids are written under handler_lock */
    pthread_mutex_lock(&(caph->handler_lock));
    pthread_mutex_lock(&(caph->thread_exit_lock));
    self_thread = ((threads & CF_EXIT_CAPTURE) && cf_thread_live(&caph->capture_live) &&
            pthread_equal(self, caph->capturethread)) ||
        ((threads & CF_EXIT_SIGNAL) && cf_thread_live(&caph->signal_live) &&
         pthread_equal(self, caph->signalthread)) ||
        ((threads & CF_EXIT_HOP) && cf_thread_live(&caph->hop_live) &&
         pthread_equal(self, caph->hopthread));
    pthread_mutex_unlock(&(caph->thread_exit_lock));
    pthread_mutex_unlock(&(caph->handler_lock));

    if (self_thread)
        return 0;

    pthread_mutex_lock(&(caph->thread_exit_lock));

    /* A thread this call just woke (the signal thread from free) gets a moment
     * even when the budget is spent */
    deadline = cf_exit_deadline_locked(caph);
    now = cf_clock_ns(caph->thread_exit_clock) + CF_THREAD_EXIT_MIN_MS * (CF_NS_PER_SEC / 1000);
    if (deadline < now)
        deadline = now;

    while (cf_threads_live_locked(caph, threads, 1)) {
        now = cf_clock_ns(caph->thread_exit_clock);

        if (now >= deadline) {
            cf_exit_give_up_locked(caph, threads);
            gave_up = 1;
            break;
        }

        slice_ns = now + CF_THREAD_EXIT_POLL_MS * (CF_NS_PER_SEC / 1000);
        if (slice_ns > deadline)
            slice_ns = deadline;

        slice.tv_sec = (time_t) (slice_ns / CF_NS_PER_SEC);
        slice.tv_nsec = (long) (slice_ns % CF_NS_PER_SEC);

        pthread_cond_timedwait(&(caph->thread_exit_cond), &(caph->thread_exit_lock), &slice);
    }

    gone = !cf_threads_live_locked(caph, threads, 0);

    pthread_mutex_unlock(&(caph->thread_exit_lock));

    if (gave_up)
        fprintf(stderr, "ERROR: capture framework thread did not exit\n");

    return gone;
}

/* Under handler_lock: stop hopping.  The current hop thread clears
 * hopping_running under handler_lock before it returns, so the id is valid. */
static void cf_cancel_hop_thread_locked(kis_capture_handler_t *caph) {
    if (caph->hopping_running) {
        if (!pthread_equal(pthread_self(), caph->hopthread))
            pthread_cancel(caph->hopthread);
        caph->hopping_running = 0;
    }
}

/* Signal (TERM, then KILL) and detach every child on the IPC list.  The reaper
 * reaps and marks under handler_lock and out_ringbuf_lock, so a pid signalled
 * under out_ringbuf_lock unmarked is not reaped.  Call with out_ringbuf_lock not
 * held (it is recursive); a child the reaper can't reap during the grace sleep
 * (handler_lock held, from shutdown) stays a zombie, which is safe to signal. */
static cf_ipc_t *cf_ipc_kill_detach(kis_capture_handler_t *caph) {
    cf_ipc_t *ipc, *list;

    pthread_mutex_lock(&(caph->out_ringbuf_lock));
    caph->shutdown = 1;
    for (ipc = caph->ipc_list; ipc != NULL; ipc = ipc->next)
        if (!ipc->reaped)
            cf_ipc_signal(caph, ipc, SIGTERM);
    list = caph->ipc_list;
    pthread_mutex_unlock(&(caph->out_ringbuf_lock));

    if (list == NULL)
        return NULL;

    /* A chance to die gracefully */
    usleep(250000);

    pthread_mutex_lock(&(caph->out_ringbuf_lock));
    for (ipc = caph->ipc_list; ipc != NULL; ipc = ipc->next)
        if (!ipc->reaped)
            cf_ipc_signal(caph, ipc, SIGKILL);
    list = caph->ipc_list;
    caph->ipc_list = NULL;
    pthread_mutex_unlock(&(caph->out_ringbuf_lock));

    return list;
}

/* Free one hop list entry; a channel the source refused has no private data */
static void cf_free_hop_entry(kis_capture_handler_t *caph, char *chan, void *privchan) {
    free(chan);

    if (privchan == NULL)
        return;

    if (caph->chanfree_cb != NULL)
        (*(caph->chanfree_cb))(privchan);
    else
        free(privchan);
}

static void cf_free_hop_lists(kis_capture_handler_t *caph, char **chans, void **privchans,
        size_t chan_sz) {
    size_t szi;

    for (szi = 0; szi < chan_sz; szi++)
        cf_free_hop_entry(caph, chans != NULL ? chans[szi] : NULL,
                privchans != NULL ? privchans[szi] : NULL);

    free(chans);
    free(privchans);
}

/* Forget which positions of the hop list failed; under handler_lock */
static void cf_hop_clear_failures(kis_capture_handler_t *caph) {
    struct cf_channel_error *err, *errnext;

    err = (struct cf_channel_error *) caph->channel_hop_failure_list;
    while (err != NULL) {
        errnext = err->next;
        free(err);
        err = errnext;
    }

    caph->channel_hop_failure_list = NULL;
    caph->channel_hop_failure_list_sz = 0;
}

void cf_handler_free(kis_capture_handler_t *caph) {
    int threads_gone;
    cf_ipc_t *ipc_list;

    if (caph == NULL)
        return;

    /* Stop every framework thread first, so nothing below goes away under one.
     * One that won't leave keeps what it can touch (wake pipe, out ring, hop
     * state, IPC records, mutexes): leaked, the process is exiting. */
    cf_cancel_capture_thread(caph);

    pthread_mutex_lock(&(caph->handler_lock));
    pthread_mutex_lock(&(caph->out_ringbuf_lock));
    pthread_mutex_lock(&(caph->thread_exit_lock));

    cf_cancel_hop_thread_locked(caph);

    /* Out of its sigwait loop, into shutdown (which returns at once if it already
     * ran); a signal thread already inside shutdown finishes it.  Still live under
     * thread_exit_lock means the id is still valid. */
    caph->shutdown = 1;
    if (cf_thread_live(&caph->signal_live))
        pthread_kill(caph->signalthread, SIGALRM);

    pthread_mutex_unlock(&(caph->thread_exit_lock));
    pthread_mutex_unlock(&(caph->out_ringbuf_lock));
    pthread_mutex_unlock(&(caph->handler_lock));

    /* Children left when shutdown never ran (or added after it) */
    ipc_list = cf_ipc_kill_detach(caph);

    threads_gone = cf_wait_threads_exit(caph, CF_EXIT_ALL);

    pthread_mutex_lock(&(caph->handler_lock));
    pthread_mutex_lock(&(caph->out_ringbuf_lock));

    if (caph->in_fd >= 0) {
        close(caph->in_fd);
        caph->in_fd = -1;
    }

    if (caph->out_fd >= 0) {
        close(caph->out_fd);
        caph->out_fd = -1;
    }

    free(caph->remote_host);
    caph->remote_host = NULL;

    free(caph->capsource_type);
    caph->capsource_type = NULL;

    free(caph->cli_sourcedef);
    caph->cli_sourcedef = NULL;

#ifdef HAVE_LIBWEBSOCKETS
    free(caph->lwsuuid);
    caph->lwsuuid = NULL;
#endif

    if (caph->tcp_fd >= 0) {
        close(caph->tcp_fd);
        caph->tcp_fd = -1;
    }

    if (threads_gone) {
        while (ipc_list != NULL) {
            cf_ipc_t *nipc = ipc_list->next;
            cf_ipc_free(caph, ipc_list);
            ipc_list = nipc;
        }

        if (caph->out_ringbuf_wake[0] >= 0)
            close(caph->out_ringbuf_wake[0]);

        if (caph->out_ringbuf_wake[1] >= 0)
            close(caph->out_ringbuf_wake[1]);

        caph->out_ringbuf_wake[0] = -1;
        caph->out_ringbuf_wake[1] = -1;

        if (caph->out_ringbuf != NULL)
            kis_simple_ringbuf_free(caph->out_ringbuf);
        caph->out_ringbuf = NULL;

        cf_free_hop_lists(caph, caph->channel_hop_list, caph->custom_channel_hop_list,
                caph->channel_hop_list_sz);
        caph->channel_hop_list = NULL;
        caph->custom_channel_hop_list = NULL;
        caph->channel_hop_list_sz = 0;

        cf_hop_clear_failures(caph);

        /* A hop thread's configure report reads it */
        free(caph->channel);
        caph->channel = NULL;

        free(caph->hop_clock);
        caph->hop_clock = NULL;
        free(caph->hop_timing);
        caph->hop_timing = NULL;

        /* Read lock-free by the capture thread, which is gone */
        free(caph->switch_windows);
        caph->switch_windows = NULL;
    }

    if (caph->in_ringbuf != NULL)
        kis_simple_ringbuf_free(caph->in_ringbuf);
    caph->in_ringbuf = NULL;

    pthread_mutex_unlock(&(caph->out_ringbuf_lock));
    pthread_mutex_unlock(&(caph->handler_lock));

    if (threads_gone) {
        pthread_mutex_destroy(&(caph->out_ringbuf_lock));
        pthread_mutex_destroy(&(caph->handler_lock));
        pthread_cond_destroy(&(caph->thread_exit_cond));
        pthread_mutex_destroy(&(caph->thread_exit_lock));
    }
}

cf_params_interface_t *cf_params_interface_new() {
    cf_params_interface_t *cpi =
        (cf_params_interface_t *) malloc(sizeof(cf_params_interface_t));
    memset(cpi, 0, sizeof(cf_params_interface_t));

    return cpi;
}

void cf_params_interface_free(cf_params_interface_t *pi) {
    if (pi->capif != NULL)
        free(pi->capif);

    if (pi->chanset != NULL)
        free(pi->chanset);

    if (pi->hardware != NULL)
        free(pi->hardware);

    if (pi->channels != NULL) {
        size_t x = 0;
        for (x = 0; x < pi->channels_len; x++) {
            free(pi->channels[x]);
        }
        free(pi->channels);
    }

    free(pi);
}

cf_params_spectrum_t *cf_params_spectrum_new() {
    cf_params_spectrum_t *cps =
        (cf_params_spectrum_t *) malloc(sizeof(cf_params_spectrum_t));
    memset(cps, 0, sizeof(cf_params_spectrum_t));
    return cps;
}

void cf_params_spectrum_free(cf_params_spectrum_t *si) {
    free(si);
}

/* Under handler_lock */
static void cf_handler_spindown_locked(kis_capture_handler_t *caph) {
    caph->spindown = 1;
    __atomic_store_n(&caph->env_report_ms, 0, __ATOMIC_RELEASE);
}

/* Called with handler_lock held once (shutdown's callers don't hold it), which it
 * drops: a second shutdown returns once the first has finished.  Not from a
 * thread the first one waits for (capture, hop), which returns at once. */
static void cf_shutdown_wait_first(kis_capture_handler_t *caph) {
    pthread_t self = pthread_self();
    int waited_on, oldstate;

    pthread_mutex_lock(&(caph->thread_exit_lock));
    waited_on = (cf_thread_live(&caph->capture_live) &&
            pthread_equal(self, caph->capturethread)) ||
        (cf_thread_live(&caph->hop_live) && pthread_equal(self, caph->hopthread));
    pthread_mutex_unlock(&(caph->thread_exit_lock));
    pthread_mutex_unlock(&(caph->handler_lock));

    if (waited_on)
        return;

    /* A cancel in the wait would leave thread_exit_lock held */
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
    pthread_mutex_lock(&(caph->thread_exit_lock));
    while (caph->shutdown_busy && !pthread_equal(self, caph->shutdown_thread))
        pthread_cond_wait(&(caph->thread_exit_cond), &(caph->thread_exit_lock));
    pthread_mutex_unlock(&(caph->thread_exit_lock));
    pthread_setcancelstate(oldstate, NULL);
}

void cf_handler_shutdown(kis_capture_handler_t *caph) {
    cf_ipc_t *ipc, *nipc;
    int hop_gone;

    if (caph == NULL)
        return;

    pthread_mutex_lock(&(caph->handler_lock));

    /* The main loop and the signal thread can both get here */
    if (caph->shutdown_done) {
        cf_shutdown_wait_first(caph);
        return;
    }

    caph->shutdown_done = 1;

    /* First, so through the waits below the reaper only marks children, the
     * loops stop and a child added late is killed */
    pthread_mutex_lock(&(caph->out_ringbuf_lock));
    caph->shutdown = 1;
    pthread_mutex_unlock(&(caph->out_ringbuf_lock));

    pthread_mutex_lock(&(caph->thread_exit_lock));
    caph->shutdown_busy = 1;
    caph->shutdown_thread = pthread_self();
    pthread_mutex_unlock(&(caph->thread_exit_lock));

    /* Cleared once reaped, so never a recycled pid.  IPC children are signalled
     * from the list below, which knows which were reaped. */
    if (caph->monitor_pid > 0) {
	    kill(caph->monitor_pid, SIGINT);
    }

    /* Capture threads that ignore cancels leave on spindown */
    cf_handler_spindown_locked(caph);
    cf_exit_deadline_start(caph);

    /* A channel change can use the IPC records freed below (zigbee900) */
    cf_cancel_hop_thread_locked(caph);

    pthread_mutex_unlock(&(caph->handler_lock));

    cf_handler_wake_loop(caph);

    hop_gone = cf_wait_threads_exit(caph, CF_EXIT_HOP);

    pthread_mutex_lock(&(caph->handler_lock));

    /* Kill any IPC; a hop thread that never left keeps the records */
    ipc = cf_ipc_kill_detach(caph);

    while (ipc != NULL) {
        nipc = ipc->next;
        if (hop_gone)
            cf_ipc_free(caph, ipc);
        ipc = nipc;
    }

    /* Kill the capture thread */
    cf_cancel_capture_thread(caph);

    /* Kill anything pending */
    cf_handler_signal_flush(caph);
    cf_handler_wake_loop(caph);

    pthread_mutex_unlock(&(caph->handler_lock));

    cf_wait_threads_exit(caph, CF_EXIT_CAPTURE);

    pthread_mutex_lock(&(caph->thread_exit_lock));
    caph->shutdown_busy = 0;
    pthread_cond_broadcast(&(caph->thread_exit_cond));
    pthread_mutex_unlock(&(caph->thread_exit_lock));
}

void cf_handler_spindown(kis_capture_handler_t *caph) {
    if (caph == NULL)
        return;

    pthread_mutex_lock(&(caph->handler_lock));
    cf_handler_spindown_locked(caph);
    pthread_mutex_unlock(&(caph->handler_lock));

    cf_handler_wake_loop(caph);
}

static uint64_t cf_mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000ULL + (uint64_t) ts.tv_nsec / 1000000ULL;
}

void cf_handler_set_close_grace(kis_capture_handler_t *caph, unsigned int grace_ms) {
    if (caph == NULL)
        return;

    caph->close_grace_ms = grace_ms;
}

/* Lock-free on purpose: capture loops poll this, and the capture thread is
 * cancelled asynchronously -- a thread killed while holding handler_lock would
 * deadlock cf_handler_shutdown(). */
int cf_handler_close_requested(kis_capture_handler_t *caph) {
    if (caph == NULL)
        return 0;

    return __atomic_load_n(&caph->close_requested, __ATOMIC_ACQUIRE);
}

void cf_handler_assign_hop_channels(kis_capture_handler_t *caph, char **stringchans,
        void **privchans, size_t chan_sz, double rate, int shuffle, int shuffle_spacing,
        int offset) {
    /*
    fprintf(stderr, "debug - assign hop channels\n");
    for (szi = 0; szi < chan_sz; szi++) {
        fprintf(stderr, "debug - channel %s priv %p\n", stringchans[szi], privchans[szi]);
    }
    */

    pthread_mutex_lock(&(caph->handler_lock));

    /* Purge any existing data; failed positions belong to the old list */
    cf_free_hop_lists(caph, caph->channel_hop_list, caph->custom_channel_hop_list,
            caph->channel_hop_list_sz);
    cf_hop_clear_failures(caph);

    caph->channel_hop_list = stringchans;
    caph->custom_channel_hop_list = privchans;
    caph->channel_hop_list_sz = chan_sz;

    /* A negative max disables hopping; a positive one caps the rate */
    if (caph->max_channel_hop_rate < 0)
        caph->channel_hop_rate = 0;
    else if (caph->max_channel_hop_rate > 0 && rate > caph->max_channel_hop_rate)
        caph->channel_hop_rate = caph->max_channel_hop_rate;
    else
        caph->channel_hop_rate = rate;

    caph->channel_hop_shuffle = shuffle;
    caph->channel_hop_shuffle_spacing = shuffle_spacing;
    /* Kept inside the list; the hop cycle uses it modulo the list size anyway */
    caph->channel_hop_offset = (offset > 0 && chan_sz != 0) ? (int) ((size_t) offset % chan_sz) : 0;

    if (caph->channel_hop_shuffle && caph->channel_hop_shuffle_spacing && chan_sz != 0) {
        /* To find a proper randomization number, take the length of the channel
         * list, divide by the preferred skipping distance.
         *
         * We then need to find the closest number to the skipping distance that
         * is not a factor of the maximum so that we get full coverage.
         *
         * A spacing >= the list size is kept as configured, so a later list
         * without one inherits it; the hop cycle treats it as no shuffle.
         */

        /* this math is wrong, fix it in the hop iterator by offsetting the loop start

        while ((chan_sz % (chan_sz / caph->channel_hop_shuffle_spacing)) == 0) {
            if (caph->channel_hop_shuffle_spacing >= chan_sz - 1) {
                caph->channel_hop_shuffle_spacing = 1;
                break;
            }
            caph->channel_hop_shuffle_spacing++;
        }
        */
    }

    pthread_mutex_unlock(&(caph->handler_lock));

    /* Launch the channel hop thread (cancelling any current channel hopping) */
    cf_handler_launch_hopping_thread(caph);
}

void cf_handler_set_hop_shuffle_spacing(kis_capture_handler_t *caph, int spacing) {
    pthread_mutex_lock(&(caph->handler_lock));

    caph->channel_hop_shuffle_spacing = spacing;

    /* Set the shuffle hop; the channel hop thread will pick it up on its own if it
     * needs to */
    if (caph->channel_hop_shuffle && caph->channel_hop_shuffle_spacing &&
            caph->channel_hop_list_sz != 0) {
        while ((caph->channel_hop_list_sz % (caph->channel_hop_list_sz /
                        caph->channel_hop_shuffle_spacing)) == 0) {
            if (caph->channel_hop_shuffle_spacing >= caph->channel_hop_list_sz - 1) {
                caph->channel_hop_shuffle_spacing = 1;
                break;
            }
        caph->channel_hop_shuffle_spacing++;
        }
    }

    pthread_mutex_unlock(&(caph->handler_lock));
}

void cf_handler_list_devices(kis_capture_handler_t *caph) {
    cf_params_list_interface_t **interfaces = NULL;

    /* Callback ret */
    int cbret = -1;

    /* Status buffer */
    char msgstr[STATUS_MAX];

    unsigned int i;

    msgstr[0] = 0;

    if (caph->listdevices_cb == NULL) {
        fprintf(stderr, "%s does not support listing available devices, sorry!\n",
                caph->capsource_type);
        return;
    }

    cbret = (*(caph->listdevices_cb))(caph, 0, msgstr, &interfaces);

    if (strlen(msgstr) != 0 && caph->verbose) {
        if (cbret <= 0)
            fprintf(stderr, "ERROR: %s\n", msgstr);
        else
            fprintf(stderr, "INFO: %s\n", msgstr);
    }

    if (cbret <= 0) {
        fprintf(stderr, "%s - No supported data sources found...\n", caph->capsource_type);
        return;
    }

    fprintf(stderr, "%s supported data sources:\n", caph->capsource_type);

    if (cbret > 0) {
        for (i = 0; i < (size_t) cbret; i++) {
            if (interfaces[i] != NULL) {
                fprintf(stderr, "    %s", interfaces[i]->interface);

                if (interfaces[i]->flags != NULL) {
                    fprintf(stderr, ":%s", interfaces[i]->flags);
                }

                if (interfaces[i]->hardware != NULL) {
                    fprintf(stderr, " (%s)", interfaces[i]->hardware);
                }

                fprintf(stderr, "\n");

                if (interfaces[i]->interface != NULL)
                    free(interfaces[i]->interface);
                if (interfaces[i]->flags != NULL)
                    free(interfaces[i]->flags);
                if (interfaces[i]->hardware != NULL)
                    free(interfaces[i]->hardware);

                free(interfaces[i]);
            }

        }

        free(interfaces);
    }
}

int cf_handler_parse_opts(kis_capture_handler_t *caph, int argc, char *argv[]) {
    int option_idx;

    optind = 0;
    opterr = 0;
    option_idx = 0;

    char parse_hname[513];
    unsigned int parse_port;

    int retry = 1;
    int daemon = 0;
	int autodetect = 0;

    static struct option longopt[] = {
        { "in-fd", required_argument, 0, 1 },
        { "out-fd", required_argument, 0, 2 },
        { "connect", required_argument, 0, 3 },
        { "source", required_argument, 0, 4 },
        { "disable-retry", no_argument, 0, 5 },
        { "daemonize", no_argument, 0, 6 },
        { "list", no_argument, 0, 7 },
        { "fixed-gps", required_argument, 0, 8 },
        { "gps-name", required_argument, 0, 9 },
        { "host", required_argument, 0, 10 },
        { "autodetect", optional_argument, 0, 11 },
        { "tcp", no_argument, 0, 12 },
        { "ssl", no_argument, 0, 13},
        { "user", required_argument, 0, 14},
        { "password", required_argument, 0, 15},
        { "apikey", required_argument, 0, 16},
        { "endpoint", required_argument, 0, 17},
        { "ssl-certificate", required_argument, 0, 18},
        { "help", no_argument, 0, 'h'},
        { "version", no_argument, 0, 'v'},
        { 0, 0, 0, 0 }
    };

    char *gps_arg = NULL;
    int pr;
#ifdef HAVE_LIBWEBSOCKETS
    char *user = NULL, *password = NULL, *token = NULL, *endp_arg = NULL;
    char uri[1024];
#endif

    int ret = 0;

    while (1) {
        int r = getopt_long(argc, argv, "vh-", longopt, &option_idx);

        if (r < 0)
            break;

        if (r == 'v') {
            char version[96];
            cf_version_string(version, sizeof(version));
            printf("%s\n", version);
            return 0;
        } else if (r == 'h') {
            ret = -2;
            goto cleanup;
        } else if (r == 1) {
            if (sscanf(optarg, "%d", &(caph->in_fd)) != 1) {
                fprintf(stderr, "FATAL: Unable to parse incoming file descriptor\n");
                ret = -1;
                goto cleanup;
            }

            caph->use_ipc = 1;
        } else if (r == 2) {
            if (sscanf(optarg, "%d", &(caph->out_fd)) != 1) {
                fprintf(stderr, "FATAL: Unable to parse outgoing file descriptor\n");
                ret = -1;
                goto cleanup;
            }
            caph->use_ipc = 1;
        } else if (r == 3) {
            if (sscanf(optarg, "%512[^:]:%u", parse_hname, &parse_port) != 2) {
                fprintf(stderr, "FATAL: Expected host:port for --connect\n");
                ret = -1;
                goto cleanup;
            }

            caph->remote_host = strdup(parse_hname);
            caph->remote_port = parse_port;
        } else if (r == 4) {
            caph->cli_sourcedef = strdup(optarg);
        } else if (r == 5) {
            fprintf(stderr, "INFO: Disabling automatic reconnection to remote servers\n");
            retry = 0;
        } else if (r == 6) {
            fprintf(stderr, "INFO: Entering daemon mode after initial setup\n");
            daemon = 1;
        } else if (r == 7) {
            cf_handler_list_devices(caph);
            cf_handler_free(caph);
            exit(KIS_EXTERNAL_RETCODE_ARGUMENTS);
        } else if (r == 8) {
            gps_arg = strdup(optarg);
        } else if (r == 9) {
            caph->gps_name = strdup(optarg);
        } else if (r == 10) {
            if (sscanf(optarg, "%512[^:]:%u", parse_hname, &parse_port) != 2) {
                fprintf(stderr, "FATAL: Expected ip:port for --host\n");
                ret = -1;
                goto cleanup;
            }

            caph->remote_host = strdup(parse_hname);
            caph->remote_port = parse_port;
        } else if (r == 11) {
            autodetect = 1;

            if (optarg != NULL)
                caph->announced_uuid = strdup(optarg);
        } else if (r == 12) {
            caph->use_tcp = 1;
        } else if (r == 13) {
#ifdef HAVE_LIBWEBSOCKETS
            caph->lwsusessl = 1;
#else
            fprintf(stderr, "FATAL: Cannot specify ssl when not compiled with websockets support\n");
            ret = -1;
            goto cleanup;
#endif
        } else if (r == 14) {
#ifdef HAVE_LIBWEBSOCKETS
            user = strdup(optarg);
#else
            fprintf(stderr, "FATAL: Cannot user a username or password login when not "
                    "compiled with websockets support\n");
            ret = -1;
            goto cleanup;
#endif
        } else if (r == 15) {
#ifdef HAVE_LIBWEBSOCKETS
            password = strdup(optarg);
#else
            fprintf(stderr, "FATAL: Cannot use a username or password login when not "
                    "compiled with websockets support\n");
            ret = -1;
            goto cleanup;
#endif
        } else if (r == 16) {
#ifdef HAVE_LIBWEBSOCKETS
            token = strdup(optarg);
#else
            fprintf(stderr, "FATAL: Cannot use an API key when not compiled with "
                    "websockets support\n");
            ret = -1;
            goto cleanup;
#endif
        } else if (r == 17) {
#ifdef HAVE_LIBWEBSOCKETS
            endp_arg = strdup(optarg);
#else
            fprintf(stderr, "FATAL: Cannot use custom endpoint when not compiled "
                    "with websockets support.\n");
            ret = -1;
            goto cleanup;
#endif
        } else if (r == 18) {
#ifdef HAVE_LIBWEBSOCKETS
            caph->lwssslcapath = strdup(optarg);
#else
            fprintf(stderr, "FATAL: Cannot use SSL certificates when not compiled "
                    "with websockets support\n");
            return -1;
            goto cleanup;
#endif
        }
    }

#ifndef HAVE_LIBWEBSOCKETS
    if (caph->remote_host != NULL && caph->use_tcp == 0) {
        fprintf(stderr, "FATAL:  Must specify --tcp when not compiled with websockets support\n");
        ret = -1;
        goto cleanup;
    }
#endif

    if (caph->remote_host != NULL && (caph->use_tcp == 0 && caph->remote_port == 3501)) {
        fprintf(stderr, "WARNING: It looks like you're using a legacy TCP remote capture port, but\n"
                "         did not specify '--tcp'; this probably is not what you want!\n");
    }

    /* Spin looking for the remote announcement */
    if (autodetect)
        if (cf_wait_announcement(caph) < 0) {
            ret = -1;
            goto cleanup;
        }

    if (caph->remote_host == NULL) {
        if (caph->cli_sourcedef != NULL)
            fprintf(stderr, "WARNING: Ignoring --source option when not in remote mode.\n");
#ifdef HAVE_LIBWEBSOCKETS
        if (user != NULL || password != NULL)
            fprintf(stderr, "WARNING: Ignoring --user and --password options when not in "
                    "remote mode\n");
        if (token != NULL)
            fprintf(stderr, "WARNING: Ignoring --apikey when not in remote mode\n");
#endif
    }

#ifdef HAVE_LIBWEBSOCKETS
    if (caph->use_tcp && (user != NULL || password != NULL || token != NULL))
        fprintf(stderr, "WARNING: Ignoring user, password, and apikeys in legacy TCP mode\n");

    if ((user != NULL || password != NULL) && (user == NULL || password == NULL)) {
        fprintf(stderr, "FATAL:  Must specify both username and password\n");
        ret = -1;
        goto cleanup;
    }
#endif

    if (caph->remote_host == NULL && gps_arg != NULL) {
        fprintf(stderr, "WARNING: Ignoring --fixed-gps option when not in remote mode.\n");
    }

    if (gps_arg != NULL) {
        pr = sscanf(gps_arg, "%lf,%lf,%lf",
                &(caph->gps_fixed_lat), &(caph->gps_fixed_lon),
                &(caph->gps_fixed_alt));

        if (pr == 2) {
            caph->gps_fixed_alt = 0;
        } else if (pr < 2) {
            fprintf(stderr, "FATAL:  --fixed-gps expects lat,lon or lat,lon,alt\n");
            ret = -1;
            goto cleanup;
        }

        free(gps_arg);
        gps_arg = NULL;
    }


    if (caph->remote_host != NULL) {
        /* Must have a --source to present to the remote host */
        if (caph->cli_sourcedef == NULL) {
            fprintf(stderr, "FATAL: --source option required when connecting to a remote host\n");
            return -1;
        }

        /* Set retry only when we have a remote host */
        caph->remote_retry = retry;

        /* Set daemon mode only when we have a remote host */
        caph->daemonize = daemon;

        /* If we're not tcp, we're websockets */
        if (!caph->use_tcp) {
#ifdef HAVE_LIBWEBSOCKETS
            caph->use_ws = 1;
#else
            fprintf(stderr, "FATAL:  Not compiled with libwebsockets support, cannot use websockets remote capture.\n");
#endif
        }

#ifdef HAVE_LIBWEBSOCKETS
        if (caph->use_ws && user == NULL && password == NULL && token == NULL) {
            fprintf(stderr, "FATAL: User and password or API key required for remote capture\n");
            ret = -1;
            goto cleanup;
        }

        if (user != NULL && token != NULL)
            fprintf(stderr, "WARNING: Ignoring APIKEY and using login information\n");

        if (endp_arg == NULL)
            endp_arg = strdup("/datasource/remote/remotesource.ws");
        else
            fprintf(stderr, "INFO: Using custom endpoint path %s\n", endp_arg);

        if (user != NULL && password != NULL) {
            snprintf(uri, 1024, "%s?user=%s&password=%s", endp_arg, user, password);
            caph->lwsuri = strdup(uri);
        } else if (token != NULL) {
            snprintf(uri, 1024, "%s?KISMET=%s", endp_arg, token);
            caph->lwsuri = strdup(uri);
        }

#endif

        ret = 2;
        goto cleanup;
    }

    ret = 1;

    if (caph->in_fd == -1 || caph->out_fd == -1) {
        ret = -1;
        goto cleanup;
    }

cleanup:
    if (gps_arg != NULL)
        free(gps_arg);

#ifdef HAVE_LIBWEBSOCKETS
    if (user != NULL)
        free(user);
    if (password != NULL)
        free(password);
    if (token != NULL)
        free(token);
    if (endp_arg != NULL)
        free(endp_arg);
#endif

    return ret;

}

void cf_print_help(kis_capture_handler_t *caph, const char *argv0) {
    fprintf(stderr, "%s is a capture driver for Kismet.  Typically it is started\n"
            "automatically by the Kismet server.\n", argv0);

    if (caph->remote_capable) {
        fprintf(stderr, "\n%s supports sending data to a remote Kismet server\n"
                "usage: %s [options]\n"
                " --connect [host]:[port]      Connect to remote Kismet server on [host] and [port]; by\n"
                "                               default this now uses the new websockets interface built\n"
                "                               into the Kismet webserver on port 2501; to connect using\n"
                "                               the legacy remote capture protocol, specify the '--tcp'\n"
                "                               option and the appropriate port, by default port 3501.\n"
                " --tcp                        Use the legacy TCP remote capture protocol, when combined\n"
                "                               with the --connect option.  The modern protocol uses \n"
                "                               websockets built into the Kismet server and does not\n"
                "                               need this option.\n"
                " --ssl                        Use SSL to connect to a websocket-enabled Kismet server\n"
                " --ssl-certificate [certfile] Use SSL to connect to a websocket-enabled Kismet server\n"
                "                               and use the provided certificate authority certificate\n"
                "                               to validate the server.\n"
                " --user [username]            Kismet username for a websockets-based remote capture\n"
                "                               source.  A username and password, or an API key, are\n"
                "                               required for websockets mode.  A username and password\n"
                "                               are ONLY used in websockets mode.\n"
                " --password [password]        Kismet password for a websockets-based remote capture source.\n"
                "                               A username and password, or an API key, are required for\n"
                "                               websocket mode.  A username and password are ONLY used in\n"
                "                               websockets mode.\n"
                " --apikey [api key]           A Kismet API key for the 'datasource' role; this may be\n"
                "                               supplied instead of a username and password for websockets\n"
                "                               based remote capture.  An API key is ONLY used in websockets\n"
                "                               mode.\n"
                " --endpoint [endpoint]        An alternate endpoint for the websockets connection.  By\n"
                "                               default remote datasources are terminated at\n"
                "                                 /datasource/remote/remotesource.ws\n"
                "                               This should typically only be changed when using a HTTP proxy\n"
                "                               homing the Kismet service under a directory.  Endpoints \n"
                "                               should include the full path to the websocket endpoint, for\n"
                "                               example:\n"
                "                                 --endpoint=/kismet/proxy/datasource/remote/remotesource.ws\n"
                " --source [source def]        Specify a source to send to the remote \n"
                "                              Kismet server; only used in conjunction with remote capture.\n"
                " --disable-retry              Do not attempt to reconnect to a remote server if there is an\n"
                "                               error; exit immediately.  By default a remote capture will\n"
                "                               attempt to reconnect indefinitely if the server is not\n"
                "                               available.\n"
                " --fixed-gps [lat,lon,alt]    Set a fixed location for this capture (remote only),\n"
                "                               accepts lat,lon,alt or lat,lon\n"
                " --gps-name [name]            Set an alternate GPS name for this source\n"
                " --daemonize                  Background the capture tool and enter daemon mode.\n"
                " --list                       List supported devices detected\n"
				" --autodetect [uuid:optional] Look for a Kismet server in announcement mode, optionally \n"
				"                              waiting for a specific server UUID to be seen.  Requires \n"
				"                              a Kismet server configured for announcement mode.\n"
                " --version                    Print version and exit.\n",
                argv0, argv0);
    }

}


void cf_handler_set_listdevices_cb(kis_capture_handler_t *capf,
        cf_callback_listdevices cb) {
    pthread_mutex_lock(&(capf->handler_lock));
    capf->listdevices_cb = cb;
    pthread_mutex_unlock(&(capf->handler_lock));
}

void cf_handler_set_probe_cb(kis_capture_handler_t *capf, cf_callback_probe cb) {
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

void cf_handler_set_capture_cb(kis_capture_handler_t *capf, cf_callback_capture cb) {
    pthread_mutex_lock(&(capf->handler_lock));
    capf->capture_cb = cb;
    pthread_mutex_unlock(&(capf->handler_lock));
}

void cf_handler_set_spectrumconfig_cb(kis_capture_handler_t *capf,
        cf_callback_spectrumconfig cb) {
    pthread_mutex_lock(&(capf->handler_lock));
    capf->spectrumconfig_cb = cb;
    pthread_mutex_unlock(&(capf->handler_lock));
}

void cf_handler_set_unknown_cb(kis_capture_handler_t *capf, cf_callback_unknown cb) {
    pthread_mutex_lock(&(capf->handler_lock));
    capf->unknown_cb = cb;
    pthread_mutex_unlock(&(capf->handler_lock));
}

void cf_handler_set_chantranslate_cb(kis_capture_handler_t *capf,
        cf_callback_chantranslate cb) {
    pthread_mutex_lock(&(capf->handler_lock));
    capf->chantranslate_cb = cb;
    pthread_mutex_unlock(&(capf->handler_lock));
}

void cf_handler_set_chancontrol_cb(kis_capture_handler_t *capf,
        cf_callback_chancontrol cb) {
    pthread_mutex_lock(&(capf->handler_lock));
    capf->chancontrol_cb = cb;
    pthread_mutex_unlock(&(capf->handler_lock));
}

void cf_handler_set_chanfree_cb(kis_capture_handler_t *capf, cf_callback_chanfree cb) {
    pthread_mutex_lock(&(capf->handler_lock));
    capf->chanfree_cb = cb;
    pthread_mutex_unlock(&(capf->handler_lock));
}

/* Runs on a cancel, after any cleanup the capture callback pushed: the thread's
 * last touch of caph, which a waiting cf_handler_free may then free */
static void cf_capture_thread_exited(void *arg) {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) arg;
    cf_thread_exited_unwound(&caph->capture_live);
}

/* A cancel longjmps back into the frame that pushed the cleanup, past the
 * sanitizer's stack bookkeeping, and ASan's instrumented return from that jump
 * then reports the stale redzones of the deeper frames.  The frames that push
 * framework cleanups aren't instrumented. */
#if defined(__SANITIZE_ADDRESS__)
#define CF_UNWIND_FRAME __attribute__((no_sanitize_address))
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define CF_UNWIND_FRAME __attribute__((no_sanitize_address))
#endif
#endif
#ifndef CF_UNWIND_FRAME
#define CF_UNWIND_FRAME
#endif

/* The capture callback and the thread's tail */
static void cf_capture_thread_run(kis_capture_handler_t *caph) {
    /* Set us cancelable */
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    if (caph->capture_cb != NULL) {
        (*(caph->capture_cb))(caph);
    } else {
        fprintf(stderr, "ERROR - No capture handler defined for capture thread\n");
    }

    // cf_send_error(caph, 0, "capture thread ended, source is closed.");

    /* Done capturing: no async cancel from here on (it could land inside a lock),
     * and nothing should try to cancel a thread that is about to be gone */
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    /* Together, so an open seen between them can't launch a capture over this one */
    pthread_mutex_lock(&(caph->handler_lock));
    pthread_mutex_lock(&(caph->out_ringbuf_lock));
    caph->capture_running = 0;
    cf_handler_spindown_locked(caph);
    pthread_mutex_unlock(&(caph->out_ringbuf_lock));
    pthread_mutex_unlock(&(caph->handler_lock));

    cf_handler_wake_loop(caph);
}

/* Internal capture thread which spawns the capture callback
 */
CF_UNWIND_FRAME void *cf_int_capture_thread(void *arg) {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) arg;

    /* Before async cancel is on, so a cancel always finds it */
    pthread_cleanup_push(cf_capture_thread_exited, caph);
    cf_capture_thread_run(caph);
    pthread_cleanup_pop(0);

    /* Returned with cancels off: the exit is signalled under thread_exit_lock,
     * which orders the tail's last touches (the wake pipe) before a waiter's
     * free, and wakes the waiter without a poll */
    cf_thread_exited(caph, &caph->capture_live);

    return NULL;
}

/*
 * Catch any terminated processes and call any termination handlers they
 * have; remove them from the IPC list.
 *
 * IPC termination callback is responsible for freeing the IPC record,
 * if not tracked elsewhere.
 *
 * SIGCHLD coalesces, so reap until no child is ready, then return to sigwait.
 */
void cf_process_child_signals(kis_capture_handler_t *caph) {
    while (1) {
        int pid_status;
        pid_t caught_pid;
        cf_ipc_t *prev_ipc = NULL;
        cf_ipc_t *ipc = NULL;

        /* Reaped and unlinked or marked in one step under both locks, in the
         * usual order: shutdown never signals a reaped pid still on the list, the
         * IPC service walk never sees it unlinked, and a term callback may take
         * handler_lock (a send that takes a seqno does) */
        pthread_mutex_lock(&(caph->handler_lock));
        pthread_mutex_lock(&(caph->out_ringbuf_lock));

        caught_pid = waitpid(-1, &pid_status, WNOHANG | WUNTRACED);

        if (caught_pid < 0 && errno == EINTR) {
            pthread_mutex_unlock(&(caph->out_ringbuf_lock));
            pthread_mutex_unlock(&(caph->handler_lock));
            continue;
        }

        if (caught_pid <= 0) {
            pthread_mutex_unlock(&(caph->out_ringbuf_lock));
            pthread_mutex_unlock(&(caph->handler_lock));
            return;
        }

        ipc = caph->ipc_list;

        while (ipc != NULL) {
            /* Shutdown frees the list; it only must not signal this one (a
             * stopped child is still there to signal) */
            if (ipc->pid == caught_pid && caph->shutdown) {
                if (WIFEXITED(pid_status) || WIFSIGNALED(pid_status))
                    ipc->reaped = 1;
                break;
            }

            if (ipc->pid == caught_pid) {
                if (ipc == caph->ipc_list) {
                    caph->ipc_list = ipc->next;
                } else {
                    prev_ipc->next = ipc->next;
                }

                /* Runs under handler_lock (as from the IPC service loop) and
                 * out_ringbuf_lock; it must not wait on a thread that takes
                 * either */
                if (ipc->term_callback != NULL) {
                    ipc->term_callback(caph, ipc, pid_status);
                }

                break;
            }

            prev_ipc = ipc;
            ipc = ipc->next;
        }

        pthread_mutex_unlock(&(caph->out_ringbuf_lock));
        pthread_mutex_unlock(&(caph->handler_lock));
    }
}

void *cf_int_signal_thread(void *arg) {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) arg;

    int sig_caught, r;

    /* Exactly the core set blocked, in one step, so sigwait takes those signals
     * and a core signal pending since init is never delivered with its default
     * action; every other signal is unblocked */
    pthread_sigmask(SIG_SETMASK, &cf_core_signal_mask, NULL);

    /* Never cancelled: cf_handler_free sets shutdown and wakes it with SIGALRM, and
     * it leaves through cf_handler_shutdown */
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    /* A child that exited before this thread started, while a helper had
     * SIGCHLD unblocked or reset, may have left no signal to wait for */
    cf_process_child_signals(caph);

    while (!caph->spindown && !caph->shutdown) {
        r = sigwait(&cf_core_signal_mask, &sig_caught);

        if (r != 0)
            continue;

        switch (sig_caught) {
            case SIGINT:
            case SIGTERM:
            case SIGHUP:
            case SIGQUIT:
                break;
            case SIGCHLD:
                cf_process_child_signals(caph);
                break;
            case SIGALRM:
                /* Do nothing with the timer, it just ticks us to break out of sigwait */
                break;
        }
    }

    fprintf(stderr, "DEBUG - cf handler shutdown\n");
    cf_handler_shutdown(caph);

    pthread_mutex_lock(&(caph->handler_lock));
    caph->signal_running = 0;
    pthread_mutex_unlock(&(caph->handler_lock));

    cf_thread_exited(caph, &caph->signal_live);

    return NULL;
}

/* Launch a capture thread after opening has been successful.  On failure msg
 * (STATUS_MAX) says why; -2 means a thread could not be created and the source
 * should spin down once the error is sent. */
static int cf_launch_capture_thread_msg(kis_capture_handler_t *caph, char *msg) {
    int ret = -2;

    /* Set the thread attributes - detached, cancellable */
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setschedpolicy(&attr, SCHED_FIFO);

    pthread_mutex_lock(&(caph->handler_lock));

    if (caph->capture_running) {
        ret = 0;
        goto out;
    }

    /* Going down, or the last capture thread is still in its tail (an open that
     * raced its spindown): a new one would run over it */
    if (caph->spindown || caph->shutdown || cf_thread_live(&caph->capture_live)) {
        snprintf(msg, STATUS_MAX, "source is closing, not starting a capture thread");
        ret = -1;
        goto out;
    }

    /* Done in cf_handler_init; again for this thread and in case the helper
     * reset SIGCHLD since.  The capture thread inherits the block. */
    cf_block_core_signals();

    /* Live before it starts: a thread that finishes at once clears it itself */
    if (!cf_thread_live(&caph->signal_live)) {
        cf_thread_started(&caph->signal_live);

        if (pthread_create(&(caph->signalthread), &attr, cf_int_signal_thread, caph) != 0) {
            cf_thread_exited(caph, &caph->signal_live);
            snprintf(msg, STATUS_MAX, "failed to launch signal thread");
            goto out;
        }

        caph->signal_running = 1;
    }

    cf_thread_started(&caph->capture_live);

    if (pthread_create(&(caph->capturethread), &attr,
                cf_int_capture_thread, caph) != 0) {
        cf_thread_exited(caph, &caph->capture_live);
        snprintf(msg, STATUS_MAX, "failed to launch capture thread");
        goto out;
    }

    caph->capture_running = 1;
    ret = 1;

out:
    pthread_mutex_unlock(&(caph->handler_lock));
    pthread_attr_destroy(&attr);

    return ret;
}

int cf_handler_launch_capture_thread(kis_capture_handler_t *caph) {
    char msg[STATUS_MAX];
    int ret = cf_launch_capture_thread_msg(caph, msg);

    if (ret < 0) {
        cf_send_error(caph, 0, msg);

        if (ret == -2)
            cf_handler_spindown(caph);

        return -1;
    }

    return ret;
}

void cf_handler_wait_ringbuffer(kis_capture_handler_t *caph) {
    int oldtype;
    int drained = 0;

    /* Capture threads are cancelled asynchronously; defer it while the flush
     * mutex is held so a cancel can't leave it locked */
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &oldtype);
    pthread_mutex_lock(&(caph->out_ringbuf_flush_cond_mutex));
    pthread_cleanup_push(cf_unlock_mutex_cleanup, &(caph->out_ringbuf_flush_cond_mutex));

    /* A flush that finished before we got here leaves an empty ring and nothing
     * left to broadcast; don't wait for one.  The wait stays bounded because the
     * websocket path broadcasts without the mutex. */
    if (caph->out_ringbuf != NULL) {
        pthread_mutex_lock(&(caph->out_ringbuf_lock));
        drained = kis_simple_ringbuf_used(caph->out_ringbuf) == 0;
        pthread_mutex_unlock(&(caph->out_ringbuf_lock));
    }

    if (!drained) {
        struct timeval tv;
        struct timespec ts;

        gettimeofday(&tv, NULL);
        ts.tv_sec = tv.tv_sec;
        ts.tv_nsec = ((long) tv.tv_usec * 1000) + (100 * 1000 * 1000);

        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000L;
        }

        pthread_cond_timedwait(&(caph->out_ringbuf_flush_cond),
                &(caph->out_ringbuf_flush_cond_mutex), &ts);
    }

    pthread_cleanup_pop(1);
    pthread_setcanceltype(oldtype, NULL);
}

/* Map a position in the hop cycle to an index in the channel list.  Without
 * shuffling the cycle is the list in order.  With shuffling it visits every
 * spacing'th channel starting at 0, then every spacing'th starting at 1, and so
 * on, so each channel is visited once per cycle.  Split sources start at
 * different positions of the same cycle, so they stay apart. */
static size_t cf_chanhop_index(size_t pos, size_t list_sz, int shuffle, size_t spacing) {
    size_t pass, pass_sz;

    pos %= list_sz;

    if (!shuffle || spacing <= 1 || spacing >= list_sz)
        return pos;

    for (pass = 0; pass < spacing; pass++) {
        pass_sz = (list_sz - pass + spacing - 1) / spacing;

        if (pos < pass_sz)
            return pass + pos * spacing;

        pos -= pass_sz;
    }

    return 0;
}

/* Position in the hop cycle of list index idx; the inverse of cf_chanhop_index */
static size_t cf_chanhop_pos(size_t idx, size_t list_sz, int shuffle, size_t spacing) {
    size_t pass, pos;

    if (!shuffle || spacing <= 1 || spacing >= list_sz)
        return idx;

    for (pass = 0, pos = 0; pass < idx % spacing; pass++)
        pos += (list_sz - pass + spacing - 1) / spacing;

    return pos + idx / spacing;
}

/* The shuffle spacing in effect for a list of list_sz: cf_chanhop_index treats
 * one >= the size as no shuffle, which reports show as 1 */
static size_t cf_hop_valid_spacing(int shuffle, size_t spacing, size_t list_sz) {
    if (shuffle && spacing != 0 && list_sz != 0 && spacing >= list_sz)
        return 1;

    return spacing;
}

static uint64_t cf_clock_ns(clockid_t clk) {
    struct timespec ts;
    clock_gettime(clk, &ts);
    return (uint64_t) ts.tv_sec * CF_NS_PER_SEC + (uint64_t) ts.tv_nsec;
}

void cf_handler_set_chanband_cb(kis_capture_handler_t *capf, cf_callback_chanband cb) {
    pthread_mutex_lock(&(capf->handler_lock));
    capf->chanband_cb = cb;
    pthread_mutex_unlock(&(capf->handler_lock));
}

/* Until a sync completes, assume the server's clock matches our realtime clock;
 * for a local source it does. */
static void cf_hop_clock_reset(struct cf_hop_clock *c) {
    uint64_t mono = cf_clock_ns(CLOCK_MONOTONIC);
    int64_t offset = (int64_t) (cf_clock_ns(CLOCK_REALTIME) - mono);

    memset(c, 0, sizeof(struct cf_hop_clock));

    c->state = KIS_EXTERNAL_V3_HOPSYNC_LOCAL;
    c->offset_ns = offset;
    c->ref_mono_ns = mono;
    c->next_sync_ns = mono;
    c->interval_ns = CF_SYNC_MIN_INTERVAL_NS;
}

static int64_t cf_hop_clock_offset_at(const struct cf_hop_clock *c, uint64_t mono) {
    int64_t dt_us = ((int64_t) (mono - c->ref_mono_ns)) / 1000;

    if (dt_us > CF_SYNC_MAX_DRIFT_SPAN_US)
        dt_us = CF_SYNC_MAX_DRIFT_SPAN_US;
    else if (dt_us < -CF_SYNC_MAX_DRIFT_SPAN_US)
        dt_us = -CF_SYNC_MAX_DRIFT_SPAN_US;

    return c->offset_ns + dt_us * c->drift_ppb / 1000000LL;
}

/* Server clock now, ns since the unix epoch */
static uint64_t cf_hop_server_ns(const struct cf_hop_clock *c, uint64_t mono) {
    return mono + (uint64_t) cf_hop_clock_offset_at(c, mono);
}

static uint64_t cf_hop_dwell_ns(kis_capture_handler_t *caph) {
    double d;

    /* Also refuses NaN and infinity from the server */
    if (!(caph->channel_hop_rate > 0) || !isfinite(caph->channel_hop_rate))
        return CF_HOP_MAX_DWELL_NS;

    d = (double) CF_NS_PER_SEC / caph->channel_hop_rate;

    if (d < (double) CF_HOP_MIN_DWELL_NS)
        return CF_HOP_MIN_DWELL_NS;
    if (d > (double) CF_HOP_MAX_DWELL_NS)
        return CF_HOP_MAX_DWELL_NS;

    return (uint64_t) d;
}

/* Answer to one exchange; t4 is taken when the frame arrived, before any lock.
 * Called under handler_lock. */
static void cf_hop_clock_sample(kis_capture_handler_t *caph, uint64_t t1, uint64_t t2,
        uint64_t t3, uint64_t t4) {
    struct cf_hop_clock *c = caph->hop_clock;
    uint64_t rtt;

    if (c == NULL || !caph->hop_sync || c->burst_sent == 0)
        return;

    /* Only answers to this burst, in a sane order, from a clock before 2116; that
     * bound keeps every offset well inside int64 */
    if (t1 < c->burst_start_ns || t1 > t4 || t3 < t2 || t3 >= CF_SYNC_MAX_CLOCK_NS)
        return;

    if (t3 - t2 > t4 - t1)
        return;

    rtt = (t4 - t1) - (t3 - t2);

    if (!c->best_valid || rtt < c->best_rtt_ns) {
        c->best_valid = 1;
        c->best_rtt_ns = rtt;
        c->best_offset_ns = ((int64_t) (t2 - t1) + (int64_t) (t3 - t4)) / 2;
        c->best_mono_ns = t1 + (t4 - t1) / 2;
    }
}

static void cf_hop_clock_drift(struct cf_hop_clock *c) {
    double sw = 0, sx = 0, sy = 0, sxx = 0, sxy = 0, w, x, y, den, slope, r;
    unsigned int i;

    if (c->hist_n < 3 ||
            c->hist_mono[c->hist_n - 1] - c->hist_mono[0] < CF_SYNC_DRIFT_MIN_SPAN_NS)
        return;

    /* least squares, seconds against ns, relative to the oldest sample; each
     * sample is weighted by 1/rtt^2 so a slow exchange barely moves the fit */
    for (i = 0; i < c->hist_n; i++) {
        r = (double) (c->hist_rtt[i] < 10000 ? 10000 : c->hist_rtt[i]) / 1000.0;
        w = 1.0 / (r * r);
        x = (double) (c->hist_mono[i] - c->hist_mono[0]) / (double) CF_NS_PER_SEC;
        y = (double) (c->hist_offset[i] - c->hist_offset[0]);
        sw += w;
        sx += w * x;
        sy += w * y;
        sxx += w * x * x;
        sxy += w * x * y;
    }

    den = sw * sxx - sx * sx;

    if (den <= 0)
        return;

    slope = (sw * sxy - sx * sy) / den;

    if (slope > CF_SYNC_MAX_DRIFT_PPB)
        slope = CF_SYNC_MAX_DRIFT_PPB;
    else if (slope < -CF_SYNC_MAX_DRIFT_PPB)
        slope = -CF_SYNC_MAX_DRIFT_PPB;

    c->drift_ppb = (int64_t) slope;
}

/* End of a burst: take the best exchange and plan the next sync */
static void cf_hop_clock_finish(struct cf_hop_clock *c, uint64_t now) {
    int64_t miss;

    c->burst_sent = 0;

    if (!c->best_valid) {
        c->next_sync_ns = now + CF_SYNC_MIN_INTERVAL_NS;
        return;
    }

    miss = c->best_offset_ns - cf_hop_clock_offset_at(c, c->best_mono_ns);
    if (miss < 0)
        miss = -miss;

    if (c->state != KIS_EXTERNAL_V3_HOPSYNC_SYNCED || miss > CF_SYNC_STEP_NS) {
        c->hist_n = 0;
        c->drift_ppb = 0;
        c->interval_ns = CF_SYNC_MIN_INTERVAL_NS;
    } else if (miss > 1000000LL) {
        c->interval_ns /= 2;
        if (c->interval_ns < CF_SYNC_MIN_INTERVAL_NS)
            c->interval_ns = CF_SYNC_MIN_INTERVAL_NS;
    } else if (miss < 250000LL) {
        c->interval_ns *= 2;
        if (c->interval_ns > CF_SYNC_MAX_INTERVAL_NS)
            c->interval_ns = CF_SYNC_MAX_INTERVAL_NS;
    }

    if (c->hist_n == CF_SYNC_HISTORY) {
        memmove(&c->hist_mono[0], &c->hist_mono[1], sizeof(uint64_t) * (CF_SYNC_HISTORY - 1));
        memmove(&c->hist_offset[0], &c->hist_offset[1], sizeof(int64_t) * (CF_SYNC_HISTORY - 1));
        memmove(&c->hist_rtt[0], &c->hist_rtt[1], sizeof(uint64_t) * (CF_SYNC_HISTORY - 1));
        c->hist_n--;
    }

    c->hist_mono[c->hist_n] = c->best_mono_ns;
    c->hist_offset[c->hist_n] = c->best_offset_ns;
    c->hist_rtt[c->hist_n] = c->best_rtt_ns;
    c->hist_n++;

    c->offset_ns = c->best_offset_ns;
    c->ref_mono_ns = c->best_mono_ns;
    c->sync_err_us = (uint32_t) ((c->best_rtt_ns / 2) / 1000);
    c->state = KIS_EXTERNAL_V3_HOPSYNC_SYNCED;

    cf_hop_clock_drift(c);

    c->next_sync_ns = now + c->interval_ns;
}

int cf_send_timesyncreq(kis_capture_handler_t *caph, uint64_t t1) {
    size_t est_len = 24;
    size_t final_len = 0;

    mpack_writer_t writer;
    mpack_error_t err;
    cf_frame_metadata *meta = NULL;

    meta = cf_prepare_packet(caph, KIS_EXTERNAL_V3_KDS_TIMESYNCREQ,
            cf_get_next_seqno(caph), 0, est_len);

    if (meta == NULL)
        return 0;

    mpack_writer_init(&writer, (char *) meta->frame->data, est_len);
    mpack_build_map(&writer);
    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_TIMESYNCREQ_FIELD_T1);
    mpack_write_u64(&writer, t1);
    mpack_complete_map(&writer);

    final_len = mpack_writer_buffer_used(&writer);

    if ((err = mpack_writer_destroy(&writer)) != mpack_ok) {
        fprintf(stderr, "ERROR: Mpack couldn't serialize TIMESYNCREQ (%u)\n", err);
        cf_cancel_packet(caph, meta);
        return -1;
    }

    return cf_commit_packet(caph, meta, final_len);
}

/* Send the next exchange of a burst, or finish it; returns the next time this needs
 * to run.  Called under handler_lock. */
static uint64_t cf_hop_clock_step(kis_capture_handler_t *caph, uint64_t now) {
    struct cf_hop_clock *c = caph->hop_clock;

    if (c->burst_sent == 0) {
        if (now < c->next_sync_ns)
            return c->next_sync_ns;

        c->burst_start_ns = now;
        c->best_valid = 0;
        c->next_req_ns = now;
    }

    if (c->burst_sent < CF_SYNC_BURST) {
        if (now < c->next_req_ns)
            return c->next_req_ns;

        cf_send_timesyncreq(caph, cf_clock_ns(CLOCK_MONOTONIC));
        c->burst_sent++;
        c->next_req_ns = now + CF_SYNC_BURST_SPACING_NS;

        if (c->burst_sent < CF_SYNC_BURST)
            return c->next_req_ns;

        c->burst_done_ns = now + CF_SYNC_BURST_WAIT_NS;
        return c->burst_done_ns;
    }

    if (now < c->burst_done_ns)
        return c->burst_done_ns;

    cf_hop_clock_finish(c, now);
    return c->next_sync_ns;
}

static void cf_write_switch_stats(mpack_writer_t *writer, unsigned int field,
        struct cf_switch_stats *st) {
    mpack_write_uint(writer, field);
    mpack_build_map(writer);

    mpack_write_uint(writer, KIS_EXTERNAL_V3_KDS_SUB_SWITCH_FIELD_TOTAL);
    mpack_write_u64(writer, st->total);
    mpack_write_uint(writer, KIS_EXTERNAL_V3_KDS_SUB_SWITCH_FIELD_COUNT);
    mpack_write_u32(writer, st->count);

    if (st->count > 0) {
        mpack_write_uint(writer, KIS_EXTERNAL_V3_KDS_SUB_SWITCH_FIELD_MEAN_US);
        mpack_write_u32(writer, (uint32_t) (st->sum_us / st->count));
        mpack_write_uint(writer, KIS_EXTERNAL_V3_KDS_SUB_SWITCH_FIELD_MIN_US);
        mpack_write_u32(writer, st->min_us);
        mpack_write_uint(writer, KIS_EXTERNAL_V3_KDS_SUB_SWITCH_FIELD_MAX_US);
        mpack_write_u32(writer, st->max_us);
    }

    mpack_complete_map(writer);

    st->count = 0;
    st->sum_us = 0;
    st->min_us = 0;
    st->max_us = 0;
}

/* Called under handler_lock */
int cf_send_hopreport(kis_capture_handler_t *caph) {
    size_t est_len = 256;
    size_t final_len = 0;

    mpack_writer_t writer;
    mpack_error_t err;
    cf_frame_metadata *meta = NULL;

    struct cf_hop_timing *t = caph->hop_timing;
    struct cf_hop_clock *c = caph->hop_clock;
    uint64_t mono;
    int64_t offset_us;

    if (t == NULL || c == NULL)
        return 0;

    meta = cf_prepare_packet(caph, KIS_EXTERNAL_V3_KDS_HOPREPORT,
            cf_get_next_seqno(caph), 0, est_len);

    if (meta == NULL)
        return 0;

    mpack_writer_init(&writer, (char *) meta->frame->data, est_len);
    mpack_build_map(&writer);

    cf_write_switch_stats(&writer, KIS_EXTERNAL_V3_KDS_HOPREPORT_FIELD_CHANSWITCH, &t->chan);

    if (t->band_known)
        cf_write_switch_stats(&writer, KIS_EXTERNAL_V3_KDS_HOPREPORT_FIELD_BANDSWITCH, &t->band);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_HOPREPORT_FIELD_MISSED);
    mpack_write_u64(&writer, t->missed);
    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_HOPREPORT_FIELD_FAILED);
    mpack_write_u64(&writer, t->failed);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_HOPREPORT_FIELD_SYNC_STATE);
    if (caph->hop_sync && caph->hopping_running) {
        mpack_write_u8(&writer, c->state);

        if (c->state == KIS_EXTERNAL_V3_HOPSYNC_SYNCED) {
            mono = cf_clock_ns(CLOCK_MONOTONIC);
            offset_us = ((int64_t) (cf_hop_server_ns(c, mono) -
                    cf_clock_ns(CLOCK_REALTIME))) / 1000;

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_HOPREPORT_FIELD_SYNC_ERR_US);
            mpack_write_u32(&writer, c->sync_err_us);
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_HOPREPORT_FIELD_SYNC_OFFSET_US);
            mpack_write_i64(&writer, offset_us);
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_HOPREPORT_FIELD_SYNC_DRIFT_PPB);
            mpack_write_i32(&writer, (int32_t) c->drift_ppb);
        }
    } else {
        mpack_write_u8(&writer, KIS_EXTERNAL_V3_HOPSYNC_OFF);
    }

    mpack_complete_map(&writer);

    final_len = mpack_writer_buffer_used(&writer);

    if ((err = mpack_writer_destroy(&writer)) != mpack_ok) {
        fprintf(stderr, "ERROR: Mpack couldn't serialize HOPREPORT (%u)\n", err);
        cf_cancel_packet(caph, meta);
        return -1;
    }

    return cf_commit_packet(caph, meta, final_len);
}

/* Send a report if one is due; returns when the next one is.  Called under
 * handler_lock. */
static uint64_t cf_hop_report_step(kis_capture_handler_t *caph, uint64_t now) {
    struct cf_hop_timing *t = caph->hop_timing;

    if (caph->hop_report_ms == 0 || t == NULL)
        return UINT64_MAX;

    if (now >= t->next_report_ns) {
        cf_send_hopreport(caph);
        t->next_report_ns = now + (uint64_t) caph->hop_report_ms * 1000000ULL;
    }

    return t->next_report_ns;
}

/* ASCII letters, digits and the listed punctuation only */
static int cf_name_chars_ok(const char *s, size_t len, const char *punct) {
    size_t i;

    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char) s[i];

        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
            continue;

        if (c == 0 || strchr(punct, c) == NULL)
            return 0;
    }

    return 1;
}

/* The same checks the server makes, so a reading it would skip isn't sent */
static int cf_env_reading_valid(const cf_env_reading_t *r) {
    size_t len;

    if (r->id == NULL)
        return 0;

    len = strnlen(r->id, 33);

    if (len == 0 || len > 32 || r->id[0] == '.')
        return 0;

    if (!cf_name_chars_ok(r->id, len, "_.-"))
        return 0;

    if (!isfinite(r->value))
        return 0;

    switch (r->kind) {
        case KIS_EXTERNAL_V3_ENV_KIND_THERMAL:
            return r->value >= -100.0 && r->value <= 400.0;
        case KIS_EXTERNAL_V3_ENV_KIND_FAN:
            return r->value >= 0.0 && r->value <= 1000000.0;
        case KIS_EXTERNAL_V3_ENV_KIND_BATTERY:
            return r->value >= 0.0 && r->value <= 100.5;
    }

    return 0;
}

size_t cf_env_estimate_len(size_t n) {
    if (n > KIS_EXTERNAL_V3_ENV_MAX_READINGS)
        n = KIS_EXTERNAL_V3_ENV_MAX_READINGS;

    /* map and timestamps, then per reading: the map, the 32 byte id, the 64 byte
     * label, and the numbers, with slop */
    return 32 + n * 192;
}

ssize_t cf_env_encode(char *buf, size_t buf_sz, const cf_env_reading_t *readings, size_t n,
        const struct timeval *ts) {
    mpack_writer_t writer;
    size_t i, nvalid = 0, written = 0, len;
    const cf_env_reading_t *r;

    if (readings == NULL)
        return 0;

    for (i = 0; i < n && nvalid < KIS_EXTERNAL_V3_ENV_MAX_READINGS; i++)
        if (cf_env_reading_valid(&readings[i]))
            nvalid++;

    if (nvalid == 0)
        return 0;

    mpack_writer_init(&writer, buf, buf_sz);
    mpack_build_map(&writer);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_ENVREPORT_FIELD_SENSORS);
    mpack_build_array(&writer);

    for (i = 0; i < n && written < nvalid; i++) {
        r = &readings[i];

        if (!cf_env_reading_valid(r))
            continue;

        written++;

        mpack_build_map(&writer);

        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_ID);
        mpack_write_str(&writer, r->id, (uint32_t) strnlen(r->id, 32));
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_KIND);
        mpack_write_u8(&writer, (uint8_t) r->kind);
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_VALUE);
        mpack_write_double(&writer, r->value);

        if (r->label != NULL && (len = strnlen(r->label, 64)) > 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_LABEL);
            mpack_write_str(&writer, r->label, (uint32_t) len);
        }

        if (r->kind == KIS_EXTERNAL_V3_ENV_KIND_BATTERY) {
            if (r->batt_state <= KIS_EXTERNAL_V3_ENV_BATT_NOT_CHARGING) {
                mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_BATT_STATE);
                mpack_write_u8(&writer, (uint8_t) r->batt_state);
            }

            if (r->ext_power == 0 || r->ext_power == 1) {
                mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_EXT_POWER);
                mpack_write_bool(&writer, r->ext_power == 1);
            }

            if (isfinite(r->voltage) && r->voltage > 0.0 && r->voltage <= 100.0) {
                mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_VOLTAGE);
                mpack_write_float(&writer, (float) r->voltage);
            }

            if (r->remaining_s > 0 && r->remaining_s <= 30 * 24 * 60 * 60) {
                mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_ENV_FIELD_REMAINING_S);
                mpack_write_u32(&writer, r->remaining_s);
            }
        }

        mpack_complete_map(&writer);
    }

    mpack_complete_array(&writer);

    if (ts != NULL) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_ENVREPORT_FIELD_TS_S);
        mpack_write_u64(&writer, (uint64_t) ts->tv_sec);
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_ENVREPORT_FIELD_TS_US);
        mpack_write_u32(&writer, (uint32_t) ts->tv_usec);
    }

    mpack_complete_map(&writer);

    len = mpack_writer_buffer_used(&writer);

    if (mpack_writer_destroy(&writer) != mpack_ok)
        return -1;

    return (ssize_t) len;
}

int cf_send_envreport(kis_capture_handler_t *caph, const cf_env_reading_t *readings, size_t n) {
    unsigned int interval;
    uint64_t now, last;
    size_t est_len;
    ssize_t final_len;
    struct timeval tv;
    cf_frame_metadata *meta;
    int r;

    if (caph == NULL || readings == NULL || n == 0)
        return 0;

    interval = __atomic_load_n(&caph->env_report_ms, __ATOMIC_ACQUIRE);

    if (interval == 0)
        return 0;

    /* Lock-free: capture threads can be cancelled at any point, so this must not
     * hold a lock of its own.  Claim the slot first; give it back if nothing went. */
    now = cf_mono_ms();
    last = __atomic_load_n(&caph->env_last_report_ms, __ATOMIC_ACQUIRE);

    /* Another thread can claim a later slot between our clock read and load */
    if (last != 0 && (now < last || now - last < interval))
        return 0;

    if (!__atomic_compare_exchange_n(&caph->env_last_report_ms, &last, now, 0,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return 0;

    if (n > KIS_EXTERNAL_V3_ENV_MAX_READINGS * 4)
        n = KIS_EXTERNAL_V3_ENV_MAX_READINGS * 4;

    est_len = cf_env_estimate_len(n);
    gettimeofday(&tv, NULL);

    meta = cf_prepare_packet(caph, KIS_EXTERNAL_V3_KDS_ENVREPORT, cf_get_next_seqno(caph), 0, est_len);

    if (meta == NULL) {
        __atomic_compare_exchange_n(&caph->env_last_report_ms, &now, last, 0,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
        return 0;
    }

    final_len = cf_env_encode((char *) meta->frame->data, est_len, readings, n, &tv);

    if (final_len <= 0) {
        cf_cancel_packet(caph, meta);
        __atomic_compare_exchange_n(&caph->env_last_report_ms, &now, last, 0,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);

        if (final_len < 0) {
            fprintf(stderr, "ERROR: Mpack couldn't serialize ENVREPORT\n");
            return -1;
        }

        return 0;
    }

    r = cf_commit_packet(caph, meta, (size_t) final_len);

    return r < 0 ? -1 : r;
}

static unsigned int cf_chan_band(kis_capture_handler_t *caph, void *privchan) {
    if (caph->chanband_cb == NULL || privchan == NULL)
        return 0;

    return (*(caph->chanband_cb))(caph, privchan);
}

static int cf_is_band_switch(kis_capture_handler_t *caph, void *privchan) {
    unsigned int band = cf_chan_band(caph, privchan);
    unsigned int last = caph->hop_timing != NULL ? caph->hop_timing->last_band : 0;

    return band != 0 && last != 0 && band != last;
}

static void cf_switch_stats_add(struct cf_switch_stats *st, uint64_t dur_ns) {
    uint64_t us = dur_ns / 1000;

    if (us > UINT32_MAX)
        us = UINT32_MAX;

    st->total++;
    st->count++;
    st->sum_us += us;

    if (st->count == 1 || us < st->min_us)
        st->min_us = (uint32_t) us;
    if (us > st->max_us)
        st->max_us = (uint32_t) us;

    if (st->ewma_ns == 0)
        st->ewma_ns = dur_ns;
    else
        st->ewma_ns = (st->ewma_ns * 7 + dur_ns) / 8;
}

/* Run the channel control callback, timing the switch and recording its window for
 * packet tagging.  Called under handler_lock. */
static int cf_timed_chancontrol(kis_capture_handler_t *caph, uint32_t seqno,
        void *privchan, char *msg) {
    struct cf_hop_timing *t = caph->hop_timing;
    struct cf_switch_window *w;
    uint64_t rt_start, rt_end, m0, m1;
    unsigned int band, pos;
    int r;

    band = cf_chan_band(caph, privchan);

    rt_start = cf_clock_ns(CLOCK_REALTIME);
    atomic_store(&caph->switch_busy_start_ns, rt_start);
    m0 = cf_clock_ns(CLOCK_MONOTONIC);

    r = (*(caph->chancontrol_cb))(caph, seqno, privchan, msg);

    m1 = cf_clock_ns(CLOCK_MONOTONIC);
    rt_end = cf_clock_ns(CLOCK_REALTIME);

    if (caph->switch_windows != NULL) {
        pos = atomic_load(&caph->switch_window_pos);
        w = &caph->switch_windows[pos % CF_SWITCH_WINDOWS];

        atomic_fetch_add(&w->seq, 1);
        atomic_store(&w->start_ns, rt_start);
        atomic_store(&w->end_ns, rt_end);
        atomic_fetch_add(&w->seq, 1);

        atomic_store(&caph->switch_window_pos, pos + 1);
    }

    atomic_store(&caph->switch_last_end_ns, rt_end);
    atomic_store(&caph->switch_busy_start_ns, 0);

    if (t == NULL)
        return r;

    if (r > 0) {
        if (band != 0) {
            if (t->last_band != 0 && band != t->last_band)
                cf_switch_stats_add(&t->band, m1 - m0);
            else
                cf_switch_stats_add(&t->chan, m1 - m0);

            t->band_known = 1;
            t->last_band = band;
        } else {
            cf_switch_stats_add(&t->chan, m1 - m0);
        }
    } else {
        t->failed++;
    }

    return r;
}

/* Packet flags for a frame captured at ts; lock-free, see switch_windows */
static uint32_t cf_packet_flags(kis_capture_handler_t *caph, struct timeval ts) {
    uint64_t t, busy, last, start, end;
    unsigned int i, s1, s2, tries;
    struct cf_switch_window *w;

    if (ts.tv_sec <= 0 || caph->switch_windows == NULL)
        return 0;

    t = (uint64_t) ts.tv_sec * CF_NS_PER_SEC + (uint64_t) ts.tv_usec * 1000ULL;

    busy = atomic_load(&caph->switch_busy_start_ns);
    if (busy != 0 && t >= busy)
        return KIS_EXTERNAL_V3_PACKET_FLAG_CHANSWITCH;

    last = atomic_load(&caph->switch_last_end_ns);
    if (last == 0 || t > last)
        return 0;

    for (i = 0; i < CF_SWITCH_WINDOWS; i++) {
        w = &caph->switch_windows[i];

        for (tries = 0; tries < 3; tries++) {
            s1 = atomic_load(&w->seq);
            start = atomic_load(&w->start_ns);
            end = atomic_load(&w->end_ns);
            s2 = atomic_load(&w->seq);

            if (s1 == s2 && (s1 & 1) == 0)
                break;
        }

        if (tries == 3)
            continue;

        if (start != 0 && t >= start && t <= end)
            return KIS_EXTERNAL_V3_PACKET_FLAG_CHANSWITCH;
    }

    return 0;
}

/* Sleep until a CLOCK_MONOTONIC time.  The hop thread runs with cancellation
 * disabled except here, so it is never cancelled holding a lock or partway
 * through a channel change. */
static void cf_hop_sleep_until(uint64_t target_ns) {
    struct timespec ts;

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_testcancel();

#if defined(__linux__) || defined(__FreeBSD__)
    ts.tv_sec = target_ns / CF_NS_PER_SEC;
    ts.tv_nsec = target_ns % CF_NS_PER_SEC;

    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) == EINTR)
        ;
#else
    while (1) {
        uint64_t now = cf_clock_ns(CLOCK_MONOTONIC);

        if (now >= target_ns)
            break;

        ts.tv_sec = (target_ns - now) / CF_NS_PER_SEC;
        ts.tv_nsec = (target_ns - now) % CF_NS_PER_SEC;
        nanosleep(&ts, NULL);
    }
#endif

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
}

/* Remember a channel which could not be tuned; returns 1 if it is new */
static int cf_hop_note_failure(kis_capture_handler_t *caph, size_t hopidx) {
    struct cf_channel_error *err;

    for (err = (struct cf_channel_error *) caph->channel_hop_failure_list;
            err != NULL; err = err->next) {
        if (err->channel_pos == hopidx)
            return 0;
    }

    err = (struct cf_channel_error *) malloc(sizeof(struct cf_channel_error));
    if (err == NULL)
        return 0;

    err->channel_pos = hopidx;
    err->next = (struct cf_channel_error *) caph->channel_hop_failure_list;
    caph->channel_hop_failure_list = err;
    caph->channel_hop_failure_list_sz++;

    return 1;
}

static int cf_hop_is_failed(kis_capture_handler_t *caph, size_t hopidx) {
    struct cf_channel_error *err;

    for (err = (struct cf_channel_error *) caph->channel_hop_failure_list;
            err != NULL; err = err->next) {
        if (err->channel_pos == hopidx)
            return 1;
    }

    return 0;
}

/* Failed positions inside the current list; an entry outside it is stale.
 * Positions are unique, as cf_hop_note_failure keeps them */
static size_t cf_hop_failed_in_list(kis_capture_handler_t *caph) {
    struct cf_channel_error *err;
    size_t n = 0;

    for (err = (struct cf_channel_error *) caph->channel_hop_failure_list;
            err != NULL; err = err->next) {
        if (err->channel_pos < caph->channel_hop_list_sz)
            n++;
    }

    return n;
}

/* Whether list entry i survives a compaction: refused entries (no private data)
 * leave a new list, failed ones the current list */
static int cf_hop_kept(kis_capture_handler_t *caph, void **privchans, size_t i) {
    if (privchans != NULL)
        return privchans[i] != NULL;

    return !cf_hop_is_failed(caph, i);
}

/* The offset into the compacted list which starts on the channel the old offset
 * started on, or on the first kept one after it in the old hop cycle.  Walks the
 * cycle pass by pass, so it costs O(list + spacing) lookups. */
static size_t cf_hop_remap_offset(kis_capture_handler_t *caph, void **privchans,
        size_t offset, size_t old_sz, int shuffle, size_t old_spacing,
        size_t new_sz, size_t new_spacing) {
    size_t s, p, pass, pass_sz, j, k, idx = 0, i, c;
    int found = 0;

    if (old_sz == 0 || new_sz == 0)
        return 0;

    s = (!shuffle || old_spacing <= 1 || old_spacing >= old_sz) ? 1 : old_spacing;

    p = offset % old_sz;
    pass = 0;
    pass_sz = (old_sz + s - 1) / s;
    while (p >= pass_sz && pass + 1 < s) {
        p -= pass_sz;
        pass++;
        pass_sz = (old_sz - pass + s - 1) / s;
    }
    j = p;

    for (k = 0; k < old_sz; k++) {
        idx = pass + j * s;

        if (idx < old_sz && cf_hop_kept(caph, privchans, idx)) {
            found = 1;
            break;
        }

        if (++j >= pass_sz) {
            pass = (pass + 1) % s;
            j = 0;
            pass_sz = (old_sz - pass + s - 1) / s;
        }
    }

    if (!found)
        return 0;

    for (i = 0, c = 0; i < idx; i++) {
        if (cf_hop_kept(caph, privchans, i))
            c++;
    }

    if (c >= new_sz)
        return 0;

    return cf_chanhop_pos(c, new_sz, shuffle, new_spacing);
}

/* Drop the channels the source refused (no private data) from a new hop list, in
 * place; returns the size left.  The offset is moved onto the compacted list, so
 * the source starts where the server meant; the configured spacing is kept, as
 * the prune keeps it. */
static size_t cf_hop_drop_refused(kis_capture_handler_t *caph, char **chans,
        void **privchans, size_t chan_sz, int shuffle, int spacing, int *offset) {
    size_t i, ni, old_spacing, new_spacing, new_offset;

    for (i = 0, ni = 0; i < chan_sz; i++) {
        if (privchans[i] != NULL)
            ni++;
    }

    old_spacing = spacing > 0 ? (size_t) spacing : 0;
    new_spacing = cf_hop_valid_spacing(shuffle, old_spacing, ni);
    new_offset = cf_hop_remap_offset(caph, privchans, *offset > 0 ? (size_t) *offset : 0,
            chan_sz, shuffle, old_spacing, ni, new_spacing);

    for (i = 0, ni = 0; i < chan_sz; i++) {
        if (privchans[i] == NULL) {
            cf_free_hop_entry(caph, chans[i], NULL);
            continue;
        }

        chans[ni] = chans[i];
        privchans[ni] = privchans[i];
        ni++;
    }

    *offset = (int) new_offset;

    return ni;
}

/* Drop the channels which failed from the hop list.  Only for hopping on our own
 * timer; a synced source keeps its list so it stays on the shared schedule.
 * Returns -1 if hopping must stop. */
static int cf_hop_prune_failures(kis_capture_handler_t *caph) {
    char errstr[STATUS_MAX];
    char **channel_hop_list_new;
    void **custom_channel_hop_list_new;
    size_t new_sz, new_spacing, new_offset;
    size_t i, ni, failed;

    /* Failed positions always lie in the current list; one that doesn't is
     * stale, and only the positions inside the list are dropped */
    failed = cf_hop_failed_in_list(caph);

    if (failed != caph->channel_hop_failure_list_sz) {
        snprintf(errstr, STATUS_MAX, "Ignoring %lu of the %lu channel errors, which are "
                "not in the %lu assigned channels",
                (unsigned long) (caph->channel_hop_failure_list_sz - failed),
                (unsigned long) caph->channel_hop_failure_list_sz,
                (unsigned long) caph->channel_hop_list_sz);
        fprintf(stderr, "WARNING: %s\n", errstr);
        cf_send_warning(caph, errstr);
    }

    if (failed == 0) {
        cf_hop_clear_failures(caph);
        return 0;
    }

    new_sz = caph->channel_hop_list_sz - failed;

    if (new_sz == 0) {
        snprintf(errstr, STATUS_MAX, "All configured channels are in error state!");
        cf_send_error(caph, 0, errstr);
        return -1;
    }

    channel_hop_list_new = (char **) malloc(sizeof(char *) * new_sz);
    custom_channel_hop_list_new = (void **) malloc(sizeof(void *) * new_sz);

    if (channel_hop_list_new == NULL || custom_channel_hop_list_new == NULL) {
        free(channel_hop_list_new);
        free(custom_channel_hop_list_new);
        return 0;
    }

    /* The offset follows the shorter list.  The configured spacing stays, since
     * a later list without one inherits it; the cycle and the reports use
     * the effective one */
    new_spacing = cf_hop_valid_spacing(caph->channel_hop_shuffle,
            caph->channel_hop_shuffle_spacing, new_sz);
    new_offset = cf_hop_remap_offset(caph, NULL,
            caph->channel_hop_offset > 0 ? (size_t) caph->channel_hop_offset : 0,
            caph->channel_hop_list_sz, caph->channel_hop_shuffle,
            caph->channel_hop_shuffle_spacing, new_sz, new_spacing);

    /* Every entry is visited, so failed ones at the end are freed too */
    for (i = 0, ni = 0; i < caph->channel_hop_list_sz; i++) {
        /* If it's in error, free it */
        if (cf_hop_is_failed(caph, i)) {
            cf_free_hop_entry(caph, caph->channel_hop_list[i], caph->custom_channel_hop_list[i]);
            continue;
        }

        /* Otherwise move the pointer to our new list */
        channel_hop_list_new[ni] = caph->channel_hop_list[i];
        custom_channel_hop_list_new[ni] = caph->custom_channel_hop_list[i];
        ni++;
    }

    /* Remove the old lists and swap in the new ones */
    free(caph->channel_hop_list);
    free(caph->custom_channel_hop_list);

    caph->channel_hop_list = channel_hop_list_new;
    caph->custom_channel_hop_list = custom_channel_hop_list_new;
    caph->channel_hop_list_sz = ni;
    caph->channel_hop_offset = (int) new_offset;

    /* Spam a configresp which should trigger a reconfigure */
    snprintf(errstr, STATUS_MAX, "Removed %lu channels from the channel list "
            "because the source could not tune to them", (unsigned long) failed);
    cf_send_configresp(caph, 0, 1, errstr);

    cf_hop_clear_failures(caph);

    return 0;
}

/* Internal capture thread which drives channel hopping.
 *
 * Synced, every source hops on the same grid of slots (1/rate long, counted from
 * the server's epoch), so sources at the same rate change channels together and
 * the channel for a slot is fixed: no per-hop traffic, and a source joins in step.
 * A switch starts early by its expected duration, so it lands on the slot
 * boundary.  Not synced, the source hops on its own timer as before.
 */
static void cf_chanhop_thread_exited(void *arg) {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) arg;
    cf_thread_exited_unwound(&caph->hop_live);
}

static void cf_int_chanhop_loop(kis_capture_handler_t *caph);

/* The loop returns from many places, with cancels off; the exit is counted
 * here, on return and on a cancel in its sleep */
CF_UNWIND_FRAME void *cf_int_chanhop_thread(void *arg) {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) arg;

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    pthread_cleanup_push(cf_chanhop_thread_exited, caph);
    cf_int_chanhop_loop(caph);
    pthread_cleanup_pop(0);

    cf_thread_exited(caph, &caph->hop_live);

    return NULL;
}

static void cf_int_chanhop_loop(kis_capture_handler_t *caph) {
    unsigned int gen;

    /* Own timer: next position in the hop cycle, and when to move to it */
    size_t hoppos;
    uint64_t next_ns;

    /* Synced: the last slot switched into */
    uint64_t last_slot = 0;
    int have_slot = 0;

    size_t hopidx, pos;
    uint64_t now, wake, dwell, srv, rel, slot, target, lead, start_srv, step;
    struct cf_hop_timing *t;

    char errstr[STATUS_MAX];

    int r = 0;
    int skip, joining, noted;

    /* Cancelled only while sleeping; see cf_hop_sleep_until */
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    pthread_mutex_lock(&(caph->handler_lock));
    gen = caph->hop_generation;
    hoppos = caph->channel_hop_offset;
    next_ns = cf_clock_ns(CLOCK_MONOTONIC) + cf_hop_dwell_ns(caph);
    pthread_mutex_unlock(&(caph->handler_lock));

    while (1) {
        pthread_mutex_lock(&(caph->handler_lock));

        /* A newer configuration owns the hop state now */
        if (gen != caph->hop_generation) {
            pthread_mutex_unlock(&(caph->handler_lock));
            return;
        }

        /* Cancel thread if we're no longer hopping */
        if (caph->channel_hop_rate == 0 || caph->hopping_running == 0 ||
                caph->chancontrol_cb == NULL || caph->channel_hop_list_sz == 0) {
            caph->hopping_running = 0;
            pthread_mutex_unlock(&(caph->handler_lock));
            return;
        }

        t = caph->hop_timing;
        now = cf_clock_ns(CLOCK_MONOTONIC);
        dwell = cf_hop_dwell_ns(caph);
        wake = UINT64_MAX;
        hopidx = 0;
        skip = 0;
        target = 0;

        step = cf_hop_report_step(caph, now);
        if (step < wake)
            wake = step;

        if (caph->hop_sync) {
            step = cf_hop_clock_step(caph, now);
            if (step < wake)
                wake = step;

            srv = cf_hop_server_ns(caph->hop_clock, now);
            rel = srv > caph->hop_sync_epoch_ns ? srv - caph->hop_sync_epoch_ns : 0;
            slot = rel / dwell;

            if (!have_slot) {
                /* Start on the channel of the slot we're in */
                target = slot;
            } else {
                target = last_slot + 1;

                /* Late by more than a slot: rejoin the schedule where it is now */
                if (slot > target) {
                    if (t != NULL)
                        t->missed += slot - target;
                    target = slot;
                }
            }

            pos = (size_t) ((target % caph->channel_hop_list_sz +
                        (uint64_t) caph->channel_hop_offset % caph->channel_hop_list_sz) %
                    caph->channel_hop_list_sz);
            hopidx = cf_chanhop_index(pos, caph->channel_hop_list_sz,
                    caph->channel_hop_shuffle, caph->channel_hop_shuffle_spacing);

            lead = 0;
            if (t != NULL) {
                if (cf_is_band_switch(caph, caph->custom_channel_hop_list[hopidx]))
                    lead = t->band.ewma_ns;
                else
                    lead = t->chan.ewma_ns;
            }
            if (lead > dwell / 2)
                lead = dwell / 2;

            start_srv = caph->hop_sync_epoch_ns + target * dwell;
            start_srv = start_srv > lead ? start_srv - lead : 0;

            if (have_slot && srv < start_srv) {
                /* Not yet; sleep until the switch should start */
                if (now + (start_srv - srv) < wake)
                    wake = now + (start_srv - srv);
                pthread_mutex_unlock(&(caph->handler_lock));
                cf_hop_sleep_until(wake);
                continue;
            }

            joining = !have_slot;
            have_slot = 1;
            last_slot = target;

            /* Synced sources keep failed channels in the list and sit out their slots */
            skip = cf_hop_is_failed(caph, hopidx);

            /* Joining the schedule on the channel we're already on */
            if (joining && t != NULL && caph->channel_hop_list[hopidx] != NULL &&
                    strcmp(t->last_chan, caph->channel_hop_list[hopidx]) == 0)
                skip = 1;
        } else {
            if (now < next_ns) {
                if (next_ns < wake)
                    wake = next_ns;
                pthread_mutex_unlock(&(caph->handler_lock));
                cf_hop_sleep_until(wake);
                continue;
            }

            hopidx = cf_chanhop_index(hoppos, caph->channel_hop_list_sz,
                    caph->channel_hop_shuffle, caph->channel_hop_shuffle_spacing);
        }

        /* Channels the source refused are marked failed (synced) or dropped (not
         * synced) when a configure request assigns the list.  A NULL slot from
         * any other path is marked failed here, so a synced source sits it out
         * and the prune drops it; never hand one to channel control */
        noted = 0;

        if (caph->custom_channel_hop_list[hopidx] == NULL) {
            skip = 1;
            noted = cf_hop_note_failure(caph, hopidx);
        }

        if (!skip) {
            errstr[0] = 0;
            r = cf_timed_chancontrol(caph, 0, caph->custom_channel_hop_list[hopidx], errstr);

            if (r > 0 && t != NULL && caph->channel_hop_list[hopidx] != NULL)
                snprintf(t->last_chan, sizeof(t->last_chan), "%s", caph->channel_hop_list[hopidx]);

            if (r < 0) {
                fprintf(stderr, "FATAL:  Datasource channel control callback failed.\n");
                cf_send_error(caph, 0, errstr);
                caph->hopping_running = 0;
                pthread_mutex_unlock(&caph->handler_lock);
                cf_handler_spindown(caph);
                return;
            } else if (r == 0) {
                noted = cf_hop_note_failure(caph, hopidx);

                if (noted && caph->hop_sync) {
                    snprintf(errstr, STATUS_MAX, "Could not tune to channel %s; skipping it "
                            "while hopping", caph->channel_hop_list[hopidx]);
                    cf_send_warning(caph, errstr);
                }
            }
        }

        /* Stop once every position of the list has failed; stale entries outside
         * it don't count, as in the prune */
        if (noted && cf_hop_failed_in_list(caph) >= caph->channel_hop_list_sz) {
            snprintf(errstr, STATUS_MAX, "All configured channels are in error state!");
            cf_send_error(caph, 0, errstr);
            caph->hopping_running = 0;
            pthread_mutex_unlock(&caph->handler_lock);
            cf_handler_spindown(caph);
            return;
        }

        if (!caph->hop_sync) {
            hoppos = (hoppos + 1) % caph->channel_hop_list_sz;

            /* Hop again a dwell after the last one, or after this one if it ran long */
            now = cf_clock_ns(CLOCK_MONOTONIC);
            next_ns += dwell;
            if (next_ns < now)
                next_ns = now + dwell;

            /* Once around the list, drop the channels the source can't tune */
            if (hoppos == 0 && caph->channel_hop_failure_list_sz != 0) {
                if (cf_hop_prune_failures(caph) < 0) {
                    caph->hopping_running = 0;
                    pthread_mutex_unlock(&caph->handler_lock);
                    cf_handler_spindown(caph);
                    return;
                }
            }
        }

        pthread_mutex_unlock(&caph->handler_lock);
    }
}

int cf_handler_launch_hopping_thread(kis_capture_handler_t *caph) {
    /* Set the thread attributes - detached, cancelable */
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setschedpolicy(&attr, SCHED_FIFO);

    pthread_mutex_lock(&(caph->handler_lock));

    /* Going down: shutdown already stopped hopping, and frees what a hop uses */
    if (caph->spindown || caph->shutdown || caph->shutdown_done) {
        pthread_mutex_unlock(&(caph->handler_lock));
        pthread_attr_destroy(&attr);
        cf_send_error(caph, 0, "source is closing, not starting a channel hopping thread");
        return -1;
    }

    if (caph->hopping_running) {
        pthread_cancel(caph->hopthread);
        caph->hopping_running = 0;
    }

    caph->hop_generation++;

    /* A new hop list keeps the clock estimate; only the first synced hop starts one */
    if (caph->hop_sync && caph->hop_clock != NULL &&
            caph->hop_clock->state == KIS_EXTERNAL_V3_HOPSYNC_OFF)
        cf_hop_clock_reset(caph->hop_clock);

    /* Running before the thread starts, so a thread which reads it never sees a
     * stale 0 */
    caph->hopping_running = 1;
    cf_thread_started(&caph->hop_live);

    if (pthread_create(&(caph->hopthread), &attr, cf_int_chanhop_thread, caph) != 0) {
        cf_thread_exited(caph, &caph->hop_live);
        caph->hopping_running = 0;
        pthread_mutex_unlock(&(caph->handler_lock));
        pthread_attr_destroy(&attr);
        cf_send_error(caph, 0, "failed to launch channel hopping thread");
        cf_handler_spindown(caph);
        return -1;
    }

    pthread_mutex_unlock(&(caph->handler_lock));
    pthread_attr_destroy(&attr);

    return 1;
}

/* Copy a plain name (serial device paths included) into the source label; the
 * label only reaches message text */
static int cf_try_source_label(kis_capture_handler_t *caph, const char *s, int len) {
    if (s == NULL || len <= 0 || (size_t) len >= sizeof(caph->source_label))
        return 0;

    if (!cf_name_chars_ok(s, (size_t) len, "_.-:/"))
        return 0;

    memcpy(caph->source_label, s, (size_t) len);
    caph->source_label[len] = 0;

    return 1;
}

/* Remember the source's name, else its interface, else its UUID, for the
 * framework's own messages; under handler_lock.  The server already names a
 * remote source in front of each of its messages, so a remote source gets none */
static void cf_set_source_label(kis_capture_handler_t *caph, char *definition,
        const char *uuid) {
    char *val = NULL;
    int len;

    caph->source_label[0] = 0;

    if (caph->remote_host != NULL)
        return;

    if (definition != NULL) {
        len = cf_find_flag(&val, "name", definition);
        if (cf_try_source_label(caph, val, len))
            return;

        val = NULL;
        len = cf_parse_interface(&val, definition);
        if (cf_try_source_label(caph, val, len))
            return;
    }

    if (uuid != NULL)
        cf_try_source_label(caph, uuid, (int) strnlen(uuid, sizeof(caph->source_label)));
}

static const char *cf_source_label(kis_capture_handler_t *caph) {
    return caph->source_label[0] != 0 ? caph->source_label : "Source";
}

/* Answer a configure request whose channels the source refused.  The report
 * succeeds, with a warning: a failed one makes the server close the source, and
 * the current channel and hop list, which it carries, are still in force.  The
 * report's text reaches no log, so the warning also goes out as a message, after
 * the report so a full ring drops the message first */
static int cf_send_chan_refused(kis_capture_handler_t *caph, uint32_t seqno, const char *msg) {
    char warn[STATUS_MAX];
    int r;

    snprintf(warn, sizeof(warn), "%s %s; keeping the current channel configuration",
            cf_source_label(caph), msg);

    r = cf_send_configresp(caph, seqno, 1, warn);

    cf_send_warning(caph, warn);

    return r;
}

/* Common dispatch layer */
int cf_dispatch_rx_content(kis_capture_handler_t *caph, unsigned int cmd,
        uint32_t seqno, const uint8_t *data, size_t packet_sz) {
    int cbret = -1;
    char msgstr[STATUS_MAX];
    size_t i;

    /* Arrival time of a sync answer, taken before waiting on the lock, which a
     * channel change holds */
    uint64_t rx_mono_ns = 0;

    if (cmd == KIS_EXTERNAL_V3_KDS_TIMESYNCREPORT)
        rx_mono_ns = cf_clock_ns(CLOCK_MONOTONIC);

    pthread_mutex_lock(&(caph->handler_lock));

    if (cmd == KIS_EXTERNAL_V3_CMD_PING) {
        caph->last_ping = time(0);
        if (cf_send_pong(caph, seqno) > 0)
            cf_out_ctl_drop_report(caph);
        cbret = 1;
        goto finish;
    } else if (cmd == KIS_EXTERNAL_V3_CMD_PONG) {
        cbret = 1;
        goto finish;
    } else if (cmd == KIS_EXTERNAL_V3_KDS_TIMESYNCREPORT) {
        mpack_tree_t tree;
        mpack_node_t root;
        uint64_t t1, t2, t3;

        cbret = 1;

        mpack_tree_init_data(&tree, (const char *) data, packet_sz);

        if (!mpack_tree_try_parse(&tree)) {
            mpack_tree_destroy(&tree);
            goto finish;
        }

        root = mpack_tree_root(&tree);
        t1 = mpack_node_u64(mpack_node_map_uint(root, KIS_EXTERNAL_V3_KDS_TIMESYNCREPORT_FIELD_T1));
        t2 = mpack_node_u64(mpack_node_map_uint(root, KIS_EXTERNAL_V3_KDS_TIMESYNCREPORT_FIELD_RX));
        t3 = mpack_node_u64(mpack_node_map_uint(root, KIS_EXTERNAL_V3_KDS_TIMESYNCREPORT_FIELD_TX));

        if (mpack_tree_error(&tree) == mpack_ok)
            cf_hop_clock_sample(caph, t1, t2, t3, rx_mono_ns);

        mpack_tree_destroy(&tree);
        goto finish;
    } else if (cmd == KIS_EXTERNAL_V3_KDS_CLOSEREQ) {
        /* Graceful close.  An opted-in source with a running capture
         * thread finishes its own teardown and spins down; the loop enforces
         * the deadline.  Anything else has no teardown to run, so it spins down
         * now -- which still drains whatever is queued before it exits. */
        if (!caph->close_requested) {
            __atomic_store_n(&caph->close_requested, 1, __ATOMIC_RELEASE);

            /* The grace counts against the exit waits that follow */
            cf_exit_deadline_start(caph);

            if (caph->close_grace_ms > 0 && caph->capture_running) {
                caph->close_deadline_ms = cf_mono_ms() + caph->close_grace_ms;
            } else {
                caph->spindown = 1;
            }
        }

        pthread_mutex_unlock(&(caph->handler_lock));
        cf_handler_wake_loop(caph);
        return 1;
    } else if (cmd == KIS_EXTERNAL_V3_KDS_LISTREQ) {
        if (caph->listdevices_cb == NULL) {
            if (caph->verbose) {
                fprintf(stderr, "ERROR:  Capture source (%s) does not support "
                        "listing datasources\n", caph->capsource_type);
            }

            cf_send_listresp(caph, seqno, true, "", NULL, 0);
            cbret = -1;
            goto finish;
        } else {
            cf_params_list_interface_t **interfaces = NULL;
            msgstr[0] = 0;
            cbret = (*(caph->listdevices_cb))(caph, seqno, msgstr, &interfaces);

            if (caph->verbose && strlen(msgstr) > 0) {
                if (cbret >= 0)
                    fprintf(stderr, "INFO: %s\n", msgstr);
                else
                    fprintf(stderr, "ERROR: %s\n", msgstr);
            }

            cf_send_listresp(caph, seqno, cbret >= 0, msgstr, interfaces, cbret < 0 ? 0 : cbret);

            if (cbret > 0) {
                for (i = 0; i < (size_t) cbret; i++) {
                    if (interfaces[i] != NULL) {
                        if (interfaces[i]->interface != NULL)
                            free(interfaces[i]->interface);
                        if (interfaces[i]->flags != NULL)
                            free(interfaces[i]->flags);
                        if (interfaces[i]->hardware != NULL)
                            free(interfaces[i]->hardware);

                        free(interfaces[i]);
                    }
                }

                free(interfaces);
            }

            /* Always spin down after listing */
            cf_handler_spindown(caph);
            goto finish;
        }
    } else if (cmd == KIS_EXTERNAL_V3_KDS_PROBEREQ) {
        if (caph->probe_cb == NULL) {
            if (caph->verbose) {
                fprintf(stderr, "ERROR:  Capture source (%s) does not support automatic "
                        "probing.\n", caph->capsource_type);
            }

            pthread_mutex_unlock(&(caph->handler_lock));
            cf_send_proberesp(caph, seqno, false, "Source does not support probing", NULL, NULL);
            pthread_mutex_lock(&(caph->handler_lock));

            cbret = -1;
            goto finish;
        } else {
            cf_params_interface_t *interfaceparams = NULL;
            cf_params_spectrum_t *spectrumparams = NULL;

            char *uuid = NULL;

            mpack_tree_t tree;
            mpack_node_t root;

            char *definition;

            mpack_tree_init_data(&tree, (const char *) data, packet_sz);

            if (!mpack_tree_try_parse(&tree)) {
                fprintf(stderr, "FATAL: Invalid probe request received, unable to unpack command.\n");
                cbret = -1;
                mpack_tree_destroy(&tree);
                goto finish;
            }

            root = mpack_tree_root(&tree);

            if (!mpack_node_map_contains_uint(root, KIS_EXTERNAL_V3_KDS_PROBEREQ_FIELD_DEFINITION)) {
                fprintf(stderr, "FATAL: Invalid probe request received, unable to unpack source definition.\n");
                cbret = -1;
                mpack_tree_destroy(&tree);
                goto finish;
            }

            definition = mpack_node_cstr_alloc(mpack_node_map_uint(root,
                        KIS_EXTERNAL_V3_KDS_PROBEREQ_FIELD_DEFINITION), 4096);

            if (mpack_tree_error(&tree) != mpack_ok) {
                fprintf(stderr, "FATAL: Invalid probe request received, unable to unpack source definition.\n");
                cbret = -1;
                mpack_tree_destroy(&tree);
                if (definition != NULL) {
                    free(definition);
                }
                goto finish;
            }

            msgstr[0] = 0;
            cbret = (*(caph->probe_cb))(caph, seqno, definition, msgstr, &uuid,
                    &interfaceparams, &spectrumparams);

            if (definition != NULL) {
                free(definition);
            }

            cf_send_proberesp(caph, seqno, cbret < 0 ? 0 : cbret, msgstr, interfaceparams, spectrumparams);

            mpack_tree_destroy(&tree);

            if (uuid != NULL)
                free(uuid);

            if (interfaceparams != NULL)
                cf_params_interface_free(interfaceparams);

            if (spectrumparams != NULL)
                cf_params_spectrum_free(spectrumparams);

            /* Always spin down after probing */
            cf_handler_spindown(caph);

            goto finish;
        }
    } else if (cmd == KIS_EXTERNAL_V3_KDS_OPENREQ) {
        if (caph->open_cb == NULL) {
            if (caph->verbose) {
                fprintf(stderr, "ERROR:  Capture source (%s) does not support opening\n",
                        caph->capsource_type);
            }

            pthread_mutex_unlock(&(caph->handler_lock));
            cf_send_openresp(caph, seqno, false, "source cannot be opened", 0,
                    NULL, NULL, NULL);
            pthread_mutex_lock(&(caph->handler_lock));

            cbret = -1;
            goto finish;
        } else if (caph->capture_running || cf_thread_live(&caph->capture_live)) {
            /* Sources free their state on open; re-opening under a running capture
             * thread, or one still leaving with cancels off, would pull it out from
             * under it */
            pthread_mutex_unlock(&(caph->handler_lock));
            cf_send_openresp(caph, seqno, false, caph->capture_running ?
                    "source is already open and capturing" :
                    "source is still closing its last capture", 0,
                    NULL, NULL, NULL);
            pthread_mutex_lock(&(caph->handler_lock));

            cbret = 0;
            goto finish;
        } else {
            cf_params_interface_t *interfaceparams = NULL;
            cf_params_spectrum_t *spectrumparams = NULL;

            char *uuid = NULL;

            mpack_tree_t tree;
            mpack_node_t root;

            char *definition;

            mpack_tree_init_data(&tree, (const char *) data, packet_sz);

            if (!mpack_tree_try_parse(&tree)) {
                fprintf(stderr, "FATAL: Invalid open request received, unable to unpack command.\n");
                cbret = -1;
                mpack_tree_destroy(&tree);
                goto finish;
            }

            root = mpack_tree_root(&tree);

            if (!mpack_node_map_contains_uint(root, KIS_EXTERNAL_V3_KDS_OPENREQ_FIELD_DEFINITION)) {
                fprintf(stderr, "FATAL: Invalid open request received, unable to unpack source definition.\n");
                cbret = -1;
                mpack_tree_destroy(&tree);
                goto finish;
            }

            definition = mpack_node_cstr_alloc(mpack_node_map_uint(root,
                        KIS_EXTERNAL_V3_KDS_OPENREQ_FIELD_DEFINITION), 8192);

            if (mpack_tree_error(&tree) != mpack_ok) {
                fprintf(stderr, "FATAL: Invalid open request received, unable to unpack source definition.\n");
                cbret = -1;
                mpack_tree_destroy(&tree);
                if (definition != NULL) {
                    free(definition);
                }
                goto finish;
            }

            uint32_t dlt;
            int launchret;

            /* Only a server which takes sensor reports asks for them; a bad value
             * leaves them off rather than failing the open */
            {
                uint32_t env_ms = 0;
                mpack_node_t env_n =
                    mpack_node_map_uint_optional(root, KIS_EXTERNAL_V3_KDS_OPENREQ_FIELD_ENV_REPORT_MS);

                if (!mpack_node_is_missing(env_n) && mpack_node_type(env_n) == mpack_type_uint) {
                    env_ms = mpack_node_u32(env_n);

                    if (mpack_tree_error(&tree) != mpack_ok)
                        env_ms = 0;
                    else if (env_ms != 0 && env_ms < 1000)
                        env_ms = 1000;
                    else if (env_ms > 3600000)
                        env_ms = 3600000;
                }

                __atomic_store_n(&caph->env_last_report_ms, 0, __ATOMIC_RELEASE);
                __atomic_store_n(&caph->env_report_ms, env_ms, __ATOMIC_RELEASE);
            }

            msgstr[0] = 0;
            cbret = (*(caph->open_cb))(caph, seqno, definition,
                    msgstr, &dlt, &uuid, &interfaceparams, &spectrumparams);

            cf_set_source_label(caph, definition, uuid);

            /* Capture thread first, so a refused launch is a failed open and not
             * a success followed by an error.  Its sends wait on handler_lock (the
             * seqno), held here, so the openresp still goes out first. */
            launchret = 0;
            if (cbret >= 0) {
                launchret = cf_launch_capture_thread_msg(caph, msgstr);
                if (launchret < 0)
                    cbret = -1;
            }

            cf_send_openresp(caph, seqno, cbret < 0 ? 0 : 1, msgstr, dlt, uuid,
                    interfaceparams, spectrumparams);

            if (launchret == -2)
                cf_handler_spindown(caph);

            if (uuid != NULL)
                free(uuid);

            if (definition != NULL)
                free(definition);

            mpack_tree_destroy(&tree);

            if (interfaceparams != NULL)
                cf_params_interface_free(interfaceparams);

            if (spectrumparams != NULL)
                cf_params_spectrum_free(spectrumparams);

            if (caph->remote_host) {
                fprintf(stderr, "INFO: %s:%u starting capture...\n", caph->remote_host, caph->remote_port);
            }

            goto finish;
        }
    } else if (cmd == KIS_EXTERNAL_V3_KDS_CONFIGREQ) {
        double chanhop_rate = 0;
        char **chanhop_channels = NULL;
        void **chanhop_priv_channels = NULL;
        size_t chanhop_channels_sz = 0, chanhop_refused = 0, chanhop_assign_sz = 0, szi = 0;
        int chanhop_shuffle = 0, chanhop_shuffle_spacing = 1, chanhop_offset = 0;
        int chanhop_sync = 0, chanhop_rate_bad = 0;
        uint64_t chanhop_sync_epoch = 0;
        void *translate_chan = NULL;

        mpack_tree_t tree;
        mpack_node_t root;

        mpack_tree_init_data(&tree, (const char *) data, packet_sz);

        if (!mpack_tree_try_parse(&tree)) {
            fprintf(stderr, "FATAL: Invalid configure request received, unable to unpack command.\n");
            cbret = -1;
            mpack_tree_destroy(&tree);
            goto finish;
        }

        root = mpack_tree_root(&tree);

        if (mpack_node_type(root) != mpack_type_map) {
            fprintf(stderr, "FATAL: Invalid configure request received, not a map.\n");
            cbret = -1;
            mpack_tree_destroy(&tree);
            goto finish;
        }

        /* Only a server which takes hop timing reports asks for them */
        if (mpack_node_map_contains_uint(root, KIS_EXTERNAL_V3_KDS_CONFIGREQ_FIELD_REPORT_MS)) {
            uint32_t report_ms =
                mpack_node_u32(mpack_node_map_uint(root, KIS_EXTERNAL_V3_KDS_CONFIGREQ_FIELD_REPORT_MS));

            if (mpack_tree_error(&tree) != mpack_ok) {
                fprintf(stderr, "FATAL: Invalid configure request received, unable to unpack report interval.\n");
                cbret = -1;
                mpack_tree_destroy(&tree);
                goto finish;
            }

            if (report_ms != 0 && report_ms < 1000)
                report_ms = 1000;
            else if (report_ms > 3600000)
                report_ms = 3600000;

            caph->hop_report_ms = report_ms;
        }

        /* Without channel control only a request with nothing to tune succeeds */
        if (caph->chancontrol_cb == NULL &&
                (mpack_node_map_contains_uint(root, KIS_EXTERNAL_V3_KDS_CONFIGREQ_FIELD_CHANNEL) ||
                 mpack_node_map_contains_uint(root, KIS_EXTERNAL_V3_KDS_CONFIGREQ_FIELD_CHANHOPBLOCK))) {
            if (caph->verbose) {
                fprintf(stderr, "ERROR:  Capture source (%s) does not support channel configuration\n",
                        caph->capsource_type);
            }

            mpack_tree_destroy(&tree);

            pthread_mutex_unlock(&(caph->handler_lock));
            cf_send_configresp(caph, seqno, 0, "source does not support channel configuration");
            pthread_mutex_lock(&(caph->handler_lock));

            cbret = -1;
            goto finish;
        }

        if (mpack_node_map_contains_uint(root, KIS_EXTERNAL_V3_KDS_CONFIGREQ_FIELD_CHANNEL)) {
            char channel[1024];
            mpack_node_copy_cstr(mpack_node_map_uint(root, KIS_EXTERNAL_V3_KDS_CONFIGREQ_FIELD_CHANNEL), channel, 1024);

            if (mpack_tree_error(&tree) != mpack_ok) {
                fprintf(stderr, "FATAL: Invalid configure request received, unable to unpack channel definition.\n");
                cbret = -1;
                mpack_tree_destroy(&tree);
                goto finish;
            }

            if (caph->chantranslate_cb != NULL) {
                translate_chan = (*(caph->chantranslate_cb))(caph, channel);
            } else {
                translate_chan = strdup(channel);
            }

            /* A channel the source refuses changes nothing: the current
             * channel and any hopping stay as they are */
            if (translate_chan == NULL) {
                if (cf_send_chan_refused(caph, seqno, strchr(channel, '=') != NULL ?
                            "could not process the requested setting" :
                            "could not use the requested channel") < 0) {
                    cbret = -1;
                    fprintf(stderr, "FATAL: Unable to send configure response.\n");
                } else {
                    cbret = 1;
                }

                mpack_tree_destroy(&tree);
                goto finish;
            }

            /* Cancel channel hopping when told a single channel.
             *
             * Not for a `key=value` string: the cell sources carry
             * their runtime SETTINGS on this route (strategy=,
             * clock_anchor_sec=), and a scan-profile switch must not end a
             * band hop the operator started. No channel name of any driver
             * contains '='. */
            if (caph->hopping_running && strchr(channel, '=') == NULL) {
                pthread_cancel(caph->hopthread);
                caph->hop_generation++;
                caph->hopping_running = 0;
            }

            msgstr[0] = 0;

            /* Settings aren't channel changes; don't time them or tag packets */
            if (strchr(channel, '=') == NULL) {
                cbret = cf_timed_chancontrol(caph, seqno, translate_chan, msgstr);
                cf_hop_report_step(caph, cf_clock_ns(CLOCK_MONOTONIC));
            } else {
                cbret = (*(caph->chancontrol_cb))(caph, seqno, translate_chan, msgstr);
            }

            /* Log the channel we're set to */
            if (cbret > 0) {
                if (caph->channel != NULL)
                    free(caph->channel);
                caph->channel = strdup(channel);

                if (caph->hop_timing != NULL && strchr(channel, '=') == NULL)
                    snprintf(caph->hop_timing->last_chan, sizeof(caph->hop_timing->last_chan),
                            "%s", channel);
            }

            /* Send a response based on the channel set success */
            if (cf_send_configresp(caph, seqno, cbret < 0 ? 0 : 1, msgstr) < 0) {
                cbret = -1;
                fprintf(stderr, "FATAL: Unable to send configure response.\n");
            }

            /* Free our channel copies */
            if (caph->chanfree_cb != NULL)
                (*(caph->chanfree_cb))(translate_chan);
            else
                free(translate_chan);

            mpack_tree_destroy(&tree);

            goto finish;
        }

        if (mpack_node_map_contains_uint(root, KIS_EXTERNAL_V3_KDS_CONFIGREQ_FIELD_CHANHOPBLOCK)) {
            mpack_node_t chanhop;
            mpack_node_t chanlist;

            chanhop = mpack_node_map_uint(root, KIS_EXTERNAL_V3_KDS_CONFIGREQ_FIELD_CHANHOPBLOCK);

            if (mpack_tree_error(&tree) != mpack_ok) {
                fprintf(stderr, "FATAL: Invalid configure request received, unable to unpack channel hop definition.\n");
                cbret = -1;
                mpack_tree_destroy(&tree);
                goto finish;
            }

            if (!mpack_node_map_contains_uint(chanhop, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_CHAN_LIST)) {
                fprintf(stderr, "FATAL: Invalid configure request received, missing required channel list field.\n");
                cbret = -1;
                mpack_tree_destroy(&tree);
                goto finish;
            }

            chanlist = mpack_node_map_uint(chanhop, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_CHAN_LIST);
            if (mpack_tree_error(&tree) != mpack_ok) {
                fprintf(stderr, "FATAL: Invalid configure request received, unable to unpack channel hop list.\n");
                cbret = -1;
                mpack_tree_destroy(&tree);
                goto finish;
            }

            if (mpack_node_array_length(chanlist) == 0 || mpack_tree_error(&tree) != mpack_ok) {
                fprintf(stderr, "FATAL: Invalid configure request received, unable to unpack channel hop list.\n");
                cbret = -1;
                mpack_tree_destroy(&tree);
                goto finish;
            }

            chanhop_channels_sz = mpack_node_array_length(chanlist);
            chanhop_channels = (char **) calloc(chanhop_channels_sz ? chanhop_channels_sz : 1, sizeof(char *));

            if (chanhop_channels == NULL) {
                fprintf(stderr, "FATAL: Could not allocate channel hop list.\n");
                cbret = -1;
                mpack_tree_destroy(&tree);
                goto finish;
            }

            for (szi = 0; szi < chanhop_channels_sz; szi++) {
                chanhop_channels[szi] = mpack_node_cstr_alloc(mpack_node_array_at(chanlist, szi), 64);

                if (mpack_tree_error(&tree) != mpack_ok) {
                    fprintf(stderr, "FATAL: Invalid configure request received, unable to unpack channel hop list.\n");
                    cf_free_hop_lists(caph, chanhop_channels, NULL, chanhop_channels_sz);
                    cbret = -1;
                    mpack_tree_destroy(&tree);
                    goto finish;
                }
            }

            /* translate or duplicate all the channels to native channel definitions */
            chanhop_priv_channels = (void **) calloc(chanhop_channels_sz ? chanhop_channels_sz : 1, sizeof(void *));

            if (chanhop_priv_channels == NULL) {
                fprintf(stderr, "FATAL: Could not allocate channel hop list.\n");
                cf_free_hop_lists(caph, chanhop_channels, NULL, chanhop_channels_sz);
                cbret = -1;
                mpack_tree_destroy(&tree);
                goto finish;
            }

            for (szi = 0; szi < chanhop_channels_sz; szi++) {
                if (caph->chantranslate_cb != NULL) {
                    chanhop_priv_channels[szi] = (*(caph->chantranslate_cb))(caph, chanhop_channels[szi]);
                } else {
                    chanhop_priv_channels[szi] = strdup(chanhop_channels[szi]);
                }
            }

            /* default to current values for unspecified fields */
            if (mpack_node_map_contains_uint(chanhop, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_RATE)) {
                chanhop_rate = mpack_node_float(mpack_node_map_uint(chanhop, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_RATE));
                chanhop_rate_bad = !isfinite(chanhop_rate) || chanhop_rate < 0;
            } else {
                chanhop_rate = caph->channel_hop_rate;
            }

            if (mpack_node_map_contains_uint(chanhop, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SHUFFLE)) {
                chanhop_shuffle = mpack_node_bool(mpack_node_map_uint(chanhop, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SHUFFLE));
            } else {
                chanhop_shuffle = caph->channel_hop_shuffle;
            }

            if (mpack_node_map_contains_uint(chanhop, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SKIP)) {
                chanhop_shuffle_spacing = mpack_node_u16(mpack_node_map_uint(chanhop, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SKIP));
            } else {
                chanhop_shuffle_spacing = caph->channel_hop_shuffle_spacing;
            }

            if (mpack_node_map_contains_uint(chanhop, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_OFFSET)) {
                chanhop_offset = mpack_node_u16(mpack_node_map_uint(chanhop, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_OFFSET));
            } else {
                chanhop_offset = caph->channel_hop_offset;
            }

            /* Each hop configuration says whether to hop on the shared grid */
            if (mpack_node_map_contains_uint(chanhop, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SYNC_EPOCH)) {
                chanhop_sync = 1;
                chanhop_sync_epoch = mpack_node_u64(mpack_node_map_uint(chanhop,
                            KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SYNC_EPOCH));
            }

            if (mpack_tree_error(&tree) != mpack_ok) {
                fprintf(stderr, "FATAL: Invalid configure request received, unable to process channel hop command.\n");
                cf_free_hop_lists(caph, chanhop_channels, chanhop_priv_channels, chanhop_channels_sz);
                cbret = -1;
                mpack_tree_destroy(&tree);
                goto finish;
            }

            chanhop_refused = 0;
            for (szi = 0; szi < chanhop_channels_sz; szi++) {
                if (chanhop_priv_channels[szi] == NULL)
                    chanhop_refused++;
            }

            /* A rate which isn't a finite number >= 0, or nothing usable, keeps
             * the current channel and hopping as they are */
            if (chanhop_rate_bad || chanhop_refused == chanhop_channels_sz) {
                cf_free_hop_lists(caph, chanhop_channels, chanhop_priv_channels, chanhop_channels_sz);

                if (cf_send_chan_refused(caph, seqno, chanhop_rate_bad ?
                            "could not use the requested hop rate" :
                            "could not use any channel in the hop list") < 0) {
                    cbret = -1;
                    fprintf(stderr, "FATAL: Unable to send configure response.\n");
                } else {
                    cbret = 1;
                }

                mpack_tree_destroy(&tree);
                goto finish;
            }

            caph->hop_sync = chanhop_sync;
            caph->hop_sync_epoch_ns = chanhop_sync_epoch;

            /* Synced, refused channels stay in the list as NULL slots marked
             * failed, so the source keeps the shared schedule and sits them out.
             * On its own timer they're dropped now, costing no dwell and leaving
             * the prune's report to channels which fail to tune.  The hop thread
             * waits on handler_lock, held here, so it never sees them unmarked.
             * Set the hop data, which will handle our thread */
            chanhop_assign_sz = chanhop_channels_sz;
            if (!chanhop_sync && chanhop_refused > 0)
                chanhop_assign_sz = cf_hop_drop_refused(caph, chanhop_channels,
                        chanhop_priv_channels, chanhop_channels_sz, chanhop_shuffle,
                        chanhop_shuffle_spacing, &chanhop_offset);

            cf_handler_assign_hop_channels(caph, chanhop_channels,
                    chanhop_priv_channels, chanhop_assign_sz, chanhop_rate,
                    chanhop_shuffle, chanhop_shuffle_spacing, chanhop_offset);

            if (chanhop_sync && chanhop_refused > 0) {
                for (szi = 0; szi < caph->channel_hop_list_sz; szi++) {
                    if (caph->custom_channel_hop_list[szi] == NULL)
                        cf_hop_note_failure(caph, szi);
                }
            }

            msgstr[0] = 0;
            if (chanhop_refused > 0)
                snprintf(msgstr, STATUS_MAX, "%s could not use %lu of the %lu channels in the "
                        "hop list; skipping them while hopping", cf_source_label(caph),
                        (unsigned long) chanhop_refused, (unsigned long) chanhop_channels_sz);

            /* Return a completion, and we do NOT free the channel lists we
             * dynamically allocated out of the buffer with cf_get_CHANHOP, as
             * we're now using them for keeping the channel record in the caph.
             * The report goes first, so a full ring drops the message instead */
            cbret = 1;
            if (cf_send_configresp(caph, seqno, 1, chanhop_refused > 0 ? msgstr : NULL) < 0) {
                cbret = -1;
                fprintf(stderr, "FATAL: Unable to send configure response.\n");
            }

            if (chanhop_refused > 0)
                cf_send_warning(caph, msgstr);

            mpack_tree_destroy(&tree);

            goto finish;
        }

        /* Neither a channel nor a hop list: only the report interval, or fields
         * from a newer server, which must not close the source */
        if (mpack_tree_error(&tree) != mpack_ok) {
            fprintf(stderr, "FATAL: Invalid configure request received, unable to unpack command.\n");
            cbret = -1;
            mpack_tree_destroy(&tree);
            goto finish;
        }

        cbret = 1;
        if (cf_send_configresp(caph, seqno, 1, NULL) < 0) {
            cbret = -1;
            fprintf(stderr, "FATAL: Unable to send configure response.\n");
        }

        mpack_tree_destroy(&tree);
    } else {
        cbret = -1;

        /* If we have an unknown frame handler, give it a chance to process this
         * frame */
        if (caph->unknown_cb != NULL) {
            cbret =
                (*(caph->unknown_cb))(caph, seqno, cmd, (const char *) data, packet_sz);
        }

        if (cbret < 0) {
            pthread_mutex_unlock(&(caph->handler_lock));
            cf_send_proberesp(caph, seqno, false, "Unsupported request", NULL, NULL);
            return 0;
        }
    }

finish:
    pthread_mutex_unlock(&caph->handler_lock);

    return cbret;
}

/* select() can only watch descriptors below FD_SETSIZE */
static int cf_fd_selectable(int fd) {
    return fd >= 0 && fd < FD_SETSIZE;
}

/* A --tcp connection which never got a valid frame most likely reached the web server
 * port instead of the remote capture port */
static int cf_tcp_wrong_port(kis_capture_handler_t *caph) {
    if (!caph->use_tcp || caph->remote_host == NULL || caph->remote_rx_valid)
        return 0;

    fprintf(stderr,
            "FATAL: %s:%u did not answer as a Kismet remote capture server.  With --tcp,\n"
            "connect to the server's remote capture port (remote_capture_port, default\n"
            "3501), not the web server port (default 2501).\n",
            caph->remote_host, caph->remote_port);

    return 1;
}

int cf_handle_rx_content(kis_capture_handler_t *caph, const uint8_t *buffer, size_t len) {
    kismet_external_frame_t *external_frame;
    kismet_external_frame_v2_t *external_frame_v2;
    kismet_external_frame_v3_t *external_frame_v3;

    /* Incoming size */
    uint32_t packet_sz;

    if (len < sizeof(kismet_external_frame_t)) {
        return -1;
    }

    /* Attempt to match across all versions, so we can give smarter errors about
     * older servers that we don't work with anymore */
    external_frame = (kismet_external_frame_t *) buffer;
    external_frame_v2 = (kismet_external_frame_v2_t *) buffer;
    external_frame_v3 = (kismet_external_frame_v3_t *) buffer;

    /* Check the signature */
    if (ntohl(external_frame->signature) != KIS_EXTERNAL_PROTO_SIG) {
        if (cf_tcp_wrong_port(caph))
            return -1;

        fprintf(stderr,
                "FATAL: Capture source (%s) cannot communicate with this Kismet server.\n"
                "Capture source got an unknown protocol signature, please upgrade the\n"
                "Kismet server install to a more recent version of Kismet.\n",
                caph->capsource_type);
        return -1;
    }

    /* Detect v2 and unknown (presumably v0 using the old checksum) frames */
    if (ntohs(external_frame_v2->v2_sentinel) == KIS_EXTERNAL_V2_SIG) {
        /* handle a legacy v2 ping packet directly; this is used for datasource
         * version discovery in the new ping handshake for v3.  respond with a
         * v3 answer. */
        if (len < sizeof(kismet_external_frame_v2_t)) {
            return -1;
        }

        if (strncasecmp(external_frame_v2->command, "PING", 32) == 0) {
            pthread_mutex_lock(&(caph->handler_lock));

            cf_send_pong(caph, ntohl(external_frame_v2->seqno));
            pthread_mutex_unlock(&(caph->handler_lock));
            return 1;
        }

        fprintf(stderr,
                "FATAL: Capture source (%s) cannot communicate with this Kismet server.\n"
                "The server is speaking the older v2 Kismet protocol, please upgrade the\n"
                "Kismet server install to a more recent version of Kismet.\n",
                caph->capsource_type);
        return -1;
    } else if (ntohs(external_frame_v3->v3_sentinel) != KIS_EXTERNAL_V3_SIG) {
        fprintf(stderr,
                "FATAL: Capture source (%s) cannot communicate with this Kismet server.\n"
                "The server is speaking an unknown Kismet protocol, please make sure\n"
                "the Kismet server install is using a similar version.\n",
                caph->capsource_type);
        return -1;
    }

    packet_sz = ntohl(external_frame->data_sz);

    /* Compare without adding to packet_sz, which can wrap on 32-bit */
    if (len < sizeof(kismet_external_frame_v3_t) ||
            len - sizeof(kismet_external_frame_v3_t) < packet_sz) {
        fprintf(stderr, "FATAL: Capture source (%s) malforned too-small v3 packet (%zu / %u)\n",
                caph->capsource_type, len, packet_sz);
        return -1;
    }

    caph->remote_rx_valid = 1;

    return cf_dispatch_rx_content(caph, ntohs(external_frame_v3->pkt_type),
            ntohl(external_frame_v3->seqno), external_frame_v3->data, packet_sz);
}


int cf_handle_rb_rx_data(kis_capture_handler_t *caph) {
    size_t rb_available;

    /* Buffer of entire frame, dynamic.  Every peek is released with peek_free,
     * including short ones, or the ring stays mid-peek and input stalls */
    uint8_t *frame_buf = NULL;

    kismet_external_frame_t *external_frame;
    kismet_external_frame_v2_t *external_frame_v2;
    kismet_external_frame_v3_t *external_frame_v3;

    /* Incoming size */
    uint32_t packet_sz;
    uint32_t total_sz = 0;

    int cbret;

    rb_available = kis_simple_ringbuf_used(caph->in_ringbuf);

    if (rb_available < sizeof(kismet_external_frame_t)) {
        /* fprintf(stderr, "DEBUG - insufficient data to represent a frame\n"); */
        return 0;
    }

    if (kis_simple_ringbuf_peek_zc(caph->in_ringbuf, (void **) &frame_buf,
                sizeof(kismet_external_frame_t)) != sizeof(kismet_external_frame_t)) {
        kis_simple_ringbuf_peek_free(caph->in_ringbuf, frame_buf);
        return 0;
    }

    /* Attempt to match across all versions, so we can give smarter errors about
     * older servers that we don't work with anymore */
    external_frame = (kismet_external_frame_t *) frame_buf;
    external_frame_v2 = (kismet_external_frame_v2_t *) frame_buf;
    external_frame_v3 = (kismet_external_frame_v3_t *) frame_buf;

    /* Check the signature */
    if (ntohl(external_frame->signature) != KIS_EXTERNAL_PROTO_SIG) {
        kis_simple_ringbuf_peek_free(caph->in_ringbuf, frame_buf);

        if (cf_tcp_wrong_port(caph))
            return -1;

        fprintf(stderr, "FATAL: Capture source (%s) invalid frame header received\n",
				caph->capsource_type);
        return -1;
    }

    /* Detect v2 and unknown (presumably v0 using the old checksum) frames */
    if (ntohs(external_frame_v2->v2_sentinel) == KIS_EXTERNAL_V2_SIG) {
        /* explicitly handle a v2 ping no matter what; this is used as a legacy
         * discovery packet to map older local binaries
         *
         * re-peek a v2 sized header once all of it has arrived
         */

        kis_simple_ringbuf_peek_free(caph->in_ringbuf, frame_buf);

        if (rb_available < sizeof(kismet_external_frame_v2_t))
            return 0;

        if (kis_simple_ringbuf_peek_zc(caph->in_ringbuf, (void **) &frame_buf,
                    sizeof(kismet_external_frame_v2_t)) != sizeof(kismet_external_frame_v2_t)) {
            kis_simple_ringbuf_peek_free(caph->in_ringbuf, frame_buf);
            return 0;
        }

        external_frame = (kismet_external_frame_t *) frame_buf;
        external_frame_v2 = (kismet_external_frame_v2_t *) frame_buf;

        if (strncasecmp(external_frame_v2->command, "PING", 32) == 0) {
            uint32_t seqno = ntohl(external_frame_v2->seqno);

            packet_sz = ntohl(external_frame->data_sz);

            /* Bound before adding the header, then consume only a complete frame;
             * a frame may fill the ring exactly */
            if (packet_sz > kis_simple_ringbuf_size(caph->in_ringbuf) - sizeof(kismet_external_frame_v2_t)) {
                kis_simple_ringbuf_peek_free(caph->in_ringbuf, frame_buf);
                fprintf(stderr, "FATAL: Capture source (%s) incoming v2 packet too large for ringbuf (%u / %zu)\n",
                        caph->capsource_type, packet_sz, kis_simple_ringbuf_size(caph->in_ringbuf));
                return -1;
            }

            total_sz = packet_sz + sizeof(kismet_external_frame_v2_t);

            if (rb_available < total_sz) {
                kis_simple_ringbuf_peek_free(caph->in_ringbuf, frame_buf);
                return 0;
            }

            pthread_mutex_lock(&(caph->handler_lock));

            kis_simple_ringbuf_peek_free(caph->in_ringbuf, frame_buf);
            kis_simple_ringbuf_read(caph->in_ringbuf, NULL, total_sz);

            cf_send_pong(caph, seqno);
            pthread_mutex_unlock(&(caph->handler_lock));
            return 1;
        }

        kis_simple_ringbuf_peek_free(caph->in_ringbuf, frame_buf);

        fprintf(stderr,
                "FATAL: Capture source (%s) cannot communicate with this Kismet server.\n"
                "The server is speaking the older v2 Kismet protocol, please upgrade the\n"
                "Kismet install to a more recent version of Kismet.\n",
                caph->capsource_type);
        return -1;
    } else if (ntohs(external_frame_v3->v3_sentinel) != KIS_EXTERNAL_V3_SIG) {
        kis_simple_ringbuf_peek_free(caph->in_ringbuf, frame_buf);

        fprintf(stderr,
                "FATAL: Capture source (%s) cannot communicate with this Kismet server.\n"
                "The server is speaking an unknown Kismet protocol, please make sure\n"
                "the Kismet install is using a similar version.\n",
                caph->capsource_type);
        return -1;
    }

    packet_sz = ntohl(external_frame->data_sz);

    /* Bound packet_sz before adding the header so total_sz can't wrap; a frame
     * may fill the ring exactly */
    if (packet_sz > kis_simple_ringbuf_size(caph->in_ringbuf) - sizeof(kismet_external_frame_v3_t)) {
        kis_simple_ringbuf_peek_free(caph->in_ringbuf, frame_buf);
        fprintf(stderr, "FATAL: Capture source (%s) incoming packet too large for ringbuf (%u / %zu)\n",
				caph->capsource_type, packet_sz, kis_simple_ringbuf_size(caph->in_ringbuf));
        return -1;
    }

    total_sz = packet_sz + sizeof(kismet_external_frame_v3_t);

    if (rb_available < total_sz) {
        kis_simple_ringbuf_peek_free(caph->in_ringbuf, frame_buf);
        return 0;
    }

    /* Free the peek of the frame header */
    kis_simple_ringbuf_peek_free(caph->in_ringbuf, frame_buf);

    /* We've got enough to read it all; try to zc the buffer */

    /* Peek our ring buffer */
    if (kis_simple_ringbuf_peek_zc(caph->in_ringbuf, (void **) &frame_buf, total_sz) != total_sz) {
        fprintf(stderr, "FATAL: Capture source (%s) failed to read packet from ringbuf\n",
				caph->capsource_type);
        kis_simple_ringbuf_peek_free(caph->in_ringbuf, frame_buf);
        return -1;
    }

    cbret = cf_handle_rx_content(caph, frame_buf, total_sz);

    kis_simple_ringbuf_peek_free(caph->in_ringbuf, frame_buf);

    /* Clear it out from the buffer */
    kis_simple_ringbuf_read(caph->in_ringbuf, NULL, total_sz);

    return cbret;
}

/* Connect to the first of the remote host's addresses which answers, in resolver order,
 * so a name with both IPv6 and IPv4 addresses reaches a server listening on only one.
 * Returns a connected non-blocking socket and, if addr is set, the numeric address used */
static int cf_connect_remote_host(kis_capture_handler_t *caph, char *addr, size_t addr_len,
        char *errstr, size_t errstr_len) {
    struct addrinfo hints, *res, *ai;
    char port[8];
    int fd = -1;
    int err = ECONNREFUSED;
    int r;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port, sizeof(port), "%u", caph->remote_port);

    if ((r = getaddrinfo(caph->remote_host, port, &hints, &res)) != 0) {
        snprintf(errstr, errstr_len, "could not resolve hostname: %s", gai_strerror(r));
        return -1;
    }

    for (ai = res; ai != NULL; ai = ai->ai_next) {
        struct pollfd pfd;
        socklen_t err_len = sizeof(err);

        if ((fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) {
            err = errno;
            continue;
        }

        fcntl(fd, F_SETFD, fcntl(fd, F_GETFD, 0) | FD_CLOEXEC);
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;

        if (errno == EINPROGRESS) {
            pfd.fd = fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;

            r = poll(&pfd, 1, 5000);

            if (r == 1) {
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len) < 0)
                    err = errno;
                else if (err == 0)
                    break;
            } else {
                err = r == 0 ? ETIMEDOUT : errno;
            }
        } else {
            err = errno;
        }

        close(fd);
        fd = -1;
    }

    if (fd < 0) {
        snprintf(errstr, errstr_len, "%s", strerror(err));
    } else if (addr != NULL &&
            getnameinfo(ai->ai_addr, ai->ai_addrlen, addr, addr_len, NULL, 0, NI_NUMERICHOST) != 0) {
        snprintf(errstr, errstr_len, "could not format the address of '%s'", caph->remote_host);
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    return fd;
}

int cf_handler_tcp_remote_connect(kis_capture_handler_t *caph) {
    int client_fd;

    char msgstr[STATUS_MAX];

    char *uuid = NULL;

    int cbret;

    cf_params_interface_t *cpi;
    cf_params_spectrum_t *cps;

    /* If we have nothing to connect to... */
    if (caph->remote_host == NULL)
        return 0;

    /* Remotes are always verbose */
    caph->verbose = 1;

    /* close the fd if it's open */
    if (caph->tcp_fd >= 0) {
        close(caph->tcp_fd);
        caph->tcp_fd = -1;
    }

    /* Reset the last ping */
    caph->last_ping = time(0);

    /* Reset spindown */
    cf_handler_reset_shutdown(caph);
    __atomic_store_n(&caph->close_requested, 0, __ATOMIC_RELEASE);
    caph->close_deadline_ms = 0;

    caph->in_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_IN_SZ);
    if (caph->in_ringbuf == NULL) {
        fprintf(stderr, "FATAL:  Cannot allocate socket ringbuffer\n");
        return -1;
    }

    caph->out_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_OUT_SZ);
    if (caph->out_ringbuf == NULL) {
        fprintf(stderr, "FATAL:  Cannot allocate socket ringbuffer\n");
        return -1;
    }


    /* Perform a local probe on the source to see if it's valid */
    msgstr[0] = 0;

    cpi = NULL;
    cps = NULL;

    if (caph->probe_cb == NULL) {
        fprintf(stderr, "FATAL: Unable to act as a remote source when no probe callback provided.\n");
        return -1;
    }

    cbret = (*(caph->probe_cb))(caph, 0, caph->cli_sourcedef, msgstr, &uuid, &cpi, &cps);

    if (cpi != NULL)
        cf_params_interface_free(cpi);

    if (cps != NULL)
        cf_params_spectrum_free(cps);

    if (cbret <= 0) {
        fprintf(stderr, "FATAL: Could not probe local source prior to connecting to the "
                "remote host: %s\n", msgstr);

        if (uuid)
            free(uuid);

        return -1;
    }

    if ((client_fd = cf_connect_remote_host(caph, NULL, 0, msgstr, sizeof(msgstr))) < 0) {
        fprintf(stderr, "FATAL: Could not connect to remote host '%s:%u': %s\n",
                caph->remote_host, caph->remote_port, msgstr);

        if (uuid)
            free(uuid);

        return -1;
    }

    caph->tcp_fd = client_fd;
    caph->remote_rx_valid = 0;

    fprintf(stderr, "INFO: Connected to '%s:%u'...\n", caph->remote_host, caph->remote_port);

    /* Send the NEWSOURCE command to the Kismet server */
    if (cf_send_newsource(caph, uuid) < 0) {
        fprintf(stderr, "FATAL: Could not transmit NEWSOURCE response\n");

        if (uuid) {
            free(uuid);
        }

        caph->tcp_fd = -1;
        close(client_fd);

        return -1;
    }

    if (uuid)
        free(uuid);

    return 1;
}

#ifdef HAVE_LIBWEBSOCKETS
void ws_connect_attempt(kis_capture_handler_t *caph) {
    char msgstr[STATUS_MAX];
    int cbret;
    int fd;
    cf_params_interface_t *cpi;
    cf_params_spectrum_t *cps;

    /* Remotes are always verbose */
    caph->verbose = 1;

    /* Reset the last ping */
    caph->last_ping = time(0);

    /* Reset spindown */
    cf_handler_reset_shutdown(caph);
    __atomic_store_n(&caph->close_requested, 0, __ATOMIC_RELEASE);
    caph->close_deadline_ms = 0;

    msgstr[0] = 0;
    cpi = NULL;
    cps = NULL;

    if (caph->probe_cb == NULL) {
        fprintf(stderr, "FATAL: unable to connect as remote source when no probe callback "
                "provided.\n");
        caph->spindown = 1;
        return;
    }

    free(caph->lwsuuid);
    caph->lwsuuid = NULL;

    cbret = (*(caph->probe_cb))(caph, 0, caph->cli_sourcedef, msgstr,
            &caph->lwsuuid, &cpi, &cps);

    if (cpi != NULL)
        cf_params_interface_free(cpi);

    if (cps != NULL)
        cf_params_spectrum_free(cps);

    if (cbret <= 0) {
        fprintf(stderr, "FATAL: Could not probe local source prior to connecting to the "
                "remote host: %s\n", msgstr);
        caph->spindown = 1;
        return;
    }

    /* libwebsockets only tries the first address of a name, so find the one which answers */
    if ((fd = cf_connect_remote_host(caph, caph->lwsaddress, sizeof(caph->lwsaddress),
                    msgstr, sizeof(msgstr))) < 0) {
        fprintf(stderr, "FATAL: Could not connect to remote host '%s:%u': %s\n",
                caph->remote_host, caph->remote_port, msgstr);
        caph->spindown = 1;
        return;
    }

    close(fd);

    memset(&caph->lwsci, 0, sizeof(struct lws_client_connect_info));
    caph->lwsci.context = caph->lwscontext;
    caph->lwsci.port = caph->remote_port;
    caph->lwsci.address = caph->lwsaddress;
    caph->lwsci.path = caph->lwsuri;
    caph->lwsci.host = caph->remote_host;
    caph->lwsci.origin  = caph->remote_host;
    caph->lwsci.ssl_connection = 0;

    if (caph->lwsusessl) {
        caph->lwsci.ssl_connection |= LCCSCF_USE_SSL;
    }

    caph->lwsci.protocol = "kismet-remote";
    caph->lwsci.pwsi = &caph->lwsclientwsi;

    if (!lws_client_connect_via_info(&caph->lwsci)) {
        fprintf(stderr, "FATAL: Datasource could not connect websocket\n");
        return;
    }
}

/* handler which gets dispatched by libwebsockets */
int ws_remotecap_broker(struct lws *wsi, enum lws_callback_reasons reason,
        void *user, void *in, size_t len) {

    kis_capture_handler_t *caph = (kis_capture_handler_t *) lws_context_user(lws_get_context(wsi));

    struct cf_ws_msg *wmsg;
    int m;

    switch (reason) {
        case LWS_CALLBACK_PROTOCOL_INIT:
            caph->lwscontext = lws_get_context(wsi);
            caph->lwsprotocol = lws_get_protocol(wsi);
            caph->lwsvhost = lws_get_vhost(wsi);
            ws_connect_attempt(caph);

            pthread_mutex_lock(&caph->handler_lock);

            if (caph->spindown) {
                caph->lwsclientwsi = NULL;
                caph->lwsestablished = 0;
                caph->shutdown = 1;
            }

	    pthread_mutex_unlock(&caph->handler_lock);

            break;
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            pthread_mutex_lock(&caph->handler_lock);
            caph->lwsclientwsi = NULL;
            caph->lwsestablished = 0;
            caph->shutdown = 1;
            pthread_mutex_unlock(&caph->handler_lock);

            fprintf(stderr, "FATAL: Datasource could not connect websocket client: %s\n",
                    in != NULL ? (const char *) in : "unknown error");
            lws_cancel_service(caph->lwscontext);
            break;
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            caph->lwsestablished = 1;
            cf_send_newsource(caph, caph->lwsuuid);
            break;
        case LWS_CALLBACK_EVENT_WAIT_CANCELLED:
            /* Other threads queue messages and wake the service loop; only this thread
             * may ask for a writeable callback */
            pthread_mutex_lock(&caph->out_ringbuf_lock);
            caph->lwswake = 0;
            if (caph->lwsring != NULL && caph->lwsclientwsi != NULL &&
                    lws_ring_get_element(caph->lwsring, &caph->lwstail) != NULL)
                lws_callback_on_writable(caph->lwsclientwsi);
            pthread_mutex_unlock(&caph->out_ringbuf_lock);
            break;
        case LWS_CALLBACK_CLIENT_WRITEABLE:
            pthread_mutex_lock(&caph->out_ringbuf_lock);

            wmsg = (struct cf_ws_msg *) lws_ring_get_element(caph->lwsring, &caph->lwstail);
            if (wmsg == NULL)
                goto skip;

            m = lws_write(wsi, (unsigned char *) wmsg->payload + LWS_PRE,
                    wmsg->len, LWS_WRITE_BINARY);

            if (m != (int) wmsg->len) {
                fprintf(stderr, "FATAL: Datasource could not write data to websocket\n");
                caph->shutdown = 1;
                lws_cancel_service(caph->lwscontext);
                pthread_mutex_unlock(&caph->out_ringbuf_lock);
                return -1;
            }

            lws_ring_consume_single_tail(caph->lwsring, &caph->lwstail, 1);

            if (lws_ring_get_element(caph->lwsring, &caph->lwstail)) {
                lws_callback_on_writable(wsi);
            } else if (caph->spindown) {
                /* If we have no more packets and we're spinning down, finish */
                caph->shutdown = 1;
                lws_cancel_service(caph->lwscontext);
                pthread_mutex_unlock(&caph->out_ringbuf_lock);
                return -1;
            }

            /* Signal to any waiting IO that the buffer has some
             * headroom */
            pthread_cond_broadcast(&(caph->out_ringbuf_flush_cond));

skip:
            pthread_mutex_unlock(&caph->out_ringbuf_lock);
            break;
        case LWS_CALLBACK_CLIENT_CLOSED:
            fprintf(stderr, "FATAL: Datasource websocket closed\n");
            pthread_mutex_lock(&caph->handler_lock);
            caph->lwsclientwsi = NULL;
            caph->lwsestablished = 0;
            caph->shutdown = 1;
            pthread_mutex_unlock(&caph->handler_lock);
            return -1;
        case LWS_CALLBACK_CLIENT_RECEIVE:
            if (cf_handle_rx_content(caph, (const uint8_t *) in, len) < 0) {
                caph->lwsestablished = 0;
                caph->spindown = 1;
                lws_cancel_service(caph->lwscontext);
            }

            break;
        default:
            break;
    }

    return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void ws_destroy_msg(void *in_msg) {
    struct cf_ws_msg *msg = (struct cf_ws_msg *) in_msg;

    free(msg->payload);
    msg->payload = NULL;
    msg->len = 0;
}

/* A helper can warn before cf_handler_loop starts the websocket service, such as
 * when it can't jail itself or drop caps; call with out_ringbuf_lock held */
static int cf_ws_ring_ready(kis_capture_handler_t *caph) {
    if (caph->lwsring == NULL)
        caph->lwsring =
            lws_ring_create(sizeof(struct cf_ws_msg), CAP_FRAMEWORK_WS_BUF_SZ, ws_destroy_msg);

    return caph->lwsring != NULL;
}
#endif

/* The descriptors of the running child programs to wait on: their output, unless
 * spinning down, and their input when there is something queued for it.  Called with
 * the handler lock held. */
static void cf_ipc_set_fds(kis_capture_handler_t *caph, int spindown, fd_set *rset, fd_set *wset,
        int *max_fd) {
    cf_ipc_t *ipc_iter;

    ipc_iter = caph->ipc_list;

    while (ipc_iter != NULL) {
        if (ipc_iter->running == 0) {
            ipc_iter = ipc_iter->next;
            continue;
        }

        if (spindown == 0) {
            if (cf_fd_selectable(ipc_iter->out_fd)) {
                FD_SET(ipc_iter->out_fd, rset);
                if (*max_fd < ipc_iter->out_fd)
                    *max_fd = ipc_iter->out_fd;
            }

            if (cf_fd_selectable(ipc_iter->err_fd)) {
                FD_SET(ipc_iter->err_fd, rset);
                if (*max_fd < ipc_iter->err_fd)
                    *max_fd = ipc_iter->err_fd;
            }
        }

        pthread_mutex_lock(&ipc_iter->out_ringbuf_lock);

        if (kis_simple_ringbuf_used(ipc_iter->out_ringbuf) != 0 &&
                cf_fd_selectable(ipc_iter->in_fd)) {
            FD_SET(ipc_iter->in_fd, wset);
            if (*max_fd < ipc_iter->in_fd)
                *max_fd = ipc_iter->in_fd;
        }

        pthread_mutex_unlock(&ipc_iter->out_ringbuf_lock);

        ipc_iter = ipc_iter->next;
    }
}

/* Read what the child programs wrote and write what is queued for them, calling their
 * handlers.  Called with the handler lock held. */
static void cf_ipc_service(kis_capture_handler_t *caph, fd_set *rset, fd_set *wset) {
    cf_ipc_t *ipc_iter;

    ipc_iter = caph->ipc_list;

    while (ipc_iter != NULL) {
        if (ipc_iter->running == 0) {
            ipc_iter = ipc_iter->next;
            continue;
        }

        /* If the IPC handler wants to be re-called, do it immediately
         * regardless of incoming data */
        if (ipc_iter->retry_rx && ipc_iter->rx_callback != NULL) {
            ipc_iter->rx_callback(caph, ipc_iter, 0);
        }

        /* Handle stdout ops into the buffer */
        if (cf_fd_selectable(ipc_iter->out_fd) && FD_ISSET(ipc_iter->out_fd, rset) && ipc_iter->running) {
            while (kis_simple_ringbuf_available(ipc_iter->in_ringbuf)) {
                ssize_t amt_read;
                size_t maxread = 0;
                uint8_t *buf;
                size_t buf_avail;

                buf_avail = kis_simple_ringbuf_available(ipc_iter->in_ringbuf);
                maxread = kis_simple_ringbuf_reserve_zcopy(ipc_iter->in_ringbuf, (void **) &buf, buf_avail);

                /* No room: not a 0 byte read, which would look like EOF */
                if (maxread == 0)
                    break;

                amt_read = read(ipc_iter->out_fd, buf, maxread);

                if (amt_read == 0) {
                    kis_simple_ringbuf_commit(ipc_iter->in_ringbuf, buf, 0);
                    if (ipc_iter->term_callback != NULL) {
                        ipc_iter->term_callback(caph, ipc_iter, -1);
                    }
                    ipc_iter->running = 0;
                    break;
                } else if (amt_read < 0) {
                    kis_simple_ringbuf_commit(ipc_iter->in_ringbuf, buf, 0);

                    if (errno != EINTR && errno != EAGAIN) {
                        if (ipc_iter->term_callback != NULL) {
                            ipc_iter->term_callback(caph, ipc_iter, -1);
                        }
                        ipc_iter->running = 0;
                    }

                    break;
                } else {
                    kis_simple_ringbuf_commit(ipc_iter->in_ringbuf, buf, amt_read);
                    amt_read = kis_simple_ringbuf_used(ipc_iter->in_ringbuf);

                    if (ipc_iter->rx_callback != NULL) {
                        ipc_iter->retry_rx = 0;
                        ipc_iter->rx_callback(caph, ipc_iter, amt_read);
                    } else {
                        /* If there is no handler, throw the data out */
                        kis_simple_ringbuf_clear(ipc_iter->in_ringbuf);
                    }
                }
            }
        }

        if (cf_fd_selectable(ipc_iter->err_fd) && FD_ISSET(ipc_iter->err_fd, rset) && ipc_iter->running) {
            while (kis_simple_ringbuf_available(ipc_iter->err_ringbuf)) {
                ssize_t amt_read;
                size_t maxread = 0;
                uint8_t *buf;
                size_t buf_avail;

                buf_avail = kis_simple_ringbuf_available(ipc_iter->err_ringbuf);
                maxread = kis_simple_ringbuf_reserve_zcopy(ipc_iter->err_ringbuf, (void **) &buf, buf_avail);

                /* No room: not a 0 byte read, which would look like EOF */
                if (maxread == 0)
                    break;

                amt_read = read(ipc_iter->err_fd, buf, maxread);

                if (amt_read == 0) {
                    kis_simple_ringbuf_commit(ipc_iter->err_ringbuf, buf, 0);
                    if (ipc_iter->term_callback != NULL) {
                        ipc_iter->term_callback(caph, ipc_iter, -1);
                    }
                    ipc_iter->running = 0;
                    break;
                } else if (amt_read < 0) {
                    kis_simple_ringbuf_commit(ipc_iter->err_ringbuf, buf, 0);

                    if (errno != EINTR && errno != EAGAIN) {
                        if (ipc_iter->term_callback != NULL) {
                            ipc_iter->term_callback(caph, ipc_iter, -1);
                        }
                        ipc_iter->running = 0;
                    }

                    break;
                } else {
                    kis_simple_ringbuf_commit(ipc_iter->err_ringbuf, buf, amt_read);
                    amt_read = kis_simple_ringbuf_used(ipc_iter->err_ringbuf);

                    if (ipc_iter->err_callback != NULL) {
                        ipc_iter->err_callback(caph, ipc_iter, amt_read);
                    } else {
                        /* If there is no handler, throw the data out */
                        kis_simple_ringbuf_clear(ipc_iter->err_ringbuf);
                    }
                }
            }
        }

        /* Write anything queued to the stdin of the forked process */
        if (cf_fd_selectable(ipc_iter->in_fd) && FD_ISSET(ipc_iter->in_fd, wset) && ipc_iter->running) {
            pthread_mutex_lock(&ipc_iter->out_ringbuf_lock);

            if (kis_simple_ringbuf_used(ipc_iter->out_ringbuf) != 0) {
                ssize_t written_sz = 0;
                size_t peeked_sz = 0;
                uint8_t *peek_buf = NULL;

                peeked_sz = kis_simple_ringbuf_peek_zc(ipc_iter->out_ringbuf, (void **) &peek_buf, 0);

                /* Don't know how we'd get here... */
                if (peeked_sz == 0) {
                    kis_simple_ringbuf_peek_free(ipc_iter->out_ringbuf, peek_buf);
                } else {
                    written_sz = write(ipc_iter->in_fd, peek_buf, peeked_sz);

                    if (written_sz < 0) {
                        kis_simple_ringbuf_peek_free(ipc_iter->out_ringbuf, peek_buf);

                        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                            if (ipc_iter->term_callback != NULL) {
                                ipc_iter->term_callback(caph, ipc_iter, -1);
                            }
                            ipc_iter->running = 0;
                        }

                    } else {
                        kis_simple_ringbuf_peek_free(ipc_iter->out_ringbuf, peek_buf);
                        kis_simple_ringbuf_read(ipc_iter->out_ringbuf, NULL, (size_t) written_sz);
                    }
                }
            }

            pthread_mutex_unlock(&ipc_iter->out_ringbuf_lock);
        }

        ipc_iter = ipc_iter->next;
    }
}

#ifdef HAVE_LIBWEBSOCKETS
/* The websocket loop only waits on the websocket, so the child programs a capture
 * source runs (rtl_433 and the like) are serviced here, as the select loop does for
 * the other transports */
static void *cf_ws_ipc_thread(void *arg) {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) arg;
    fd_set rset, wset;
    struct timeval tm;
    int max_fd, spindown, ret;

    while (1) {
        FD_ZERO(&rset);
        FD_ZERO(&wset);
        max_fd = -1;

        pthread_mutex_lock(&(caph->handler_lock));

        if (caph->shutdown || caph->ipcthread_stop) {
            pthread_mutex_unlock(&(caph->handler_lock));
            break;
        }

        spindown = caph->spindown;
        cf_ipc_set_fds(caph, spindown, &rset, &wset, &max_fd);

        pthread_mutex_unlock(&(caph->handler_lock));

        /* With nothing to wait on this is the delay before looking again */
        tm.tv_sec = 0;
        tm.tv_usec = 500000;

        ret = select(max_fd + 1, &rset, &wset, NULL, &tm);

        if (ret < 0) {
            /* A child's descriptors can close between the two locks */
            if (errno != EINTR && errno != EAGAIN) {
                tm.tv_sec = 0;
                tm.tv_usec = 100000;
                select(0, NULL, NULL, NULL, &tm);
            }
            continue;
        }

        if (ret == 0)
            continue;

        pthread_mutex_lock(&(caph->handler_lock));

        if (!caph->shutdown && !caph->ipcthread_stop)
            cf_ipc_service(caph, &rset, &wset);

        pthread_mutex_unlock(&(caph->handler_lock));
    }

    return NULL;
}
#endif

int cf_handler_loop(kis_capture_handler_t *caph) {
    fd_set rset, wset;
    int max_fd;
    int read_fd, write_fd;
    struct timeval tm;
    int spindown;
    int ret;
    int rv = 0;

    if (caph->use_tcp || caph->use_ipc) {
        if (caph->in_ringbuf == NULL) {
            caph->in_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_IN_SZ);

            if (caph->in_ringbuf == NULL) {
                fprintf(stderr, "FATAL:  Cannot allocate socket ringbuffer\n");
                return -1;
            }
        }

        if (caph->out_ringbuf == NULL) {
            caph->out_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_OUT_SZ);

            if (caph->out_ringbuf == NULL) {
                fprintf(stderr, "FATAL:  Cannot allocate socket ringbuffer\n");
                return -1;
            }
        }

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

        if (!cf_fd_selectable(read_fd) || !cf_fd_selectable(write_fd) ||
                (caph->out_ringbuf_wake[0] >= 0 && !cf_fd_selectable(caph->out_ringbuf_wake[0]))) {
            fprintf(stderr, "FATAL:  Capture source descriptors out of range for select()\n");
            return -1;
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
                rv = -1;
                break;
            }

            if (caph->last_ping != 0 && time(NULL) - caph->last_ping > 15) {
                fprintf(stderr, "FATAL: Capture source %u did not get PING from Kismet for "
                        "over 15 seconds; shutting down\n", getpid());
                pthread_mutex_unlock(&(caph->handler_lock));
                rv = -1;
                break;
            }

            /* Graceful-close deadline: the capture thread was asked to
             * finish up and has not spun down in time.  Stop waiting for it;
             * spinning down still sends everything it queued. */
            if (caph->close_requested && !caph->spindown &&
                    caph->close_deadline_ms != 0 &&
                    cf_mono_ms() >= caph->close_deadline_ms) {
                fprintf(stderr, "ERROR: Capture source %u did not finish its close "
                        "within %u ms; closing without the rest of its teardown\n",
                        getpid(), caph->close_grace_ms);
                caph->spindown = 1;
            }

            /* Copy spindown state outside of lock */
            spindown = caph->spindown;

            max_fd = 0;

            cf_ipc_set_fds(caph, spindown, &rset, &wset, &max_fd);

            pthread_mutex_unlock(&(caph->handler_lock));

            /* Only set read sets if we're not spinning down */
            if (spindown == 0) {
                /* Only set rset if we're not spinning down */
                FD_SET(read_fd, &rset);
                if (max_fd < read_fd)
                    max_fd = read_fd;
            }

            /* Arm the wakeup before the write set is decided, so a commit after
             * that check still ends the select */
            if (caph->out_ringbuf_wake[0] >= 0) {
                FD_SET(caph->out_ringbuf_wake[0], &rset);
                if (max_fd < caph->out_ringbuf_wake[0])
                    max_fd = caph->out_ringbuf_wake[0];
                __atomic_store_n(&caph->out_ringbuf_wake_armed, 1, __ATOMIC_SEQ_CST);
            }

            /* Inspect the write buffer - do we have data? */
            pthread_mutex_lock(&(caph->out_ringbuf_lock));

            if (kis_simple_ringbuf_used(caph->out_ringbuf) != 0) {
                FD_SET(write_fd, &wset);
                if (max_fd < write_fd)
                    max_fd = write_fd;
            } else if (spindown != 0) {
                pthread_mutex_unlock(&(caph->out_ringbuf_lock));
                rv = 0;
                break;
            }

            pthread_mutex_unlock(&(caph->out_ringbuf_lock));

            tm.tv_sec = 0;
            tm.tv_usec = 500000;

            ret = select(max_fd + 1, &rset, &wset, NULL, &tm);

            __atomic_store_n(&caph->out_ringbuf_wake_armed, 0, __ATOMIC_SEQ_CST);

            if (ret < 0) {
                if (errno != EINTR && errno != EAGAIN) {
                    fprintf(stderr, "FATAL:  Error during select(): %s\n", strerror(errno));
                    rv = -1;
                    break;
                }
            }

            if (ret == 0)
                continue;

            /* The next pass's write-set check picks up whatever these announced */
            if (ret > 0 && caph->out_ringbuf_wake[0] >= 0 &&
                    FD_ISSET(caph->out_ringbuf_wake[0], &rset)) {
                uint8_t drain[64];

                while (read(caph->out_ringbuf_wake[0], drain, sizeof(drain)) > 0)
                    ;
            }

            pthread_mutex_lock(&caph->handler_lock);

            cf_ipc_service(caph, &rset, &wset);

            pthread_mutex_unlock(&caph->handler_lock);

            if (FD_ISSET(read_fd, &rset)) {
                while (kis_simple_ringbuf_available(caph->in_ringbuf)) {
                    /* We use a fixed-length read buffer for simplicity, and we shouldn't
                     * ever have too many incoming packets queued because the datasource
                     * protocol is very tx-heavy */
                    ssize_t amt_read;
                    size_t amt_buffered;
                    uint8_t rbuf[1024];
                    size_t maxread = 0;

                    /* Read don't read more than we can handle in the buffer or in our
                     * read slot */
                    maxread = kis_simple_ringbuf_available(caph->in_ringbuf);

                    if (maxread > 1024)
                        maxread = 1024;

                    if (caph->remote_host != NULL) {
                        // amt_read = recv(read_fd, rbuf, maxread, MSG_DONTWAIT);
                        amt_read = recv(read_fd, rbuf, maxread, 0);
                    } else {
                        amt_read = read(read_fd, rbuf, maxread);
                    }

                    if (amt_read == 0) {
                        if (!cf_tcp_wrong_port(caph))
                            fprintf(stderr, "FATAL: Remote side closed read pipe\n");
                        rv = -1;
                        goto cap_loop_fail;
                    } else if (amt_read < 0) {
                        /* Detect nonblocking */
                        if (errno != EINTR && errno != EAGAIN) {
                            fprintf(stderr, "FATAL:  Error during read(): %s\n", strerror(errno));
                            rv = -1;
                            goto cap_loop_fail;
                        } else {
                            /* Drop out of read/process loop */
                            break;
                        }
                    }

                    amt_buffered = kis_simple_ringbuf_write(caph->in_ringbuf, rbuf, amt_read);

                    if ((ssize_t) amt_buffered != amt_read) {
                        /* Bail entirely - to do, report error if we can over connection */
                        fprintf(stderr, "FATAL:  Error during read(): insufficient buffer space\n");
                        rv = -1;
                        goto cap_loop_fail;
                    }

                    /* Process all pending packets in the buffer */
                    do {
                        ret = cf_handle_rb_rx_data(caph);

                        if (ret < 0) {
                            // fprintf(stderr, "FATAL:  Datasource helper (%s) failed, could not process incoming control packet.\n", caph->capsource_type);
                            cf_handler_spindown(caph);
                        }
                    } while (ret > 0);
                }
            }

            if (FD_ISSET(write_fd, &wset)) {
                /* We can write data - lock the ring buffer mutex and write out
                 * whatever we can; we peek the ringbuffer and then flag off what
                 * we've successfully written out */
                ssize_t written_sz;
                size_t peeked_sz;
                uint8_t *peek_buf = NULL;

                pthread_mutex_lock(&(caph->out_ringbuf_lock));

                peeked_sz = kis_simple_ringbuf_peek_zc(caph->out_ringbuf, (void **) &peek_buf, 0);

                /* Don't know how we'd get here... */
                if (peeked_sz == 0) {
                    kis_simple_ringbuf_peek_free(caph->out_ringbuf, peek_buf);
                    pthread_mutex_unlock(&(caph->out_ringbuf_lock));
                    continue;
                }

                /* Same nonsense as before - send on tcp, write on pipes */
                if (caph->remote_host != NULL) {
                    // written_sz = send(write_fd, peek_buf, peeked_sz, MSG_DONTWAIT);
                    written_sz = send(write_fd, peek_buf, peeked_sz, 0);
                } else {
                    written_sz = write(write_fd, peek_buf, peeked_sz);
                }

                if (written_sz < 0) {
                    if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                        kis_simple_ringbuf_peek_free(caph->out_ringbuf, peek_buf);
                        pthread_mutex_unlock(&(caph->out_ringbuf_lock));
                        fprintf(stderr, "FATAL:  Error during write(): %s\n", strerror(errno));
                        rv = -1;
                        break;
                    }

                    /* Nothing written; retry next pass instead of consuming (size_t) -1 */
                    kis_simple_ringbuf_peek_free(caph->out_ringbuf, peek_buf);
                    pthread_mutex_unlock(&(caph->out_ringbuf_lock));
                    continue;
                }

                /* Flag it as consumed */
                kis_simple_ringbuf_read(caph->out_ringbuf, NULL, (size_t) written_sz);

                /* Get rid of the peek */
                kis_simple_ringbuf_peek_free(caph->out_ringbuf, peek_buf);

                /* Unlock */
                pthread_mutex_unlock(&(caph->out_ringbuf_lock));

                /* Signal to any waiting IO that the buffer has some
                 * headroom */
                cf_handler_signal_flush(caph);
            }
        }
    } else if (caph->use_ws) {
#ifdef HAVE_LIBWEBSOCKETS
        pthread_mutex_lock(&(caph->out_ringbuf_lock));
        ret = cf_ws_ring_ready(caph);
        pthread_mutex_unlock(&(caph->out_ringbuf_lock));

        if (!ret) {
            fprintf(stderr, "FATAL:  Cannot allocate websocket ringbuffer\n");
            return -1;
        }

        ret = 0;

        caph->ipcthread_stop = 0;
        if (pthread_create(&caph->ipcthread, NULL, cf_ws_ipc_thread, caph) != 0) {
            fprintf(stderr, "FATAL:  Cannot start the child program service thread\n");
            return -1;
        }
        caph->ipcthread_running = 1;

        while (ret >= 0 && !caph->shutdown)
            lws_service(caph->lwscontext, 0);

        fprintf(stderr, "FATAL:  Datasource exiting libwebsocket loop\n");

        pthread_mutex_lock(&(caph->handler_lock));
        caph->ipcthread_stop = 1;
        pthread_mutex_unlock(&(caph->handler_lock));

        pthread_join(caph->ipcthread, NULL);
        caph->ipcthread_running = 0;
#endif
    } else {
        fprintf(stderr, "FATAL:  Could not determine mode?\n");
        return -1;
    }


    /* Fall out of select loop */

cap_loop_fail:
    /* Kill the capture thread */
    cf_cancel_capture_thread(caph);

    /* Kill anything pending */
    cf_handler_signal_flush(caph);
    return rv;
}

/* Which share of the outbound queue a frame may use (CAP_FRAMEWORK_*_RESERVE).
 * Frames keep their order: a reserve only decides whether a frame fits. */
enum cf_out_class {
    CF_OUT_REPLY,
    CF_OUT_NOTICE,
    CF_OUT_DATA
};

static enum cf_out_class cf_out_frame_class(unsigned int command) {
    switch (command) {
        case KIS_EXTERNAL_V3_KDS_PACKET:
            return CF_OUT_DATA;
        case KIS_EXTERNAL_V3_CMD_PONG:
        case KIS_EXTERNAL_V3_CMD_SHUTDOWN:
        case KIS_EXTERNAL_V3_CMD_ERROR:
        case KIS_EXTERNAL_V3_KDS_PROBEREPORT:
        case KIS_EXTERNAL_V3_KDS_OPENREPORT:
        case KIS_EXTERNAL_V3_KDS_LISTREPORT:
        case KIS_EXTERNAL_V3_KDS_CONFIGREPORT:
        case KIS_EXTERNAL_V3_KDS_NEWSOURCE:
            return CF_OUT_REPLY;
        default:
            return CF_OUT_NOTICE;
    }
}

/* Room a frame of this class must leave free in the TCP/IPC ring, in bytes */
static size_t cf_rb_out_reserve(enum cf_out_class cls) {
    switch (cls) {
        case CF_OUT_DATA:
            return CAP_FRAMEWORK_RINGBUF_OUT_CTL_RESERVE;
        case CF_OUT_NOTICE:
            return CAP_FRAMEWORK_RINGBUF_OUT_REPLY_RESERVE;
        default:
            return 0;
    }
}

/* Does a frame of len bytes and this class fit the TCP/IPC ring; under out_ringbuf_lock */
static int cf_rb_out_fits(kis_capture_handler_t *caph, enum cf_out_class cls, size_t len) {
    size_t avail = kis_simple_ringbuf_available(caph->out_ringbuf);
    size_t reserve = cf_rb_out_reserve(cls);

    return avail >= reserve && avail - reserve >= len;
}

/* Count a control frame there was no room for; under out_ringbuf_lock.  Returns
 * the count to log, or 0 when one was logged in the last few seconds. */
#define CF_OUT_DROP_LOG_NS (5ULL * 1000000000ULL)
static uint64_t cf_out_ctl_dropped(kis_capture_handler_t *caph, enum cf_out_class cls) {
    uint64_t now;

    if (cls == CF_OUT_DATA)
        return 0;

    /* The drop report itself; it's retried on the next pong */
    if (caph->out_ctl_reporting && pthread_equal(pthread_self(), caph->out_ctl_report_thread))
        return 0;

    caph->out_ctl_dropped++;

    now = cf_clock_ns(CLOCK_MONOTONIC);
    if (caph->out_ctl_drop_log_ns != 0 && now - caph->out_ctl_drop_log_ns < CF_OUT_DROP_LOG_NS)
        return 0;

    caph->out_ctl_drop_log_ns = now;
    return caph->out_ctl_dropped;
}

/* After out_ringbuf_lock is released */
static void cf_out_ctl_drop_log(unsigned int command, uint64_t dropped) {
    if (dropped == 0)
        return;

    fprintf(stderr, "ERROR: Outbound buffer to the Kismet server is full; no room for a type %u "
            "control frame (%llu so far)\n", command, (unsigned long long) dropped);
}

/* Tell the server about control frames refused since the last report, once a
 * pong fit again.  Called from the service thread under handler_lock. */
static void cf_out_ctl_drop_report(kis_capture_handler_t *caph) {
    char msg[STATUS_MAX];
    uint64_t dropped;
    int r;

    pthread_mutex_lock(&(caph->out_ringbuf_lock));
    dropped = caph->out_ctl_dropped - caph->out_ctl_dropped_reported;
    if (dropped != 0) {
        caph->out_ctl_reporting = 1;
        caph->out_ctl_report_thread = pthread_self();
    }
    pthread_mutex_unlock(&(caph->out_ringbuf_lock));

    if (dropped == 0)
        return;

    snprintf(msg, STATUS_MAX, "Capture source outbound buffer was full; %llu control "
            "messages to the server could not be queued", (unsigned long long) dropped);

    r = cf_send_warning(caph, msg);

    pthread_mutex_lock(&(caph->out_ringbuf_lock));
    caph->out_ctl_reporting = 0;
    if (r > 0)
        caph->out_ctl_dropped_reported += dropped;
    pthread_mutex_unlock(&(caph->out_ringbuf_lock));
}

/* Raw bytes carry no command, so they get the data share */
int cf_send_rb_raw_bytes(kis_capture_handler_t *caph, uint8_t *data, size_t len) {
    pthread_mutex_lock(&(caph->out_ringbuf_lock));

    if (!cf_rb_out_fits(caph, CF_OUT_DATA, len)) {
        /* fprintf(stderr, "debug - Insufficient room in write buffer to queue data\n"); */
        pthread_mutex_unlock(&(caph->out_ringbuf_lock));
        return 0;
    }

    if (kis_simple_ringbuf_write(caph->out_ringbuf, data, len) != len) {
        fprintf(stderr, "FATAL: Failed to write data to buffer\n");
        pthread_mutex_unlock(&(caph->out_ringbuf_lock));
        return -1;
    }

    pthread_mutex_unlock(&(caph->out_ringbuf_lock));

    cf_handler_wake_commit(caph);

    return 1;
}

#ifdef HAVE_LIBWEBSOCKETS
/* Wake the service loop to send what's queued; lws_callback_on_writable isn't safe
 * from other threads.  Called under out_ringbuf_lock. */
static void cf_ws_wake(kis_capture_handler_t *caph) {
    if (caph->lwswake || caph->lwscontext == NULL)
        return;
    caph->lwswake = 1;
    lws_cancel_service(caph->lwscontext);
}

/* Does one more message of this class fit the websocket ring; under out_ringbuf_lock */
static int cf_ws_out_fits(kis_capture_handler_t *caph, enum cf_out_class cls) {
    size_t n = lws_ring_get_count_free_elements(caph->lwsring);

    switch (cls) {
        case CF_OUT_DATA:
            return n > CAP_FRAMEWORK_WS_CTL_RESERVE;
        case CF_OUT_NOTICE:
            return n > CAP_FRAMEWORK_WS_REPLY_RESERVE;
        default:
            return n > 0;
    }
}

int cf_send_ws_raw_bytes(kis_capture_handler_t *caph, uint8_t *data, size_t len) {
    int n;
    struct cf_ws_msg wsmsg;

    pthread_mutex_lock(&caph->out_ringbuf_lock);

    if (!cf_ws_ring_ready(caph)) {
        pthread_mutex_unlock(&caph->out_ringbuf_lock);
        return -1;
    }

    if (!cf_ws_out_fits(caph, CF_OUT_DATA)) {
        pthread_mutex_unlock(&caph->out_ringbuf_lock);
        lws_cancel_service(caph->lwscontext);
        return 0;
    }

    wsmsg.payload = (char *) malloc(LWS_PRE + len);
    if (wsmsg.payload == NULL) {
        fprintf(stderr, "FATAL: Failed to allocate ws buffer\n");
        pthread_mutex_unlock(&caph->out_ringbuf_lock);
        lws_cancel_service(caph->lwscontext);
        return -1;
    }

    memcpy(wsmsg.payload + LWS_PRE, data, len);

    wsmsg.len = len;

    n = (int) lws_ring_insert(caph->lwsring, &wsmsg, 1);
    if (n != 1) {
        fprintf(stderr, "FATAL:  Failed to queue ws message\n");
        pthread_mutex_unlock(&caph->out_ringbuf_lock);
        lws_cancel_service(caph->lwscontext);
        return -1;
    }

    cf_ws_wake(caph);
    pthread_mutex_unlock(&caph->out_ringbuf_lock);

    return 1;
}
#endif

int cf_send_raw_bytes(kis_capture_handler_t *caph, uint8_t *data, size_t len) {
    if (caph->use_tcp || caph->use_ipc)
        return cf_send_rb_raw_bytes(caph, data, len);
#ifdef HAVE_LIBWEBSOCKETS
    else if (caph->use_ws)
        return cf_send_ws_raw_bytes(caph, data, len);
#endif

    return -1;
}

/* prepare a memory mapped region for a packet based on a provided
 * size; returns a pointer to the complete frame for the caller to
 * then populate the inner data record.
 *
 * the provided estimated length must be large enough to hold the
 * serialized content of the data.
 *
 * after packet creation is complete, it must be committed for
 * transmit with cf_commit_rb_packet, with the final length.
 *
 * the capture framework handler is locked for the duration until the
 * commit is called.
 */
kismet_external_frame_v3_t *cf_prep_rb_packet(kis_capture_handler_t *caph,
        unsigned int command, uint32_t seqno, uint16_t code,
        size_t estimated_len) {

    /* Frame we'll be sending */
    kismet_external_frame_v3_t *frame;
    /* Size of assembled command data buffer */
    size_t rs_sz;
    /* Buffer holding all of it */
    uint8_t *send_buffer;

    enum cf_out_class cls = cf_out_frame_class(command);
    uint64_t dropped;

    /* Directly inject into the ringbuffer with a zero-copy, ringbuffer
     * handles non-zero-copy end of buffer situations */

    pthread_mutex_lock(&(caph->out_ringbuf_lock));

    /* A helper can warn before cf_handler_loop allocates the IPC buffer, such as when
     * it can't jail itself or drop caps; the warning goes out once the loop starts */
    if (caph->out_ringbuf == NULL) {
        caph->out_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_OUT_SZ);

        if (caph->out_ringbuf == NULL) {
            pthread_mutex_unlock(&(caph->out_ringbuf_lock));
            return NULL;
        }
    }

    if (!cf_rb_out_fits(caph, cls, estimated_len + sizeof(kismet_external_frame_v3_t))) {
        dropped = cf_out_ctl_dropped(caph, cls);
        pthread_mutex_unlock(&(caph->out_ringbuf_lock));
        cf_out_ctl_drop_log(command, dropped);
        return NULL;
    }

    rs_sz = kis_simple_ringbuf_reserve(caph->out_ringbuf, (void **) &send_buffer,
            estimated_len + sizeof(kismet_external_frame_v3_t));

    if (rs_sz != estimated_len + sizeof(kismet_external_frame_v3_t)) {
        dropped = cf_out_ctl_dropped(caph, cls);
        pthread_mutex_unlock(&(caph->out_ringbuf_lock));
        cf_out_ctl_drop_log(command, dropped);
        return NULL;
    }

    /* Map to the tx frame */
    frame = (kismet_external_frame_v3_t *) send_buffer;

    /* Set the signature and data size */
    frame->signature = htonl(KIS_EXTERNAL_PROTO_SIG);
    frame->v3_sentinel = htons(KIS_EXTERNAL_V3_SIG);
    frame->v3_version = htons(3);

    frame->seqno = htonl(seqno);

    frame->pkt_type = htons(command);

    frame->code = htons(code);

    // frame->length = htons(len);

    return frame;
}

/* Returns -1 when the ring refuses the commit (larger than the reserve): the
 * frame is dropped, and retrying can't fit it */
int cf_commit_rb_packet(kis_capture_handler_t *caph, kismet_external_frame_v3_t *frame,
        size_t final_length) {
    size_t total = final_length + sizeof(kismet_external_frame_v3_t);
    size_t r;

    frame->length = htonl(final_length);

    r = kis_simple_ringbuf_commit(caph->out_ringbuf, frame, total);
    pthread_mutex_unlock(&(caph->out_ringbuf_lock));

    if (r != total)
        return -1;

    cf_handler_wake_commit(caph);

    return 1;
}

/* Send a generic packet; pre-assembled packet content must be provided
 * and is copied into a packet.  More efficiency-centric callers should
 * call prep/commit and assemble into a zero-copy instance. */
int cf_send_rb_packet(kis_capture_handler_t *caph, unsigned int command,
        uint32_t seqno, uint16_t code, uint8_t *data, size_t len) {

    /* Frame we'll be sending */
    kismet_external_frame_v3_t *frame =
        cf_prep_rb_packet(caph, command, seqno, code, len);
    int r;

    /* free calling data and unlock if we failed */
    if (frame == NULL) {
        free(data);
        return 0;
    }

    memcpy(frame->data, data, len);

    r = cf_commit_rb_packet(caph, frame, len);

    free(data);

    return r;
}

#ifdef HAVE_LIBWEBSOCKETS
/* Prepare a websockets command in an allocated buffer.
 *
 * Websockets use a queue of allocated buffers, so the advantages aren't as
 * large as for the tcp rb, but this still prevents excess memory copies
 *
 * The packet must be concluded with cf_commit_rb_packet with the final size.
 */
struct cf_ws_msg *cf_prep_ws_packet(kis_capture_handler_t *caph,
        unsigned int command, uint32_t seqno, uint16_t code,
        size_t estimated_len) {
    /* msg record */
    struct cf_ws_msg *ws_msg = NULL;

    /* Frame we'll be sending */
    kismet_external_frame_v3_t *frame = NULL;

    enum cf_out_class cls = cf_out_frame_class(command);
    uint64_t dropped;

    pthread_mutex_lock(&(caph->out_ringbuf_lock));

    if (!cf_ws_ring_ready(caph)) {
        pthread_mutex_unlock(&(caph->out_ringbuf_lock));
        return NULL;
    }

    if (!cf_ws_out_fits(caph, cls)) {
        dropped = cf_out_ctl_dropped(caph, cls);
        cf_ws_wake(caph);
        pthread_mutex_unlock(&caph->out_ringbuf_lock);
        cf_out_ctl_drop_log(command, dropped);
        return NULL;
    }

    ws_msg = (struct cf_ws_msg *) calloc(1, sizeof(struct cf_ws_msg));
    if (ws_msg == NULL) {
        fprintf(stderr, "FATAL: Failed to allocate ws buffer\n");
        pthread_mutex_unlock(&caph->out_ringbuf_lock);
        return NULL;
    }

    ws_msg->payload = (char *) malloc(LWS_PRE + estimated_len + sizeof(kismet_external_frame_v3_t));
    if (ws_msg->payload == NULL) {
        fprintf(stderr, "FATAL: Failed to allocate ws buffer\n");
        free(ws_msg);
        pthread_mutex_unlock(&caph->out_ringbuf_lock);
        return NULL;
    }

    // ws_msg->len = len + sizeof(kismet_external_frame_v3_t);

    /* Map to the tx frame */
    frame = (kismet_external_frame_v3_t *) (ws_msg->payload + LWS_PRE);

    /* Set the signature and data size */
    frame->signature = htonl(KIS_EXTERNAL_PROTO_SIG);
    frame->v3_sentinel = htons(KIS_EXTERNAL_V3_SIG);
    frame->v3_version = htons(3);

    frame->seqno = htonl(seqno);

    frame->pkt_type = htons(command);

    frame->code = htons(code);
    // frame->length = htons(len);

    return ws_msg;
}

int cf_commit_ws_packet(kis_capture_handler_t *caph, struct cf_ws_msg *wsmsg, size_t final_len) {
    kismet_external_frame_v3_t *frame;
    int n;

    wsmsg->len = final_len + sizeof(kismet_external_frame_v3_t);

    frame = (kismet_external_frame_v3_t *) (wsmsg->payload + LWS_PRE);
    frame->length = htonl(final_len);

    /* performing the insert here causes a memcpy of the wsmsg struct,
     * so we're now able to (and must) destroy our copy */
    n = lws_ring_insert(caph->lwsring, wsmsg, 1);

    /* free the holder, the data content will be freed when the websocket
     * ringbuffer triggers the element delete */
    free(wsmsg);

    if (n != 1) {
        fprintf(stderr, "FATAL:  Failed to queue ws message\n");
        pthread_mutex_unlock(&caph->out_ringbuf_lock);
        lws_cancel_service(caph->lwscontext);
        return -1;
    }

    cf_ws_wake(caph);
    pthread_mutex_unlock(&(caph->out_ringbuf_lock));

    return 1;
}


/* Send a websocket packet; pre-assembled packet content must be provided and
 * is copied into the packet.  More efficiency-centric callers should consider
 * calling prep/commit to omit an extra copy */
int cf_send_ws_packet(kis_capture_handler_t *caph, unsigned int command, uint32_t seqno,
        uint16_t code, uint8_t *data, size_t len) {

    struct cf_ws_msg *wsmsg;
    kismet_external_frame_v3_t *frame;
    int n;

    wsmsg = cf_prep_ws_packet(caph, command, seqno, code, len);
    if (wsmsg == NULL) {
        free(data);
        return 0;
    }

    frame = (kismet_external_frame_v3_t *) (wsmsg->payload + LWS_PRE);

    memcpy(frame->data, data, len);

    free(data);

    n = cf_commit_ws_packet(caph, wsmsg, len);
    if (n != 0) {
        return n;
    }

    return 1;
}

#endif

static void cf_free_rb_meta(kis_capture_handler_t *caph,
        struct _cf_frame_metadata *meta) {
    kis_simple_ringbuf_commit(caph->out_ringbuf, meta->frame, 0);
}

#ifdef HAVE_LIBWEBSOCKETS
static void cf_free_ws_meta(kis_capture_handler_t *caph,
        struct _cf_frame_metadata *meta) {
    struct cf_ws_msg *msg = (struct cf_ws_msg *) meta->metadata;
    free(msg->payload);
    free(meta->metadata);
}
#endif

cf_frame_metadata *cf_prepare_packet(kis_capture_handler_t *caph,
        unsigned int command, uint32_t seqno, uint16_t code,
        size_t estimated_len) {

    cf_frame_metadata *meta = NULL;

    if (caph->use_tcp || caph->use_ipc) {
        kismet_external_frame_v3_t *frame =
            cf_prep_rb_packet(caph, command, seqno, code, estimated_len);

        if (frame == NULL) {
            return NULL;
        }


        meta = (cf_frame_metadata *) malloc(sizeof(cf_frame_metadata));
        memset(meta, 0, sizeof(cf_frame_metadata));

        meta->free_record = cf_free_rb_meta;

        meta->frame = frame;

        return meta;
#ifdef HAVE_LIBWEBSOCKETS
    } else if (caph->use_ws) {
        struct cf_ws_msg *ws_msg =
            cf_prep_ws_packet(caph, command, seqno, code, estimated_len);

        if (ws_msg == NULL) {
            return NULL;
        }

        meta = (cf_frame_metadata *) malloc(sizeof(cf_frame_metadata));
        memset(meta, 0, sizeof(cf_frame_metadata));

        meta->free_record = cf_free_ws_meta;

        meta->metadata = ws_msg;
        meta->frame = (kismet_external_frame_v3_t *) (ws_msg->payload + LWS_PRE);

        return meta;
#endif
    } else {
        fprintf(stderr, "ERROR:  cf_send_packet with unknown connection type\n");
        return NULL;
    }

}

void cf_cancel_packet(kis_capture_handler_t *caph, cf_frame_metadata *meta) {
    if (meta == NULL) {
        pthread_mutex_unlock(&caph->out_ringbuf_lock);
        return;
    }

    if (meta->free_record != NULL) {
        (meta->free_record)(caph, meta);
    }

    free(meta);

    pthread_mutex_unlock(&caph->out_ringbuf_lock);
}

int cf_commit_packet(kis_capture_handler_t *caph, cf_frame_metadata *meta, size_t final_len) {
    int r = -1;

    /* The commit owns the frame; only the metadata wrapper is ours to free */
    if (caph->use_tcp || caph->use_ipc) {
        r = cf_commit_rb_packet(caph, meta->frame, final_len);
#ifdef HAVE_LIBWEBSOCKETS
    } else if (caph->use_ws) {
        r = cf_commit_ws_packet(caph, (struct cf_ws_msg *) meta->metadata, final_len);
#endif
    }

    free(meta);

    return r;
}

uint32_t cf_get_next_seqno(kis_capture_handler_t *caph) {
    uint32_t seqno;

    /* Lock the handler and get the next sequence number */
    pthread_mutex_lock(&(caph->handler_lock));
    if (++caph->seqno == 0)
        caph->seqno = 1;
    seqno = caph->seqno;
    pthread_mutex_unlock(&(caph->handler_lock));

    return seqno;
}

int cf_send_packet(kis_capture_handler_t *caph, unsigned int packtype, uint16_t code,
        uint8_t *data, size_t len) {
    uint32_t seqno = cf_get_next_seqno(caph);

    if (caph->use_tcp || caph->use_ipc) {
        return cf_send_rb_packet(caph, packtype, seqno, code, data, len);
#ifdef HAVE_LIBWEBSOCKETS
    } else if (caph->use_ws) {
        return cf_send_ws_packet(caph, packtype, seqno, code, data, len);
#endif
    } else {
        fprintf(stderr, "ERROR:  cf_send_packet with unknown connection type\n");
        return -1;
    }
}

int cf_send_message(kis_capture_handler_t *caph, const char *msg, unsigned int flags) {
    /* Estimate the length of the buffer as the length of the string, the
     * size of the flags, the string type, and some slop room */
    size_t est_len = (strlen(msg) + 4 + 4) * 1.25;
    size_t final_len = 0;

    uint32_t seqno = cf_get_next_seqno(caph);
    cf_frame_metadata *meta = NULL;

    mpack_writer_t writer;
    mpack_error_t err;

    meta =
        cf_prepare_packet(caph, KIS_EXTERNAL_V3_CMD_MESSAGE, seqno, 0, est_len);

    if (meta == NULL) {
        return 0;
    }

    mpack_writer_init(&writer, (char *) meta->frame->data, est_len);

    mpack_build_map(&writer);
    mpack_write_uint(&writer, KIS_EXTERNAL_V3_MESSAGE_FIELD_TYPE);
    mpack_write_u8(&writer, flags);
    mpack_write_uint(&writer, KIS_EXTERNAL_V3_MESSAGE_FIELD_STRING);
    mpack_write_str(&writer, msg, strlen(msg));
    mpack_complete_map(&writer);

    final_len = mpack_writer_buffer_used(&writer);

    if ((err = mpack_writer_destroy(&writer)) != mpack_ok) {
        fprintf(stderr, "FATAL: Mpack couldn't serialize MESSAGE (%u)\n", err);
        cf_cancel_packet(caph, meta);
        return -1;
    }

    return cf_commit_packet(caph, meta, final_len);
}

int cf_send_warning(kis_capture_handler_t *caph, const char *warning) {
    return cf_send_message(caph, warning, KIS_EXTERNAL_V3_MSG_ERROR);
}

int cf_send_error(kis_capture_handler_t *caph, uint32_t in_seqno, const char *msg) {
    size_t est_len = 0;
    size_t final_len = 0;

    mpack_writer_t writer;
    mpack_error_t err;

    cf_frame_metadata *meta = NULL;

    if (msg != NULL) {
        est_len = (strlen(msg) + 4) * 1.25;
    } else {
        est_len = 24;
    }

    meta =
        cf_prepare_packet(caph, KIS_EXTERNAL_V3_CMD_ERROR, in_seqno, 1, est_len);

    if (meta == NULL) {
        return 0;
    }

    mpack_writer_init(&writer, (char *) meta->frame->data, est_len);

    mpack_build_map(&writer);

    if (msg != NULL) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_ERROR_FIELD_STRING);
        mpack_write_cstr(&writer, msg);
    }

    mpack_complete_map(&writer);

    final_len = mpack_writer_buffer_used(&writer);

    if ((err = mpack_writer_destroy(&writer)) != mpack_ok) {
        fprintf(stderr, "FATAL: Mpack couldn't serialize ERROR (%u)\n", err);
        cf_cancel_packet(caph, meta);
        return -1;
    }

    return cf_commit_packet(caph, meta, final_len);
}

int cf_send_listresp(kis_capture_handler_t *caph, uint32_t seq, unsigned int success,
        const char *msg, cf_params_list_interface_t **interfaces, size_t len) {
    size_t est_len = 24;
    size_t final_len = 0;

    mpack_writer_t writer;
    mpack_error_t err;
    cf_frame_metadata *meta = NULL;

    size_t i;

    uint32_t seqno;

    int n;

    /* Room for the per-binary suffix */
    char version[96];

    cf_version_string(version, sizeof(version));

    est_len += strlen(version);

    /* Send messages independently */
    if (msg != NULL) {
        if (success) {
            if (caph->verbose)
                fprintf(stderr, "INFO: %s\n", msg);
        } else {
            if (caph->verbose)
                fprintf(stderr, "ERROR: %s\n", msg);
        }

    }

    /* Failures go back as a list report with a nonzero code (0 is success for
     * list reports, unlike probe/open/config) and the error text */
    if (!success) {
        len = 0;

        if (msg != NULL)
            est_len += strlen(msg);
    } else if (msg != NULL && strlen(msg) != 0) {
        /* Send messages independently not tied to this sequence,
         * they're just informational */
        n = cf_send_message(caph, msg, MSGFLAG_INFO);

        if (n < 0) {
            return n;
        }
    }

    est_len += 4 * len;

    /* Calculate the length of all interface data */
    for (i = 0; i < len; i++) {
        if (interfaces[i]->interface != NULL) {
            est_len += strlen(interfaces[i]->interface);
        }

        if (interfaces[i]->flags != NULL) {
            est_len += strlen(interfaces[i]->flags);
        }

        if (interfaces[i]->hardware != NULL) {
            est_len += strlen(interfaces[i]->hardware);
        }
    }

    est_len = est_len * 1.5;

    seqno = cf_get_next_seqno(caph);

    meta =
        cf_prepare_packet(caph, KIS_EXTERNAL_V3_KDS_LISTREPORT, seqno, success ? 0 : 1, est_len);

    if (meta == NULL) {
        return 0;
    }

    mpack_writer_init(&writer, (char *) meta->frame->data, est_len);

    mpack_build_map(&writer);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_LISTREPORT_FIELD_SEQNO);
    mpack_write_u32(&writer, seq);

    if (!success && msg != NULL) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_LISTREPORT_FIELD_MSG);
        mpack_write_cstr(&writer, msg);
    }

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_LISTREPORT_FIELD_VERSION);
    mpack_write_cstr(&writer, version);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_LISTREPORT_FIELD_IFLIST);
    mpack_start_array(&writer, len);

    for (i = 0; i < len; i++) {
        mpack_build_map(&writer);

        if (interfaces[i]->interface != NULL) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_INTERFACE_FIELD_IFACE);
            mpack_write_cstr(&writer, interfaces[i]->interface);
        }

        if (interfaces[i]->flags != NULL) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_INTERFACE_FIELD_FLAGS);
            mpack_write_cstr(&writer, interfaces[i]->flags);
        }

        if (interfaces[i]->hardware != NULL) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_INTERFACE_FIELD_HW);
            mpack_write_cstr(&writer, interfaces[i]->hardware);
        }

        mpack_complete_map(&writer);
    }

    mpack_finish_array(&writer);
    mpack_complete_map(&writer);

    final_len = mpack_writer_buffer_used(&writer);

    if ((err = mpack_writer_destroy(&writer)) != mpack_ok) {
        cf_cancel_packet(caph, meta);
        fprintf(stderr, "FATAL: Mpack couldn't serialize LISTREPORT (%u)\n", err);
        return -1;
    }

    return cf_commit_packet(caph, meta, final_len);
}

int cf_send_proberesp(kis_capture_handler_t *caph, uint32_t seq,
        unsigned int success, const char *msg,
        cf_params_interface_t *interface, cf_params_spectrum_t *spectrum) {

    size_t est_len = 24;
    size_t final_len = 0;

    mpack_writer_t writer;
    mpack_error_t err;
    cf_frame_metadata *meta = NULL;

    size_t i;

    /* Send messages independently */
    if (msg != NULL && strlen(msg) > 0) {
        if (success) {
            if (caph->verbose)
                fprintf(stderr, "INFO: %s\n", msg);
        } else {
            if (caph->verbose)
                fprintf(stderr, "ERROR: %s\n", msg);
        }

        est_len += strlen(msg);
    }

    if (interface != NULL) {
        est_len += 16;

        if (interface->capif != NULL) {
            est_len += strlen(interface->capif);
        }

        if (interface->chanset != NULL) {
            est_len += strlen(interface->chanset);
        }

        if (interface->hardware != NULL) {
            est_len += strlen(interface->hardware);
        }

        for (i = 0; i < interface->channels_len; i++) {
            est_len += strlen(interface->channels[i]);
        }
    }

    /* we don't handle spectrum yet in v3 until we figure out how to define it */

    est_len = est_len * 1.5;

    meta =
        cf_prepare_packet(caph, KIS_EXTERNAL_V3_KDS_PROBEREPORT, seq, success, est_len);

    if (meta == NULL) {
        return 0;
    }

    mpack_writer_init(&writer, (char *) meta->frame->data, est_len);
    mpack_build_map(&writer);

    if (msg != NULL) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_PROBEREPORT_FIELD_MSG);
        mpack_write_cstr(&writer, msg);
    }

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_PROBEREPORT_FIELD_SEQNO);
    mpack_write_u32(&writer, seq);

    if (interface != NULL) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_PROBEREPORT_FIELD_INTERFACE);
        mpack_build_map(&writer);
        if (interface->capif != NULL) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_INTERFACE_FIELD_CAPIFACE);
            mpack_write_cstr(&writer, interface->capif);
        }

        if (interface->hardware != NULL) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_INTERFACE_FIELD_HW);
            mpack_write_cstr(&writer, interface->hardware);
        }

        if (interface->chanset != NULL) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_INTERFACE_FIELD_CHANNEL);
            mpack_write_cstr(&writer, interface->chanset);
        }

        if (interface->channels_len > 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_INTERFACE_FIELD_CHAN_LIST);
            mpack_start_array(&writer, interface->channels_len);
            for (i = 0; i < interface->channels_len; i++) {
                mpack_write_cstr(&writer, interface->channels[i]);
            }
            mpack_finish_array(&writer);
        }
        mpack_complete_map(&writer);
    }

    mpack_complete_map(&writer);

    final_len = mpack_writer_buffer_used(&writer);

    if ((err = mpack_writer_destroy(&writer)) != mpack_ok) {
        fprintf(stderr, "ERROR: Mpack couldn't serialize PROBEREPORT (%u)\n", err);
        cf_cancel_packet(caph, meta);
        return -1;
    }

    return cf_commit_packet(caph, meta, final_len);
}

int cf_send_openresp(kis_capture_handler_t *caph, uint32_t seq, unsigned int success,
        const char *msg, uint32_t dlt, const char *uuid,
        cf_params_interface_t *interface, cf_params_spectrum_t *spectrum) {

    size_t est_len = 28;
    size_t final_len = 0;

    mpack_writer_t writer;
    mpack_error_t err;
    cf_frame_metadata *meta = NULL;

    /* Room for the per-binary suffix */
    char version[96];

    size_t i;

    cf_version_string(version, sizeof(version));

    est_len += strlen(version);

    if (msg != NULL && strlen(msg) != 0) {
        if (success) {
            if (caph->verbose)
                fprintf(stderr, "INFO: %s\n", msg);
        } else {
            if (caph->verbose)
                fprintf(stderr, "ERROR: %s\n", msg);
        }

        est_len += strlen(msg);
    }

    if (interface != NULL) {
        est_len += 16;

        if (interface->capif != NULL) {
            est_len += strlen(interface->capif);
        }

        if (interface->chanset != NULL) {
            est_len += strlen(interface->chanset);
        }

        if (interface->hardware != NULL) {
            est_len += strlen(interface->hardware);
        }

        for (i = 0; i < interface->channels_len; i++) {
            est_len += strlen(interface->channels[i]);
        }
    }

    if (uuid != NULL) {
        est_len += strlen(uuid);
    }

    if (caph->hopping_running) {
        /* rate + shuffle + skip + offset + array */
        est_len += 8 + 1 + 2 + 2 + 4;

        for (i = 0; i < caph->channel_hop_list_sz; i++) {
            est_len += strlen(caph->channel_hop_list[i]);
        }
    }

    /* we don't handle spectrum yet in v3 until we figure out how to define it */

    /* key + uint32 for the graceful-close grace */
    est_len += 8;

    est_len = est_len * 1.5;

    meta =
        cf_prepare_packet(caph, KIS_EXTERNAL_V3_KDS_OPENREPORT, seq, success, est_len);

    if (meta == NULL) {
        return 0;
    }

    mpack_writer_init(&writer, (char *) meta->frame->data, est_len);

    mpack_build_map(&writer);

    if (msg != NULL) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_MSG);
        mpack_write_cstr(&writer, msg);
    }

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_SEQNO);
    mpack_write_u32(&writer, seq);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_DLT);
    mpack_write_u32(&writer, dlt);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_VERSION);
    mpack_write_cstr(&writer, version);

    /* Only an opted-in source advertises it: the field's absence is what keeps
     * the server on the plain close for everything else. */
    if (caph->close_grace_ms > 0) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_CLOSEGRACE);
        mpack_write_u32(&writer, caph->close_grace_ms);
    }

    if (uuid != NULL) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_UUID);
        mpack_write_cstr(&writer, uuid);
    }

    if (interface != NULL) {
        if (interface->capif != NULL) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_CAPIF);
            mpack_write_cstr(&writer, interface->capif);
        }

        if (interface->hardware != NULL) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_HARDWARE);
            mpack_write_cstr(&writer, interface->hardware);
        }

        if (interface->chanset != NULL) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_CHANNEL);
            mpack_write_cstr(&writer, interface->chanset);
        }

        if (interface->channels_len > 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_CHAN_LIST);
            mpack_start_array(&writer, interface->channels_len);
            for (i = 0; i < interface->channels_len; i++) {
                mpack_write_cstr(&writer, interface->channels[i]);
            }
            mpack_finish_array(&writer);
        }
    }

    if (caph->hopping_running) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_OPENREPORT_FIELD_CHANHOPBLOCK);
        mpack_build_map(&writer);

        if (caph->channel_hop_list_sz > 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_CHAN_LIST);
            mpack_start_array(&writer, caph->channel_hop_list_sz);

            for (i = 0; i < caph->channel_hop_list_sz; i++) {
                mpack_write_cstr(&writer, caph->channel_hop_list[i]);
            }

            mpack_finish_array(&writer);
        }

        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_RATE);
        mpack_write_float(&writer, caph->channel_hop_rate);

        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SHUFFLE);
        mpack_write_bool(&writer, caph->channel_hop_shuffle);

        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_OFFSET);
        mpack_write_uint(&writer, caph->channel_hop_offset);

        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SKIP);
        mpack_write_uint(&writer, cf_hop_valid_spacing(caph->channel_hop_shuffle,
                    caph->channel_hop_shuffle_spacing, caph->channel_hop_list_sz));

        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_ENABLED);
        mpack_write_bool(&writer, true);

        mpack_complete_map(&writer);
    }

    mpack_complete_map(&writer);

    final_len = mpack_writer_buffer_used(&writer);

    if ((err = mpack_writer_destroy(&writer)) != mpack_ok) {
        fprintf(stderr, "ERROR: Mpack couldn't serialize OPENREPORT (%u)\n", err);
        cf_cancel_packet(caph, meta);
        return -1;
    }

    return cf_commit_packet(caph, meta, final_len);
}

int cf_send_data(kis_capture_handler_t *caph,
        const char *msg, unsigned int msg_type,
        struct cf_params_signal *signal, struct cf_params_gps *gps,
        struct timeval ts, uint32_t dlt, uint32_t original_sz,
        uint32_t packet_sz, uint8_t *pack) {

    size_t est_len = 24;
    size_t final_len = 0;

    mpack_writer_t writer;
    mpack_error_t err;
    cf_frame_metadata *meta = NULL;

    uint32_t seqno;
    uint32_t flags;

    if (msg != NULL) {
        if (caph->verbose) {
            switch (msg_type) {
                case KIS_EXTERNAL_V3_MSG_DEBUG:
                    fprintf(stderr, "DEBUG: %s\n", msg);
                    break;
                case KIS_EXTERNAL_V3_MSG_INFO:
                    fprintf(stderr, "INFO: %s\n", msg);
                    break;
                case KIS_EXTERNAL_V3_MSG_ERROR:
                    fprintf(stderr, "ERROR: %s\n", msg);
                    break;
                case KIS_EXTERNAL_V3_MSG_ALERT:
                    fprintf(stderr, "ALERT: %s\n", msg);
                    break;
                case KIS_EXTERNAL_V3_MSG_FATAL:
                    fprintf(stderr, "FATAL: %s\n", msg);
                    break;
            }
        }

        est_len += strlen(msg);
    }

    if (signal != NULL) {
        KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_EST_LEN(est_len, signal);
    }

    if (gps != NULL) {
        KIS_EXTERNAL_V3_KDS_SUB_GPS_EST_LEN(est_len, gps);
    } else if (caph->gps_fixed_lat != 0) {
        if (caph->gps_name != NULL) {
            KIS_EXTERNAL_V3_KDS_SUB_GPS_EST_LEN2(est_len, "remote-fixed",
                    caph->gps_name);
        } else {
            KIS_EXTERNAL_V3_KDS_SUB_GPS_EST_LEN2(est_len, "remote-fixed",
                    "remote-fixed");
        }

    }

    KIS_EXTERNAL_V3_KDS_SUB_PACKET_EST_LEN(est_len, packet_sz);

    /* packet flags */
    est_len += 8;

    est_len = est_len * 1.5;

    seqno = cf_get_next_seqno(caph);

    meta =
        cf_prepare_packet(caph, KIS_EXTERNAL_V3_KDS_PACKET, seqno, 0, est_len);

    if (meta == NULL) {
        return 0;
    }

    mpack_writer_init(&writer, (char *) meta->frame->data, est_len);

    mpack_build_map(&writer);

    if (gps != NULL || caph->gps_fixed_lat != 0) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_GPSBLOCK);
        mpack_build_map(&writer);

        if (gps != NULL) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_LAT);
            mpack_write_double(&writer, gps->lat);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_LON);
            mpack_write_double(&writer, gps->lon);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_ALT);
            mpack_write_float(&writer, gps->alt);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_FIX);
            mpack_write_u8(&writer, gps->fix);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_SPEED);
            mpack_write_float(&writer, gps->speed);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_HEADING);
            mpack_write_float(&writer, gps->heading);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_PRECISION);
            mpack_write_float(&writer, gps->precision);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TS_S);
            mpack_write_u64(&writer, gps->ts_sec);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TS_US);
            mpack_write_u64(&writer, gps->ts_usec);

            if (gps->gps_type != NULL) {
                mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TYPE);
                mpack_write_cstr(&writer, gps->gps_type);
            }

            if (gps->gps_name != NULL) {
                mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TYPE);
                mpack_write_cstr(&writer, gps->gps_name);
            }

            if (gps->gps_uuid != NULL) {
                mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_UUID);
                mpack_write_cstr(&writer, gps->gps_uuid);
            }
        } else if (caph->gps_fixed_lat != 0) {
            struct timeval tv;
            gettimeofday(&tv, NULL);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_LAT);
            mpack_write_double(&writer, caph->gps_fixed_lat);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_LON);
            mpack_write_double(&writer, caph->gps_fixed_lon);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_ALT);
            mpack_write_float(&writer, caph->gps_fixed_alt);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_FIX);
            mpack_write_u8(&writer, 3);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TYPE);
            mpack_write_cstr(&writer, "remote-fixed");

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TS_S);
            mpack_write_u64(&writer, tv.tv_sec);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TS_US);
            mpack_write_u64(&writer, tv.tv_usec);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_NAME);
            if (caph->gps_name != NULL) {
                mpack_write_cstr(&writer, caph->gps_name);
            } else {
                mpack_write_cstr(&writer, "remote-fixed");
            }
        }

        mpack_complete_map(&writer);
    }

    if (signal != NULL) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_SIGNALBLOCK);
        mpack_build_map(&writer);

        if (signal->channel != NULL) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_CHANNEL);
            mpack_write_cstr(&writer, signal->channel);
        }

        if (signal->signal_dbm != 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_SIGNAL_DBM);
            mpack_write_u32(&writer, signal->signal_dbm);
        }

        if (signal->noise_dbm != 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_NOISE_DBM);
            mpack_write_u32(&writer, signal->noise_dbm);
        }

        if (signal->signal_rssi != 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_SIGNAL_RSSI);
            mpack_write_u32(&writer, signal->signal_rssi);
        }

        if (signal->noise_rssi != 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_NOISE_RSSI);
            mpack_write_u32(&writer, signal->noise_rssi);
        }

        if (signal->freq_khz != 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_FREQ_KHZ);
            mpack_write_u64(&writer, signal->freq_khz);
        }

        if (signal->datarate != 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_DATARATE);
            mpack_write_u64(&writer, signal->datarate);
        }

        mpack_complete_map(&writer);
    }

    /* write the packet itself */
    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_PACKETBLOCK);
    mpack_build_map(&writer);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_DLT);
    mpack_write_u32(&writer, dlt);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_TS_S);
    mpack_write_u64(&writer, ts.tv_sec);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_TS_US);
    mpack_write_u32(&writer, ts.tv_usec);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_LENGTH);
    mpack_write_u32(&writer, original_sz);

    if ((flags = cf_packet_flags(caph, ts)) != 0) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_FLAGS);
        mpack_write_u32(&writer, flags);
    }

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_CONTENT);
    mpack_write_bin(&writer, (const char *) pack, packet_sz);

    mpack_complete_map(&writer);

    /* complete the map */
    mpack_complete_map(&writer);

    final_len = mpack_writer_buffer_used(&writer);

    if ((err = mpack_writer_destroy(&writer)) != mpack_ok) {
        fprintf(stderr, "ERROR: Mpack couldn't serialize DATA (%u)\n", err);
        cf_cancel_packet(caph, meta);
        return -1;
    }

    return cf_commit_packet(caph, meta, final_len);
}

int cf_send_data_multi(kis_capture_handler_t *caph,
        const char *msg, unsigned int msg_type,
        struct cf_params_signal *signal, struct cf_params_gps *gps,
        struct timeval ts, uint32_t dlt,
        uint32_t header_sz, uint8_t *hdr,
        uint32_t original_sz, uint32_t packet_sz, uint8_t *pack,
        uint32_t footer_sz, uint8_t *foot) {

    size_t est_len = 24;
    size_t final_len = 0;

    mpack_writer_t writer;
    mpack_error_t err;
    cf_frame_metadata *meta = NULL;

    uint32_t seqno;
    uint32_t flags;

    uint32_t synth_packet_sz = header_sz + packet_sz + footer_sz;
    uint32_t synth_original_sz = header_sz + original_sz + footer_sz;

    if (msg != NULL) {
        if (caph->verbose) {
            switch (msg_type) {
                case KIS_EXTERNAL_V3_MSG_DEBUG:
                    fprintf(stderr, "DEBUG: %s\n", msg);
                    break;
                case KIS_EXTERNAL_V3_MSG_INFO:
                    fprintf(stderr, "INFO: %s\n", msg);
                    break;
                case KIS_EXTERNAL_V3_MSG_ERROR:
                    fprintf(stderr, "ERROR: %s\n", msg);
                    break;
                case KIS_EXTERNAL_V3_MSG_ALERT:
                    fprintf(stderr, "ALERT: %s\n", msg);
                    break;
                case KIS_EXTERNAL_V3_MSG_FATAL:
                    fprintf(stderr, "FATAL: %s\n", msg);
                    break;
            }
        }

        est_len += strlen(msg);
    }

    if (signal != NULL) {
        KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_EST_LEN(est_len, signal);
    }

    if (gps != NULL) {
        KIS_EXTERNAL_V3_KDS_SUB_GPS_EST_LEN(est_len, gps);
    } else if (caph->gps_fixed_lat != 0) {
        if (caph->gps_name != NULL) {
            KIS_EXTERNAL_V3_KDS_SUB_GPS_EST_LEN2(est_len, "remote-fixed",
                    caph->gps_name);
        } else {
            KIS_EXTERNAL_V3_KDS_SUB_GPS_EST_LEN2(est_len, "remote-fixed",
                    "remote-fixed");
        }

    }

    KIS_EXTERNAL_V3_KDS_SUB_PACKET_EST_LEN(est_len, synth_packet_sz);

    /* packet flags */
    est_len += 8;

    est_len = est_len * 1.5;

    seqno = cf_get_next_seqno(caph);

    meta =
        cf_prepare_packet(caph, KIS_EXTERNAL_V3_KDS_PACKET, seqno, 0, est_len);

    if (meta == NULL) {
        return 0;
    }

    mpack_writer_init(&writer, (char *) meta->frame->data, est_len);

    mpack_build_map(&writer);

    if (gps != NULL || caph->gps_fixed_lat != 0) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_GPSBLOCK);
        mpack_build_map(&writer);

        if (gps != NULL) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_LAT);
            mpack_write_double(&writer, gps->lat);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_LON);
            mpack_write_double(&writer, gps->lon);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_ALT);
            mpack_write_float(&writer, gps->alt);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_FIX);
            mpack_write_u8(&writer, gps->fix);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_SPEED);
            mpack_write_float(&writer, gps->speed);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_HEADING);
            mpack_write_float(&writer, gps->heading);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_PRECISION);
            mpack_write_float(&writer, gps->precision);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TS_S);
            mpack_write_u64(&writer, gps->ts_sec);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TS_US);
            mpack_write_u64(&writer, gps->ts_usec);

            if (gps->gps_type != NULL) {
                mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TYPE);
                mpack_write_cstr(&writer, gps->gps_type);
            }

            if (gps->gps_name != NULL) {
                mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TYPE);
                mpack_write_cstr(&writer, gps->gps_name);
            }

            if (gps->gps_uuid != NULL) {
                mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_UUID);
                mpack_write_cstr(&writer, gps->gps_uuid);
            }
        } else if (caph->gps_fixed_lat != 0) {
            struct timeval tv;
            gettimeofday(&tv, NULL);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_LAT);
            mpack_write_double(&writer, caph->gps_fixed_lat);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_LON);
            mpack_write_double(&writer, caph->gps_fixed_lon);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_ALT);
            mpack_write_float(&writer, caph->gps_fixed_alt);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_FIX);
            mpack_write_u8(&writer, 3);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TYPE);
            mpack_write_cstr(&writer, "remote-fixed");

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TS_S);
            mpack_write_u64(&writer, tv.tv_sec);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TS_US);
            mpack_write_u64(&writer, tv.tv_usec);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_NAME);
            if (caph->gps_name != NULL) {
                mpack_write_cstr(&writer, caph->gps_name);
            } else {
                mpack_write_cstr(&writer, "remote-fixed");
            }
        }

        mpack_complete_map(&writer);
    }

    if (signal != NULL) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_SIGNALBLOCK);
        mpack_build_map(&writer);

        if (signal->channel != NULL) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_CHANNEL);
            mpack_write_cstr(&writer, signal->channel);
        }

        if (signal->signal_dbm != 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_SIGNAL_DBM);
            mpack_write_u32(&writer, signal->signal_dbm);
        }

        if (signal->noise_dbm != 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_NOISE_DBM);
            mpack_write_u32(&writer, signal->noise_dbm);
        }

        if (signal->signal_rssi != 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_SIGNAL_RSSI);
            mpack_write_u32(&writer, signal->signal_rssi);
        }

        if (signal->noise_rssi != 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_NOISE_RSSI);
            mpack_write_u32(&writer, signal->noise_rssi);
        }

        if (signal->freq_khz != 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_FREQ_KHZ);
            mpack_write_u64(&writer, signal->freq_khz);
        }

        if (signal->datarate != 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_DATARATE);
            mpack_write_u64(&writer, signal->datarate);
        }

        mpack_complete_map(&writer);
    }

    /* write the packet itself */
    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_PACKETBLOCK);
    mpack_build_map(&writer);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_DLT);
    mpack_write_u32(&writer, dlt);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_TS_S);
    mpack_write_u64(&writer, ts.tv_sec);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_TS_US);
    mpack_write_u32(&writer, ts.tv_usec);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_LENGTH);
    mpack_write_u32(&writer, synth_original_sz);

    if ((flags = cf_packet_flags(caph, ts)) != 0) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_FLAGS);
        mpack_write_u32(&writer, flags);
    }

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_PACKET_FIELD_CONTENT);
    mpack_start_bin(&writer, synth_packet_sz);
    mpack_write_bytes(&writer, (const char *) hdr, header_sz);
    mpack_write_bytes(&writer, (const char *) pack, packet_sz);
    mpack_write_bytes(&writer, (const char *) foot, footer_sz);
    mpack_finish_bin(&writer);

    mpack_complete_map(&writer);

    /* complete the map */
    mpack_complete_map(&writer);

    final_len = mpack_writer_buffer_used(&writer);

    if ((err = mpack_writer_destroy(&writer)) != mpack_ok) {
        fprintf(stderr, "ERROR: Mpack couldn't serialize DATA (%u)\n", err);
        cf_cancel_packet(caph, meta);
        return -1;
    }

    return cf_commit_packet(caph, meta, final_len);

}


int cf_send_json(kis_capture_handler_t *caph,
        const char *msg, unsigned int msg_type,
        struct cf_params_signal *signal,
        struct cf_params_gps *gps,
        struct timeval ts, const char *type, const char *json) {

    size_t est_len = 24;
    size_t final_len = 0;

    mpack_writer_t writer;
    mpack_error_t err;
    cf_frame_metadata *meta = NULL;
    uint32_t seqno;

    if (msg != NULL) {
        if (caph->verbose) {
            switch (msg_type) {
                case KIS_EXTERNAL_V3_MSG_DEBUG:
                    fprintf(stderr, "DEBUG: %s\n", msg);
                    break;
                case KIS_EXTERNAL_V3_MSG_INFO:
                    fprintf(stderr, "INFO: %s\n", msg);
                    break;
                case KIS_EXTERNAL_V3_MSG_ERROR:
                    fprintf(stderr, "ERROR: %s\n", msg);
                    break;
                case KIS_EXTERNAL_V3_MSG_ALERT:
                    fprintf(stderr, "ALERT: %s\n", msg);
                    break;
                case KIS_EXTERNAL_V3_MSG_FATAL:
                    fprintf(stderr, "FATAL: %s\n", msg);
                    break;
            }
        }

        est_len += strlen(msg);
    }

    if (signal != NULL) {
        KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_EST_LEN(est_len, signal);
    }

    if (gps != NULL) {
        KIS_EXTERNAL_V3_KDS_SUB_GPS_EST_LEN(est_len, gps);
    } else if (caph->gps_fixed_lat != 0) {
        if (caph->gps_name != NULL) {
            KIS_EXTERNAL_V3_KDS_SUB_GPS_EST_LEN2(est_len, "remote-fixed",
                    caph->gps_name);
        } else {
            KIS_EXTERNAL_V3_KDS_SUB_GPS_EST_LEN2(est_len, "remote-fixed",
                    "remote-fixed");
        }

    }

    KIS_EXTERNAL_V3_KDS_SUB_JSON_EST_LEN(est_len, type, json);

    est_len = est_len * 1.5;

    seqno = cf_get_next_seqno(caph);

    meta =
        cf_prepare_packet(caph, KIS_EXTERNAL_V3_KDS_PACKET, seqno, 0, est_len);

    if (meta == NULL) {
        return 0;
    }

    mpack_writer_init(&writer, (char *) meta->frame->data, est_len);

    mpack_build_map(&writer);

    if (gps != NULL || caph->gps_fixed_lat != 0) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_GPSBLOCK);
        mpack_build_map(&writer);

        if (gps != NULL) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_LAT);
            mpack_write_double(&writer, gps->lat);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_LON);
            mpack_write_double(&writer, gps->lon);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_ALT);
            mpack_write_float(&writer, gps->alt);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_FIX);
            mpack_write_u8(&writer, gps->fix);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_SPEED);
            mpack_write_float(&writer, gps->speed);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_HEADING);
            mpack_write_float(&writer, gps->heading);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_PRECISION);
            mpack_write_float(&writer, gps->precision);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TS_S);
            mpack_write_u64(&writer, gps->ts_sec);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TS_US);
            mpack_write_u64(&writer, gps->ts_usec);

            if (gps->gps_type != NULL) {
                mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TYPE);
                mpack_write_cstr(&writer, gps->gps_type);
            }

            if (gps->gps_name != NULL) {
                mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TYPE);
                mpack_write_cstr(&writer, gps->gps_name);
            }

            if (gps->gps_uuid != NULL) {
                mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_UUID);
                mpack_write_cstr(&writer, gps->gps_uuid);
            }
        } else if (caph->gps_fixed_lat != 0) {
            struct timeval tv;
            gettimeofday(&tv, NULL);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_LAT);
            mpack_write_double(&writer, caph->gps_fixed_lat);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_LON);
            mpack_write_double(&writer, caph->gps_fixed_lon);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_ALT);
            mpack_write_float(&writer, caph->gps_fixed_alt);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_FIX);
            mpack_write_u8(&writer, 3);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TYPE);
            mpack_write_cstr(&writer, "remote-fixed");

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TS_S);
            mpack_write_u64(&writer, tv.tv_sec);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_TS_US);
            mpack_write_u64(&writer, tv.tv_usec);

            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_GPS_FIELD_NAME);
            if (caph->gps_name != NULL) {
                mpack_write_cstr(&writer, caph->gps_name);
            } else {
                mpack_write_cstr(&writer, "remote-fixed");
            }
        }

        mpack_complete_map(&writer);
    }

    if (signal != NULL) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_SIGNALBLOCK);
        mpack_build_map(&writer);

        if (signal->channel != NULL) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_CHANNEL);
            mpack_write_cstr(&writer, signal->channel);
        }

        if (signal->signal_dbm != 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_SIGNAL_DBM);
            mpack_write_u32(&writer, signal->signal_dbm);
        }

        if (signal->noise_dbm != 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_NOISE_DBM);
            mpack_write_u32(&writer, signal->noise_dbm);
        }

        if (signal->signal_rssi != 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_SIGNAL_RSSI);
            mpack_write_u32(&writer, signal->signal_rssi);
        }

        if (signal->noise_rssi != 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_NOISE_RSSI);
            mpack_write_u32(&writer, signal->noise_rssi);
        }

        if (signal->freq_khz != 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_FREQ_KHZ);
            mpack_write_u64(&writer, signal->freq_khz);
        }

        if (signal->datarate != 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_SIGNAL_FIELD_DATARATE);
            mpack_write_u64(&writer, signal->datarate);
        }

        mpack_complete_map(&writer);
    }

    /* write the json itself */
    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_DATAREPORT_FIELD_JSONBLOCK);
    mpack_build_map(&writer);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_TS_S);
    mpack_write_u64(&writer, ts.tv_sec);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_TS_US);
    mpack_write_u32(&writer, ts.tv_usec);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_TYPE);
    mpack_write_cstr(&writer, type);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_JSON_FIELD_JSON);
    mpack_write_cstr(&writer, json);

    mpack_complete_map(&writer);

    /* complete the map */
    mpack_complete_map(&writer);

    final_len = mpack_writer_buffer_used(&writer);

    if ((err = mpack_writer_destroy(&writer)) != mpack_ok) {
        fprintf(stderr, "ERROR: Mpack couldn't serialize JSON (%u)\n", err);
        cf_cancel_packet(caph, meta);
        return -1;
    }

    return cf_commit_packet(caph, meta, final_len);
}


int cf_send_configresp(kis_capture_handler_t *caph, unsigned int in_seqno,
        unsigned int success, const char *msg) {
    size_t est_len = 24;
    size_t final_len = 0;

    mpack_writer_t writer;
    cf_frame_metadata *meta = NULL;
    mpack_error_t err;

    size_t i;

    /* Send messages independently */
    if (msg != NULL) {
        if (caph->verbose) {
            if (success) {
                fprintf(stderr, "INFO: %s\n", msg);
            } else {
                fprintf(stderr, "ERROR: %s\n", msg);
            }
        }

        est_len += strlen(msg);
    }

    if (caph->hopping_running) {
        /* rate + shuffle + skip + offset + array */
        est_len += (2 + 8) + (2 + 1) + (2 + 2) + (2 + 2) + (2 + 4);

        for (i = 0; i < caph->channel_hop_list_sz; i++) {
            est_len += strlen(caph->channel_hop_list[i]) + 4;
        }
    } else if (caph->channel != NULL) {
        /* NULL until a channel set has succeeded, e.g. when refusing the first one */
        est_len += strlen(caph->channel);
    }

    /* we don't handle spectrum yet in v3 until we figure out how to define it */

    est_len = est_len * 1.5;

    meta =
        cf_prepare_packet(caph, KIS_EXTERNAL_V3_KDS_CONFIGREPORT, in_seqno, success, est_len);

    if (meta == NULL) {
        return 0;
    }

    mpack_writer_init(&writer, (char *) meta->frame->data, est_len);

    mpack_build_map(&writer);

    if (msg) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_CONFIGREPORT_FIELD_MSG);
        mpack_write_cstr(&writer, msg);
    }

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_CONFIGREPORT_FIELD_SEQNO);
    mpack_write_u32(&writer, in_seqno);

    if (caph->hopping_running) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_CONFIGREPORT_FIELD_CHANHOPBLOCK);
        mpack_build_map(&writer);

        if (caph->channel_hop_list_sz > 0) {
            mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_CHAN_LIST);
            mpack_start_array(&writer, caph->channel_hop_list_sz);

            for (i = 0; i < caph->channel_hop_list_sz; i++) {
                mpack_write_cstr(&writer, caph->channel_hop_list[i]);
            }

            mpack_finish_array(&writer);
        }

        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_RATE);
        mpack_write_float(&writer, caph->channel_hop_rate);

        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SHUFFLE);
        mpack_write_bool(&writer, caph->channel_hop_shuffle);

        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_OFFSET);
        mpack_write_uint(&writer, caph->channel_hop_offset);

        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_SKIP);
        mpack_write_uint(&writer, cf_hop_valid_spacing(caph->channel_hop_shuffle,
                    caph->channel_hop_shuffle_spacing, caph->channel_hop_list_sz));

        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_SUB_CHANHOP_FIELD_ENABLED);
        mpack_write_uint(&writer, true);

        mpack_complete_map(&writer);
    } else if (caph->channel != NULL) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_CONFIGREPORT_FIELD_CHANNEL);
        mpack_write_cstr(&writer, caph->channel);
    }

    mpack_complete_map(&writer);

    final_len = mpack_writer_buffer_used(&writer);

    if ((err = mpack_writer_destroy(&writer)) != mpack_ok) {
        fprintf(stderr, "ERROR: Mpack couldn't serialize CONFIGUREREPORT (%u)\n", err);
        cf_cancel_packet(caph, meta);
        return -1;
    }

    return cf_commit_packet(caph, meta, final_len);
}

int cf_send_newsource(kis_capture_handler_t *caph, const char *uuid) {
    size_t est_len = 24;
    size_t final_len = 0;

    mpack_writer_t writer;
    mpack_error_t err;
    cf_frame_metadata *meta = NULL;

    uint32_t seqno;

    est_len += strlen(caph->cli_sourcedef);
    est_len += strlen(caph->capsource_type);
    if (uuid != NULL) {
        est_len += strlen(uuid);
    }

    est_len = est_len * 1.5;

    seqno = cf_get_next_seqno(caph);

    meta =
        cf_prepare_packet(caph, KIS_EXTERNAL_V3_KDS_NEWSOURCE, seqno, 0, est_len);

    if (meta == NULL) {
        return 0;
    }

    mpack_writer_init(&writer, (char *) meta->frame->data, est_len);

    mpack_build_map(&writer);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_NEWSOURCE_FIELD_DEFINITION);
    mpack_write_cstr(&writer, caph->cli_sourcedef);

    mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_NEWSOURCE_FIELD_SOURCETYPE);
    mpack_write_cstr(&writer, caph->capsource_type);

    if (uuid != NULL) {
        mpack_write_uint(&writer, KIS_EXTERNAL_V3_KDS_NEWSOURCE_FIELD_UUID);
        mpack_write_cstr(&writer, uuid);
    }

    mpack_complete_map(&writer);

    final_len = mpack_writer_buffer_used(&writer);

    if ((err = mpack_writer_destroy(&writer)) != mpack_ok) {
        fprintf(stderr, "ERROR: Mpack couldn't serialize NEWSOURCE (%u)\n", err);
        cf_cancel_packet(caph, meta);
        return -1;
    }

    return cf_commit_packet(caph, meta, final_len);
}

int cf_send_pong(kis_capture_handler_t *caph, uint32_t in_seqno) {
    size_t est_len = 24;
    size_t final_len = 0;

    cf_frame_metadata *meta = NULL;

    uint32_t seqno;

    est_len = est_len * 1.5;

    seqno = in_seqno;

    meta =
        cf_prepare_packet(caph, KIS_EXTERNAL_V3_CMD_PONG, seqno, 0, est_len);

    if (meta == NULL) {
        return 0;
    }


    return cf_commit_packet(caph, meta, final_len);
}

double cf_parse_frequency(const char *freq) {
    char *ufreq;
    unsigned int i;
    double v = 0;

    if (freq == NULL)
        return 0;

    if (strlen(freq) == 0)
        return 0;

    /* Make a buffer at least as big as the total string to hold the frequency component */
    ufreq = (char *) malloc(strlen(freq) + 1);

    /* sscanf w/ unbounded string component is still 'safe' here because ufreq is the length
     * of the entire field, so must be able to fit any sub-component of the field.  */
    i = sscanf(freq, "%lf%s", &v, ufreq);

    if (i == 1 || strlen(ufreq) == 0) {
        /* Did we parse a single number or a scientific notation? */
        /* Assume it's in hz */
        v = v / 1000;
    } else if (i == 2) {
        /* hz */
        if (ufreq[0] == 'h' || ufreq[0] == 'H') {
            v = v / 1000;
        } else if (ufreq[0] == 'm' || ufreq[0] == 'M') {
            v = v * 1000;
        } else if (ufreq[0] == 'g' || ufreq[0] == 'G') {
            v = v * 1000 * 1000;
        }
    }

    free(ufreq);
    return v;
}

#ifdef HAVE_CAPABILITY
/* cf_set_caps flags: keep-caps set first (which fails under a locked SECBIT_KEEP_CAPS),
 * and cap_list in the inheritable set too */
#define CF_SET_CAPS_KEEPCAPS    0x1
#define CF_SET_CAPS_INHERIT     0x2

/* The permitted and effective sets become exactly cap_list, and the inheritable set
 * cap_list or nothing */
static int cf_set_caps(kis_capture_handler_t *caph, cap_value_t *cap_list, int cl_len,
        unsigned int flags) {
    char errstr[STATUS_MAX];
    cap_t caps;

    if ((caps = cap_init()) == NULL)
        return -1;

    if ((flags & CF_SET_CAPS_KEEPCAPS) && prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1) {
        snprintf(errstr, STATUS_MAX, "datasource failed to set keepcaps in prctl: %s",
                strerror(errno));
        cf_send_warning(caph, errstr);
        cap_free(caps);
        return -1;
    }

    if (cl_len > 0) {
        cap_set_flag(caps, CAP_PERMITTED, cl_len, cap_list, CAP_SET);

        if (flags & CF_SET_CAPS_INHERIT)
            cap_set_flag(caps, CAP_INHERITABLE, cl_len, cap_list, CAP_SET);
    }

    if (cap_set_proc(caps)) {
        snprintf(errstr, STATUS_MAX, "datasource failed to set future process "
                "capabilities: %s", strerror(errno));
        cf_send_warning(caph, errstr);
        cap_free(caps);
        return -1;
    }

    if (cl_len > 0)
        cap_set_flag(caps, CAP_EFFECTIVE, cl_len, cap_list, CAP_SET);

    if (cap_set_proc(caps)) {
        snprintf(errstr, STATUS_MAX, "datasource failed to set effective capabilities: %s",
                strerror(errno));
        cf_send_warning(caph, errstr);
        cap_free(caps);
        return -1;
    }

    cap_free(caps);

    return 1;
}
#endif

int cf_drop_most_caps(kis_capture_handler_t *caph) {
    /* Modeled on the Wireshark Dumpcap priv dropping
     *
     * Restricts the capabilities of the process to only NET_ADMIN and NET_RAW and
     * strips capabilities for anything else; almost all capture sources which run as
     * root will need these, but shouldn't have free reign of the system.
     *
     */

    /* Can't drop caps unless running as root so don't try; check the effective uid so
     * a setuid-root helper, run by an ordinary user, drops them too */
    if (geteuid() != 0)
        return 0;

#ifdef HAVE_CAPABILITY
    cap_value_t cap_list[2] = { CAP_NET_ADMIN, CAP_NET_RAW };

    return cf_set_caps(caph, cap_list, 2, CF_SET_CAPS_KEEPCAPS | CF_SET_CAPS_INHERIT);
#else
    /*
    snprintf(errstr, STATUS_MAX, "datasource not compiled with libcap capabilities control");
    cf_send_warning(caph, errstr);
    */
    return 0;
#endif
}

#ifdef SYS_LINUX
/* linux/prctl.h from 4.3 */
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT              47
#endif
#ifndef PR_CAP_AMBIENT_CLEAR_ALL
#define PR_CAP_AMBIENT_CLEAR_ALL    4
#endif
#endif

#define CF_CAPS_KEEP_MAX    8

int cf_drop_caps_keep(kis_capture_handler_t *caph, const int *keep, size_t n_keep) {
#ifdef HAVE_CAPABILITY
    cap_value_t held[CF_CAPS_KEEP_MAX];
    cap_flag_value_t v;
    cap_t cur;
    int n_held = 0;
    size_t i;
#endif

    if (keep == NULL || n_keep == 0 || n_keep > CF_CAPS_KEEP_MAX)
        return -1;

    /* Lowering needs no privilege, so this runs whatever the uid.  An ambient set,
     * which an unprivileged parent can hand down, goes first; EINVAL is a kernel
     * before 4.3, which has none */
#ifdef SYS_LINUX
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) == -1 && errno != EINVAL) {
        char errstr[STATUS_MAX];

        snprintf(errstr, STATUS_MAX, "datasource failed to clear its ambient capabilities: %s",
                strerror(errno));
        cf_send_warning(caph, errstr);
        return -1;
    }
#endif

#ifdef HAVE_CAPABILITY
    /* Only what is held can be kept; asking for more fails the whole change */
    if ((cur = cap_get_proc()) == NULL)
        return -1;

    for (i = 0; i < n_keep; i++) {
        if (cap_get_flag(cur, (cap_value_t) keep[i], CAP_PERMITTED, &v) == 0 && v == CAP_SET)
            held[n_held++] = (cap_value_t) keep[i];
    }

    cap_free(cur);

    /* Keep-caps only matters to a uid change, which is the caller's to arrange, and
     * nothing kept is meant to pass to an exec'd program */
    if (cf_set_caps(caph, held, n_held, 0) < 0)
        return -1;

    return n_held > 0 ? 1 : 2;
#else
    return 0;
#endif
}

#ifdef SYS_LINUX
/* Hidden by the include order ahead of _GNU_SOURCE */
extern int unshare(int flags);

/* Kernel filesystems, device nodes, and the shared scratch and lock directories stay
 * writable; /tmp and /run stay shared with the host, so lock files still work between
 * processes.  Everything else, /etc, /usr, /var, /home and so on, is read-only. */
static const char *cf_jail_writable[] = {
    "/dev", "/proc", "/sys", "/run", "/tmp", "/var/tmp", "/var/lock", "/var/run", NULL
};

static int cf_jail_path_under(const char *path, const char *prefix) {
    size_t l = strlen(prefix);

    if (l == 1 && prefix[0] == '/')
        return 1;

    return strncmp(path, prefix, l) == 0 && (path[l] == '\0' || path[l] == '/');
}

static int cf_jail_keep(const char *path, char **kept, size_t nkept) {
    size_t i;

    for (i = 0; i < nkept; i++) {
        if (cf_jail_path_under(path, kept[i]))
            return 1;
    }

    return 0;
}

/* Mountinfo escapes space, tab, newline, and backslash as octal */
static void cf_jail_unescape(char *s) {
    char *r = s, *w = s;

    while (*r != '\0') {
        if (r[0] == '\\' && r[1] >= '0' && r[1] <= '3' && r[2] >= '0' && r[2] <= '7' &&
                r[3] >= '0' && r[3] <= '7') {
            *w++ = (char) (((r[1] - '0') << 6) | ((r[2] - '0') << 3) | (r[3] - '0'));
            r += 4;
        } else {
            *w++ = *r++;
        }
    }

    *w = '\0';
}

/* A bind remount replaces every per-mount flag, so carry over the ones already set */
static unsigned long cf_jail_mount_flags(const char *opts, int *readonly) {
    unsigned long flags = 0;
    char *dup, *tok, *save = NULL;

    *readonly = 0;

    if ((dup = strdup(opts)) == NULL)
        return 0;

    for (tok = strtok_r(dup, ",", &save); tok != NULL; tok = strtok_r(NULL, ",", &save)) {
        if (strcmp(tok, "ro") == 0)
            *readonly = 1;
        else if (strcmp(tok, "nosuid") == 0)
            flags |= MS_NOSUID;
        else if (strcmp(tok, "nodev") == 0)
            flags |= MS_NODEV;
        else if (strcmp(tok, "noexec") == 0)
            flags |= MS_NOEXEC;
        else if (strcmp(tok, "noatime") == 0)
            flags |= MS_NOATIME;
        else if (strcmp(tok, "nodiratime") == 0)
            flags |= MS_NODIRATIME;
        else if (strcmp(tok, "relatime") == 0)
            flags |= MS_RELATIME;
    }

    free(dup);
    return flags;
}
#endif

int cf_jail_filesystem(kis_capture_handler_t *caph) {
    return cf_jail_filesystem_keep(caph, NULL);
}

int cf_jail_filesystem_keep(kis_capture_handler_t *caph, const char **writable) {
#ifdef SYS_LINUX
    char errstr[STATUS_MAX];
    char *kept[32];
    size_t nkept = 0, nmounts = 0, mounts_sz = 0, i, j;
    const char **lists[2] = { cf_jail_writable, writable };
    struct cf_jail_mount { char *path; unsigned long flags; int readonly; } *mounts = NULL;
    FILE *mf;
    char *line = NULL;
    size_t linesz = 0;
    unsigned int failed = 0;
    int ret = 1;
    struct statvfs vfs;

    /* Needs CAP_SYS_ADMIN, so only root or a setuid-root helper can jail itself;
     * call before cf_drop_most_caps */
    if (geteuid() != 0)
        return 0;

    if (unshare(CLONE_NEWNS) < 0) {
        /* A container without CAP_SYS_ADMIN, or a seccomp filter, refuses new
         * namespaces; the helper runs without the jail */
        if (errno == EPERM || errno == ENOSYS) {
            snprintf(errstr, STATUS_MAX, "datasource running without a read-only "
                    "filesystem jail, unshare(CLONE_NEWNS) was denied: %s", strerror(errno));
            cf_send_warning(caph, errstr);
            return 0;
        }

        snprintf(errstr, STATUS_MAX, "datasource failed to jail to new namespace: %s",
                strerror(errno));
        cf_send_warning(caph, errstr);
        return -1;
    }

    /* Nothing done in here may reach the host's mounts */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        snprintf(errstr, STATUS_MAX, "datasource failed to make its mount namespace "
                "private: %s", strerror(errno));
        cf_send_warning(caph, errstr);
        return -1;
    }

    if ((mf = fopen("/proc/self/mountinfo", "r")) == NULL) {
        snprintf(errstr, STATUS_MAX, "datasource failed to read its mounts to jail them: %s",
                strerror(errno));
        cf_send_warning(caph, errstr);
        return -1;
    }

    while (getline(&line, &linesz, mf) > 0) {
        char *f[6];
        char *save = NULL, *tok;
        int n = 0;

        /* id parent major:minor root mountpoint options ... */
        for (tok = strtok_r(line, " ", &save); tok != NULL && n < 6;
                tok = strtok_r(NULL, " ", &save))
            f[n++] = tok;

        if (n < 6)
            continue;

        if (nmounts == mounts_sz) {
            size_t nsz = mounts_sz == 0 ? 64 : mounts_sz * 2;
            struct cf_jail_mount *nm = realloc(mounts, nsz * sizeof(*mounts));

            if (nm == NULL) {
                ret = -1;
                break;
            }

            mounts = nm;
            mounts_sz = nsz;
        }

        cf_jail_unescape(f[4]);

        if ((mounts[nmounts].path = strdup(f[4])) == NULL) {
            ret = -1;
            break;
        }

        mounts[nmounts].flags = cf_jail_mount_flags(f[5], &mounts[nmounts].readonly);
        nmounts++;
    }

    free(line);
    fclose(mf);

    if (ret < 0) {
        snprintf(errstr, STATUS_MAX, "datasource ran out of memory jailing its mounts");
        cf_send_warning(caph, errstr);
        goto out;
    }

    /* A writable directory which isn't a mount already is bound onto itself, so the
     * read-only remount of its parent leaves it alone */
    for (i = 0; i < 2; i++) {
        const char **l;

        for (l = lists[i]; l != NULL && *l != NULL; l++) {
            char *real;
            struct stat sb;
            int is_mount = 0;

            if ((real = realpath(*l, NULL)) == NULL)
                continue;

            if (stat(real, &sb) < 0 || !S_ISDIR(sb.st_mode) || cf_jail_keep(real, kept, nkept) ||
                    nkept >= sizeof(kept) / sizeof(char *)) {
                free(real);
                continue;
            }

            for (j = 0; j < nmounts && !is_mount; j++)
                is_mount = strcmp(mounts[j].path, real) == 0;

            if (!is_mount && mount(real, real, NULL, MS_BIND | MS_REC, NULL) < 0) {
                snprintf(errstr, STATUS_MAX, "datasource failed to keep %s writable in "
                        "its jail: %s", real, strerror(errno));
                cf_send_warning(caph, errstr);
                free(real);
                continue;
            }

            kept[nkept++] = real;
        }
    }

    for (i = 0; i < nmounts; i++) {
        if (mounts[i].readonly || cf_jail_keep(mounts[i].path, kept, nkept))
            continue;

        if (mount(NULL, mounts[i].path, NULL,
                    MS_BIND | MS_REMOUNT | MS_RDONLY | mounts[i].flags, NULL) < 0)
            failed++;
    }

    if (failed > 0) {
        snprintf(errstr, STATUS_MAX, "datasource could not make %u mount%s read-only in "
                "its jail", failed, failed == 1 ? "" : "s");
        cf_send_warning(caph, errstr);
    }

    if (statvfs("/", &vfs) < 0 || !(vfs.f_flag & ST_RDONLY)) {
        snprintf(errstr, STATUS_MAX, "datasource failed to remount root in jail as RO");
        cf_send_warning(caph, errstr);
        ret = -1;
    }

out:
    for (i = 0; i < nkept; i++)
        free(kept[i]);

    for (i = 0; i < nmounts; i++)
        free(mounts[i].path);

    free(mounts);

    return ret;
#else
    return 0;
#endif
}

void cf_handler_daemonize(kis_capture_handler_t *caph) {
    /* If we're going into daemon mode, fork-exec and drop out here */
    if (caph->daemonize) {
        int pid = fork();

        if (pid < 0) {
            fprintf(stderr, "FATAL:  Unable to fork child process: %s\n", strerror(errno));
            cf_handler_free(caph);
            exit(KIS_EXTERNAL_RETCODE_FORK);
        } else if (pid > 0) {
            fprintf(stderr, "INFO: Entering daemon mode...\n");
            cf_handler_free(caph);
            exit(0);
        }

        /* Once only, so cf_handler_remote_capture doesn't fork again */
        caph->daemonize = 0;
    }
}

void cf_handler_remote_capture(kis_capture_handler_t *caph) {
    pid_t monitor_pid;
    int status;

    cf_handler_daemonize(caph);

    /* Don't enter remote loop at all if we're not doing a remote connection */
    if (caph->use_ipc) {
        return;
    }

    while (1) {
        cf_handler_reset_shutdown(caph);

        monitor_pid = caph->remote_retry ? fork() : 0;

        if (monitor_pid > 0) {
            pthread_mutex_lock(&(caph->handler_lock));
            caph->monitor_pid = monitor_pid;
            pthread_mutex_unlock(&(caph->handler_lock));

            while (1) {
                /* Parent loop waiting for spaned process to exit, then restart */
                pid_t wpid;
                wpid = waitpid(monitor_pid, &status, 0);

                if (wpid < 0 && errno == EINTR)
                    continue;

                /* Already reaped (SIGCHLD ignored behind our back); spinning on
                 * ECHILD would never end */
                if (wpid < 0) {
                    fprintf(stderr, "INFO: lost track of capture process: %s\n",
                            strerror(errno));
                    break;
                }

                if (wpid == monitor_pid) {
                    if (WIFEXITED(status) || WIFSIGNALED(status)) {
                        fprintf(stderr, "INFO: capture process exited %d signal %d\n",
                                WEXITSTATUS(status), WTERMSIG(status));
                        break;
                    }
                }
            }

            /* Reaped, so its pid can be reused: shutdown must not signal it */
            pthread_mutex_lock(&(caph->handler_lock));
            caph->monitor_pid = 0;
            pthread_mutex_unlock(&(caph->handler_lock));
        } else {
            if (caph->use_tcp) {
                if (cf_handler_tcp_remote_connect(caph) < 1) {
                    exit(KIS_EXTERNAL_RETCODE_TCP);
                }
            } else {
#ifdef HAVE_LIBWEBSOCKETS
                /* Prepare the libwebsockets ssl and context, but let the main connection callback
                 * via the main lws_service loop */

                memset(&caph->lwsinfo, 0, sizeof(struct lws_context_creation_info));

                caph->lwsinfo.user = caph;

                if (caph->lwsusessl)
                    caph->lwsinfo.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

                if (caph->lwssslcapath != NULL)
                    caph->lwsinfo.client_ssl_ca_filepath = caph->lwssslcapath;

                caph->lwsinfo.port = CONTEXT_PORT_NO_LISTEN;
                caph->lwsinfo.protocols = kismet_lws_protocols;

                /* Should only need to be 2 but lets be safe for now */
                caph->lwsinfo.fd_limit_per_thread = 10;

                caph->lwscontext = lws_create_context(&caph->lwsinfo);
                if (!caph->lwscontext) {
                    fprintf(stderr, "FATAL:  Could not create websockets context\n");
                    exit(KIS_EXTERNAL_RETCODE_WEBSOCKET);
                }

#else
                fprintf(stderr, "FATAL:  Not compiled with websocket support\n");
                exit(KIS_EXTERNAL_RETCODE_WSCOMPILE);
#endif
            }

            /* Exit so main loop continues */
            return;
        }

        /* Don't keep going if we're not retrying */
        if (caph->remote_retry == 0) {
            exit(1);
        }

        fprintf(stderr, "INFO: Sleeping 5 seconds before attempting to reconnect to "
                "remote server\n");
        sleep(5);

    }
}

void cf_set_verbose(kis_capture_handler_t *caph, int verbosity) {
    caph->verbose = verbosity;
}

int cf_wait_announcement(kis_capture_handler_t *caph) {
    struct sockaddr_in lsin;
    int sock;

	ssize_t r;
	struct msghdr rcv_msg;
	struct iovec iov;
	kismet_remote_announce announcement;
	struct sockaddr_in recv_addr;

    char *name;

    if (caph->remote_host != NULL) {
        free(caph->remote_host);
        caph->remote_host = NULL;
    }

    caph->remote_port = 0;

    memset(&lsin, 0, sizeof(struct sockaddr_in));
    lsin.sin_family = AF_INET;
    lsin.sin_port = htons(2501);
    lsin.sin_addr.s_addr = INADDR_ANY;

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        fprintf(stderr, "ERROR:  Could not create listening socket for announcements: %s\n",
                strerror(errno));
		return -1;
    }

    if (bind(sock, (struct sockaddr *) &lsin, sizeof(lsin)) < 0) {
        fprintf(stderr, "ERROR:  Could not bind to listening socket for announcements: %s\n",
                strerror(errno));
        close(sock);
		return -1;
    }

    fprintf(stderr, "INFO: Listening for Kismet server announcements...\n");

    while(1) {
        iov.iov_base = &announcement;
        iov.iov_len = sizeof(kismet_remote_announce);

        rcv_msg.msg_name = &recv_addr;
        rcv_msg.msg_namelen = sizeof(recv_addr);
        rcv_msg.msg_iov = &iov;
        rcv_msg.msg_iovlen = 1;
        rcv_msg.msg_control = NULL;
        rcv_msg.msg_controllen = 0;

        if ((r = recvmsg(sock, &rcv_msg, 0) < 0)) {
            fprintf(stderr, "ERROR:  Failed receiving announcement: %s\n", strerror(errno));
            close(sock);
			return -1;
        }

        if (r < sizeof(kismet_remote_announce)) {
            fprintf(stderr, "ERROR:  Received short announcement, ignoring.\n");
            continue;
        }

        if (be64toh(announcement.tag) != REMOTE_ANNOUNCE_TAG) {
            fprintf(stderr, "WARNING:  Corrupt/invalid announcement seen, ignoring.\n");
            continue;
        }

        if (caph->announced_uuid != NULL)
            if (strncmp(caph->announced_uuid, announcement.uuid, 36) != 0)
                continue;

        caph->remote_host = strdup(inet_ntoa(recv_addr.sin_addr));
        caph->remote_port = ntohl(announcement.remote_port);

        name = strndup(announcement.name, 32);

        fprintf(stderr, "INFO:  Detected Kismet server %s:%u %.36s (%s)\n",
                caph->remote_host, caph->remote_port,
                announcement.uuid, strlen(name) > 0 ? name : "no name");

        free(name);

        close(sock);

        return 1;
    }

}

/* access() checks the real uid, which is who cf_ipc_exec runs the tool as */
static int cf_ipc_is_exec(const char *path) {
    struct stat sb;

    if (stat(path, &sb) != 0 || !S_ISREG(sb.st_mode))
        return 0;

    return access(path, X_OK) == 0;
}

int cf_ipc_find_exec(kis_capture_handler_t *caph, char *program) {
    const char *envpath = getenv("PATH");
    char *path, *orig, *token;
    char binpath[512];
    int found = 0;

    if (strchr(program, '/') != NULL)
        return cf_ipc_is_exec(program);

    if (envpath == NULL)
        return 0;

    if ((path = strdup(envpath)) == NULL)
        return 0;

    orig = path;

    while ((token = strsep(&path, ":")) != NULL) {
        if (snprintf(binpath, sizeof(binpath), "%s/%s",
                    strlen(token) ? token : ".", program) >= (int) sizeof(binpath))
            continue;

        if (cf_ipc_is_exec(binpath)) {
            found = 1;
            break;
        }
    }

    free(orig);

    return found;
}

#ifdef SYS_LINUX
/* Hidden by the include order ahead of _GNU_SOURCE */
extern int setresuid(uid_t ruid, uid_t euid, uid_t suid);
extern int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
#endif

/* Drops a setuid/setgid helper back to the user who ran it, for a forked child, before it
 * runs a tool found in that user's PATH.  The saved ids are reset too, so the tool can't
 * regain root; this needs no capabilities, since each id is set to one it already holds. */
static int cf_ipc_drop_to_real_ids(void) {
    uid_t uid = getuid();
    gid_t gid = getgid();

    if (uid == geteuid() && gid == getegid())
        return 0;

#if defined(SYS_LINUX) || defined(SYS_FREEBSD) || defined(SYS_OPENBSD)
    if (setresgid(gid, gid, gid) < 0 || setresuid(uid, uid, uid) < 0)
        return -1;
#else
    if (setgid(gid) < 0 || setuid(uid) < 0)
        return -1;
#endif

    if (geteuid() != uid || getegid() != gid)
        return -1;

    /* Must not be able to get back */
    if (uid != 0 && setuid(0) == 0)
        return -1;

    return 0;
}

/* Closes every descriptor from lowfd up; only async-signal-safe calls, for a forked child */
static void cf_close_fds_from(int lowfd) {
    long maxfd;

#if defined(SYS_LINUX) && defined(SYS_close_range)
    if (syscall(SYS_close_range, (unsigned int) lowfd, ~0U, 0) == 0)
        return;
#endif

    maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > INT_MAX)
        maxfd = 65536;

    for (int fd = lowfd; fd < maxfd; fd++)
        close(fd);
}

cf_ipc_t *cf_ipc_exec(kis_capture_handler_t *caph, int argc, char **argv) {
    cf_ipc_t *ret = NULL;
    pthread_mutexattr_t mutexattr;
    pid_t child_pid;
#ifdef SYS_LINUX
    pid_t parent_pid = getpid();
#endif

    int inpair[2];
    int outpair[2];
    int errpair[2];

    if (pipe(inpair) < 0) {
        return NULL;
    }

    if (pipe(outpair) < 0) {
        close(inpair[0]);
        close(inpair[1]);
        return NULL;
    }

    if (pipe(errpair) < 0) {
        close(inpair[0]);
        close(inpair[1]);
        close(outpair[0]);
        close(outpair[1]);
        return NULL;
    }

    child_pid = fork();

    if (child_pid < 0) {
        fprintf(stderr, "FATAL: Failed to fork IPC process\n");
        close(inpair[0]);
        close(inpair[1]);
        close(outpair[0]);
        close(outpair[1]);
        close(errpair[0]);
        close(errpair[1]);
        return NULL;
    } else if (child_pid == 0) {
        sigset_t unblock_mask;
        sigfillset(&unblock_mask);
        pthread_sigmask(SIG_UNBLOCK, &unblock_mask, NULL);

        dup2(inpair[0], STDIN_FILENO);
        close(inpair[0]);
        close(inpair[1]);

        dup2(outpair[1], STDOUT_FILENO);
        close(outpair[1]);
        close(outpair[0]);

        dup2(errpair[1], STDERR_FILENO);
        close(errpair[1]);
        close(errpair[0]);

        /* The tool gets only its stdio, not the server connection, the radio, or the
         * descriptors the server leaked to us, and goes away with us */
        cf_close_fds_from(STDERR_FILENO + 1);

#ifdef SYS_LINUX
        if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0 || getppid() != parent_pid)
            _exit(255);
#endif

        if (cf_ipc_drop_to_real_ids() < 0)
            _exit(255);

        execvp(argv[0], argv);

        _exit(255);
    } else {
        close(inpair[0]);
        close(errpair[1]);
        close(outpair[1]);

        ret = (cf_ipc_t *) malloc(sizeof(cf_ipc_t));
        memset(ret, 0, sizeof(cf_ipc_t));

        ret->running = 1;

        ret->in_fd = inpair[1];
        ret->out_fd = outpair[0];
        ret->err_fd = errpair[0];

        ret->pid = child_pid;

        fcntl(ret->in_fd, F_SETFL, fcntl(ret->in_fd, F_GETFL, 0) | O_NONBLOCK);
        fcntl(ret->out_fd, F_SETFL, fcntl(ret->out_fd, F_GETFL, 0) | O_NONBLOCK);
        fcntl(ret->err_fd, F_SETFL, fcntl(ret->err_fd, F_GETFL, 0) | O_NONBLOCK);

        pthread_mutexattr_init(&mutexattr);
        pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&(ret->out_ringbuf_lock), &mutexattr);

        /* Ungracefully die if we're out of memory */
        ret->in_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_IN_SZ);
        if (ret->in_ringbuf == NULL) {
            fprintf(stderr, "FATAL:  Cannot allocate process ringbuffer (in)\n");
            exit(1);
        }

        /* Ungracefully die if we're out of memory */
        ret->out_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_OUT_SZ);
        if (ret->out_ringbuf == NULL) {
            fprintf(stderr, "FATAL:  Cannot allocate process ringbuffer (out)\n");
            exit(1);
        }

        /* Ungracefully die if we're out of memory */
        ret->err_ringbuf = kis_simple_ringbuf_create(CAP_FRAMEWORK_RINGBUF_OUT_SZ);
        if (ret->err_ringbuf == NULL) {
            fprintf(stderr, "FATAL:  Cannot allocate process ringbuffer (err)\n");
            exit(1);
        }

        return ret;
    }
}

void cf_ipc_free(kis_capture_handler_t *caph, cf_ipc_t *ipc) {
    kis_simple_ringbuf_free(ipc->in_ringbuf);

    pthread_mutex_lock(&ipc->out_ringbuf_lock);
    kis_simple_ringbuf_free(ipc->out_ringbuf);
    kis_simple_ringbuf_free(ipc->err_ringbuf);
    pthread_mutex_unlock(&ipc->out_ringbuf_lock);

    pthread_mutex_destroy(&ipc->out_ringbuf_lock);

    if (ipc->in_fd >= 0)
        close(ipc->in_fd);
    if (ipc->out_fd >= 0)
        close(ipc->out_fd);
    if (ipc->err_fd >= 0)
        close(ipc->err_fd);

    free(ipc);
}

void cf_ipc_signal(kis_capture_handler_t *caph, cf_ipc_t *ipc, int signal) {
    kill(ipc->pid, signal);
}

void cf_ipc_set_rx(kis_capture_handler_t *caph, cf_ipc_t *ipc, cf_callback_ipc_data cb) {
    ipc->rx_callback = cb;
}

void cf_ipc_set_err_rx(kis_capture_handler_t *caph, cf_ipc_t *ipc, cf_callback_ipc_data cb) {
    ipc->err_callback = cb;
}

void cf_ipc_set_term(kis_capture_handler_t *caph, cf_ipc_t *ipc, cf_callback_ipc_term cb) {
    ipc->term_callback = cb;
}

/* The list changes under both locks, handler_lock first, as the reaper does */
void cf_ipc_add_process(kis_capture_handler_t *caph, cf_ipc_t *ipc) {
    pthread_mutex_lock(&(caph->handler_lock));
    pthread_mutex_lock(&(caph->out_ringbuf_lock));

    cf_ipc_t *first = caph->ipc_list;

    ipc->next = first;
    caph->ipc_list = ipc;

    /* Shutdown already took the list: nothing will service this child, so end it
     * now; cf_handler_free frees what is left on the list */
    if (caph->shutdown)
        cf_ipc_signal(caph, ipc, SIGKILL);

    pthread_mutex_unlock(&(caph->out_ringbuf_lock));
    pthread_mutex_unlock(&(caph->handler_lock));
}

void cf_ipc_remove_process(kis_capture_handler_t *caph, cf_ipc_t *ipc) {
    pthread_mutex_lock(&(caph->handler_lock));
    pthread_mutex_lock(&(caph->out_ringbuf_lock));

    cf_ipc_t *current = caph->ipc_list;
    cf_ipc_t *prev = NULL;
    int matched = 0;

    while (current != NULL) {
        if (current->pid == ipc->pid) {
            matched = 1;
            break;
        }

        prev = current;
        current = current->next;
    }

    if (matched) {
        if (prev == NULL) {
            caph->ipc_list = current->next;
        } else {
            prev->next = current->next;
        }
    }

    pthread_mutex_unlock(&(caph->out_ringbuf_lock));
    pthread_mutex_unlock(&(caph->handler_lock));
}

/* sanitize_extra_space and sanitize_string taken from nlohmann's jsonhpp library,
 * Copyright 2013-2015 Niels Lohmann. and under the MIT license */
size_t json_sanitize_extra_space(const char *s) {
    size_t result = 0;
    size_t i;

    if (s == NULL) {
        return 0;
    }

    for (i = 0; i < strlen(s); i++) {
        switch (s[i]) {
            case '"':
            case '\\':
            case '\b':
            case '\f':
            case '\n':
            case '\r':
            case '\t':
                {
                    /* from c (1 byte) to \x (2 bytes) */
                    result += 1;
                    break;
                }

            default:
                {
                    if (s[i] >= 0x00 && s[i] <= 0x1f)
                    {
                        /* from c (1 byte) to \uxxxx (6 bytes) */
                        result += 5;
                    }
                    break;
                }
        }
    }

    return result;
}

/* caller must free this string, if it isn't equal to the original
 * pointer. */
char *json_sanitize_string(char *s) {
    if (s == NULL) {
        return NULL;
    }

    size_t space = json_sanitize_extra_space(s);
    char *result = NULL;
    size_t pos, i;

    if (space == 0) {
        return s;
    }

    result = malloc(sizeof(char) * strlen(s) + space + 1);

    if (result == NULL) {
        return NULL;
    }

    pos = 0;

    for (i = 0; i < strlen(s); i++) {
        char c = s[i];

        switch (c) {
            /* quotation mark (0x22) */
            case '"':
                {
                    result[pos] = '\\';
                    result[pos + 1] = '"';
                    pos += 2;
                    break;
                }

                /* reverse solidus (0x5c) */
            case '\\':
                {
                    result[pos] = '\\';
                    result[pos + 1] = '\\';
                    pos += 2;
                    break;
                }

                /* backspace (0x08) */
            case '\b':
                {
                    result[pos] = '\\';
                    result[pos + 1] = 'b';
                    pos += 2;
                    break;
                }

                /* formfeed (0x0c) */
            case '\f':
                {
                    result[pos] = '\\';
                    result[pos + 1] = 'f';
                    pos += 2;
                    break;
                }

                /* newline (0x0a) */
            case '\n':
                {
                    result[pos] = '\\';
                    result[pos + 1] = 'n';
                    pos += 2;
                    break;
                }

                /* carriage return (0x0d) */
            case '\r':
                {
                    result[pos] = '\\';
                    result[pos + 1] = 'r';
                    pos += 2;
                    break;
                }

                /* horizontal tab (0x09) */
            case '\t':
                {
                    result[pos] = '\\';
                    result[pos + 1] = 't';
                    pos += 2;
                    break;
                }

            default:
                {
                    if (c >= 0x00 && c <= 0x1f)
                    {
                        /* print character c as \uxxxx */
                        result[pos] = '\\';
                        snprintf(&result[pos + 1], 6, "u%04x", (int) c);
                        pos += 6;
                    }
                    else
                    {
                        // all other characters are added as-is
                        result[pos++] = c;
                    }
                    break;
                }
        }
    }

    result[strlen(s) + space] = 0;

    return result;
}

