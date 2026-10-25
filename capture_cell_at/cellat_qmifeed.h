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

    cellat QMI feed: the `qmifeed=<command>` source option.

    WHAT IT IS. QMI carries cell data AT cannot: the NR Cell Identity Telit's
    AT#RFSTS drops, and full cell identity on Sierra parts whose
    AT+CEREG / AT+CSQ return ERROR. qmifeed/kismet_qmi_feed.py, which
    ships in this directory (`qmifeed=auto` runs it), polls qmicli and writes one cell_observation JSON per stdout line, already in
    build_cell_json()'s shape with a {"src":"qmi",...} prov block. This unit
    spawns that command as a child of kismet_cap_cell_at and hands each complete
    line back to the capture loop, which forwards it as a `CellModem` record --
    the same record type the AT observations ride -- so phy_cell merges QMI, AT
    and DIAG sightings of one tower through prov.src with no server change.

    WHY A CHILD OF THE CAPTURE BINARY, not a datasource of its own. The Kismet
    server never reads NDJSON: a capture source speaks KDS over its IPC pipe.
    The capture child is the adapter, so the feed inherits cellat's source
    identity, its ModemIdentity record and its kismetdb rows for free.

    FD HYGIENE. The capture child's KDS IPC fds are NOT close-on-exec. A
    grandchild that inherited them would hold the server's pipe open after the
    capture child died, and the server -- which learns of a dead source from
    EOF -- would keep a zombie source forever. qmifeed_start() closes every fd
    >= 3 in the child before exec.

    STOPPING, IN LAYERS (because no single mechanism reaches every case):
      1. Kismet's own stop is a CLOSEREQ: the capture loop ends,
         teardown runs, and qmifeed_stop() kills the child's whole process
         group -- sh, python and any qmicli in flight.
      2. A capture child killed outright runs no teardown. PR_SET_PDEATHSIG
         then signals the DIRECT child only (it is not transitive).
      3. Everything deeper must notice for itself: a writer dies of SIGPIPE at
         its next line, and kismet_qmi_feed.py -- which may write nothing for
         a long time when no cell is in range -- also exits once its parent
         pid changes.
    The server's own reaper (capture_framework.c, waitpid(-1)) may collect
    the child before qmifeed_stop() does, so its exit status can be unknown.

    WHOSE CELLS THESE ARE. The feed stamps prov.imei with the
    IMEI its QMI device reports, not the one this source verified on its AT
    port, and cdc-wdm numbering on a multi-modem host is not stable. So:
      B. qmifeed_start() exports CELLAT_IMEI=<verified IMEI> to the child;
         kismet_qmi_feed.py picks the cdc-wdm whose DMS IMEI matches, or
         refuses to start.
      A. Every line is checked anyway (qmifeed_imei_check): a line stamped
         with another IMEI, or with none, is dropped, never relayed under
         this source. B prevents the mis-route; A is the backstop for any
         feed that does not honour B.

    A SECOND LINE TYPE. Besides `{...}` observations, qmifeed_start()
    exports CELLAT_QMIFEED_PROTO=2,
    and a feed that sees it may also write TAGGED lines:
        #rawqmi {json}          one raw qmicli exchange -> a `RawQMI` data row
        #msg info|error <text>  an operator note -> the Kismet message bus
    A feed that does not know the protocol never writes them, and a capture
    binary without a tag callback counts them as non-JSON, so either side can
    be older than the other. A raw record carries qmicli's text (and, with
    --qmilog-wire, the QMUX frames): ~10 KB, so lines may run to
    QMIFEED_RAW_MAX, while an observation line keeps the 4 KiB cap.

    Like clockanchor.c and cellat_options.c this is a libc-only translation unit
    (no Kismet, no serial), so the spawn / line framing / teardown are tested
    standalone in test_cellat_qmifeed.c (`make check` in this directory).
*/

#ifndef __CELLAT_QMIFEED_H__
#define __CELLAT_QMIFEED_H__

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One observation line, NUL included. Matches capture_cell_at's JSON_BUF_MAX:
 * a line that would not fit an AT observation's buffer is not forwarded. */
#define QMIFEED_LINE_MAX 4096

/* Any line, tagged ones included: the read buffer's size. */
#define QMIFEED_RAW_MAX 65536

/* The largest JSON payload any cellat `data` row (RawQMI, RawAT) may carry
 * This, not QMIFEED_RAW_MAX, is the real limit: Kismet refuses any
 * IPC frame over MAX_EXTERNAL_FRAME_LEN (16384, kis_external.h), and refuses it
 * by erroring the whole SOURCE -- which it reopens 5 s later into the same row.
 * The frame also carries the v3 header, the msgpack map, the type string and
 * any fixed-GPS block, so 4 KiB is left for those, the same budget the DIAG
 * raw slices keep (DIAG_RAWPKT_PAYLOAD_MAX). A longer row is a counted drop.
 * celltools/tests/test_cellat_rawqmi_frame_limit.py pins it against
 * kis_external.h. */
#define CELLAT_ROW_JSON_MAX 12288

/* Exported to the feed, so it trims a raw record to what this reader will
 * forward instead of copying the number. */
#define QMIFEED_RAWQMI_MAX_ENV "CELLAT_QMIFEED_RAWQMI_MAX"

/* The line protocol this binary speaks, exported as CELLAT_QMIFEED_PROTO. */
#define QMIFEED_PROTO 2
#define QMIFEED_PROTO_ENV "CELLAT_QMIFEED_PROTO"

typedef enum {
    QMIFEED_TAG_RAWQMI = 0,  /* payload: one JSON object */
    QMIFEED_TAG_MSG_INFO,    /* payload: text */
    QMIFEED_TAG_MSG_ERROR,   /* payload: text */
} qmifeed_tag_t;

/* Deliver one tagged line's payload (NUL-terminated, tag stripped). */
typedef void (*qmifeed_tag_cb)(qmifeed_tag_t tag, const char *payload, void *ctx);

typedef struct {
    pid_t    pid;            /* child (and process-group leader); -1 = none */
    int      fd;             /* O_NONBLOCK read end of the child's stdout; -1 = closed */
    char     buf[QMIFEED_RAW_MAX];
    size_t   len;            /* bytes of the current, not-yet-terminated line */
    int      discarding;     /* inside an overlong line: drop to the next '\n' */
    int      eof;            /* the child closed its stdout */
    uint64_t lines;          /* complete JSON lines delivered */
    uint64_t dropped_overlong;
    uint64_t dropped_nonjson;
    qmifeed_tag_cb tag_cb;   /* NULL = tagged lines count as non-JSON */
    uint64_t tagged;         /* tagged lines delivered to tag_cb */
    uint64_t dropped_badtag; /* '#' lines with an unknown tag or bad payload */
    char     expect_imei[32]; /* exported as CELLAT_IMEI; "" = none */
} qmifeed_t;

/* Deliver one complete observation line (NUL-terminated, no newline). */
typedef void (*qmifeed_line_cb)(const char *line, void *ctx);

void qmifeed_init(qmifeed_t *qf);

/* Route tagged lines to `cb` (called with qmifeed_poll's ctx). Without it a
 * tagged line is counted in dropped_nonjson. */
void qmifeed_set_tag_cb(qmifeed_t *qf, qmifeed_tag_cb cb);

/* Spawn `/bin/sh -c cmd` with stdout on a pipe, stdin on /dev/null and stderr
 * inherited (it lands in the Kismet log beside the capture child's own).
 * Returns 0, or -1 with an operator-facing reason in `err`. */
int qmifeed_start(qmifeed_t *qf, const char *cmd, char *err, size_t errsz);

/* Drain whatever the child has written, without blocking, calling `cb` once per
 * complete line that looks like a JSON object ({...}) and fits
 * QMIFEED_LINE_MAX, and the tag callback once per well-formed tagged line. A
 * trailing partial line is held for the next call. Returns the number of
 * observation lines delivered (tagged lines are counted in qf->tagged).
 *
 * End-of-stream sets qf->eof and closes qf->fd; check qf->eof, not the return
 * value. A feed's last lines and its EOF routinely arrive in one read, so the
 * call that sees the EOF may also deliver lines; a "-1 on EOF" return could not
 * report both. */
int qmifeed_poll(qmifeed_t *qf, qmifeed_line_cb cb, void *ctx);

/* SIGTERM the child's process group, give it up to `grace_ms` to exit, then
 * SIGKILL; always reaps. Returns the child's wait status (as from waitpid), or
 * -1 if there was no child. Safe to call twice. */
int qmifeed_stop(qmifeed_t *qf, int grace_ms);

/* Option B: the IMEI this source verified on its AT port. The
 * next qmifeed_start() exports it to the child as CELLAT_IMEI, replacing any
 * inherited value. NULL, "" or the all-zeros unknown-IMEI sentinel exports
 * nothing (and removes an inherited CELLAT_IMEI): an unverified identity is
 * never handed on as if it were one. */
void qmifeed_set_expect_imei(qmifeed_t *qf, const char *imei);

/* Option A: the prov.imei string of one observation line.
 * Returns 1 and copies it to `out` (possibly ""), 0 if the line has no
 * prov object or no prov.imei, -1 if prov / prov.imei is not the expected
 * JSON type, a string is unterminated, or the value does not fit `out`.
 * Keys are matched byte-for-byte (a \u-escaped key is not recognised). */
int qmifeed_line_imei(const char *line, char *out, size_t outsz);

typedef enum {
    QMIFEED_IMEI_MATCH = 0,  /* prov.imei == the source's: relay */
    QMIFEED_IMEI_MISMATCH,   /* another modem's cells: drop */
    QMIFEED_IMEI_UNSTAMPED,  /* no (or malformed) prov.imei: drop -- no one checked it */
    QMIFEED_IMEI_UNCHECKED,  /* the source has no verified IMEI: relay, and say so */
} qmifeed_imei_verdict_t;

/* Judge one line against the source's verified IMEI. `got` receives the
 * line's prov.imei when there is one (for the operator message). */
qmifeed_imei_verdict_t qmifeed_imei_check(const char *line, const char *source_imei,
                                          char *got, size_t gotsz);

/* `qmifeed=auto` -- the feed that ships in this tree.
 *
 * The feed is capture_cell_at/qmifeed/kismet_qmi_feed.py: standard library only,
 * needing qmicli on $PATH and nothing else. `auto` (or `1`) finds it beside the
 * binary -- `<dir>/qmifeed/` or `<dir>/capture_cell_at/qmifeed/`, at the binary's
 * directory or up to QMIFEED_AUTO_MAX_UP parents -- and runs it with the system
 * python3.
 * Anything after `auto ` is passed on as the feed's own arguments:
 *   qmifeed=auto                    autodetect the device, 5 s cadence
 *   qmifeed=auto -d /dev/cdc-wdm0 --interval 2
 * Any other value is a command, used verbatim.
 *
 * Fills `out` with the command for qmifeed_start(). Returns 0, or -1 with the
 * reason in `err` when `auto` finds no feed (or `self_dir` is NULL) or the
 * command does not fit. `self_dir` is qmifeed_exe_dir() in the helper; tests
 * pass a directory of their own. */
#define QMIFEED_AUTO_SCRIPT "qmifeed/kismet_qmi_feed.py"
#define QMIFEED_AUTO_MAX_UP 3
int qmifeed_resolve_command(const char *value, const char *self_dir,
                            char *out, size_t outsz, char *err, size_t errsz);

/* Where `make install` puts the feed -- `<datadir>/kismet/cell`, holding
 * qmifeed/. An installed binary sits in $(BINDIR) with no qmifeed/ beside it,
 * so the walk above finds nothing there; this is the last candidate `auto`
 * tries. Compiled in by the autoconf build; "" (no candidate) otherwise, so a
 * standalone or copied binary relies on the walk alone. */
#ifndef QMIFEED_DATADIR
#define QMIFEED_DATADIR ""
#endif

/* qmifeed_resolve_command() with the data directory named rather than compiled
 * in: `data_dir` (NULL or "" for none) is tried after the walk finds nothing.
 * qmifeed_resolve_command() is this with QMIFEED_DATADIR. */
int qmifeed_resolve_command_in(const char *value, const char *self_dir,
                               const char *data_dir,
                               char *out, size_t outsz, char *err, size_t errsz);

/* The directory this binary runs from (canonical, symlinks resolved), or NULL
 * when the platform cannot say. */
const char *qmifeed_exe_dir(void);

#ifdef __cplusplus
}
#endif

#endif
