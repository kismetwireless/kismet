/* diag_rawlog.h - raw DIAG byte-stream tee sink for the celldiag source.
 *
 * The write-side mirror of the `replay=<file>` read hook: `rawlog=<path>` tees
 * the raw HDLC DIAG byte stream to disk *while* it is still being decoded, so a
 * run can be captured and later fed straight back through `replay=`. The tee
 * sits at the single DIAG-read -> helper-write seam in capture_cell_diag.c, so
 * the file holds exactly the bytes the decoder saw (round-trip faithful).
 *
 * The file is written UNCOMPRESSED live (raw HDLC, .hdlc); compress it to
 * .zst afterwards if wanted. Do not zstd inline.
 *
 * The path templating and the whole-buffer write are libc-only (no Kismet
 * dependency) so they are unit-tested standalone in test_diag_rawlog.c
 * (`make check` in this directory).
 */
#ifndef DIAG_RAWLOG_H
#define DIAG_RAWLOG_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* Resolve a rawlog= spec into a concrete file path.
 *
 * Token expansion anywhere in the spec:
 *   %i -> IMEI
 *   %m -> model, sanitized to [A-Za-z0-9._-] (other bytes become '_')
 *   %t -> capture start time as UTC "YYYYmmddTHHMMSSZ"
 *   %% -> a literal '%'
 *
 * If the (token-expanded) spec names an existing directory, or the spec ends
 * in '/', a filename "celldiag-<imei>-<ts>.hdlc" is synthesized inside it so
 * concurrent per-modem sources on one host never collide.
 *
 * Writes a NUL-terminated result to `out`. Returns 0 on success, -1 if the
 * result would not fit in `outsz` (out left untouched on overflow).
 */
int diag_rawlog_resolve(const char *spec, const char *imei, const char *model,
                        time_t now, char *out, size_t outsz);

/* Open the tee for ONE capture session, never destroying bytes an earlier
 * session wrote.
 *
 * A source reopen (a restart-to-apply toggle, the whole-modem switch, Kismet's
 * automatic error reopen) is a new helper process. If a fixed rawlog= path
 * were O_TRUNC'd on every open, the tee on disk would hold only the LAST
 * session while the kismetdb held all of them, and nothing would say so.
 *
 *   - `path` absent, empty, or not a regular file (/dev/null, a FIFO):
 *     opened as given.
 *   - `path` a non-empty regular file: the session is diverted to a sibling
 *     "<stem>-<UTC YYYYmmddTHHMMSSZ><ext>", then "<stem>-<ts>-2<ext>", ...
 *     created O_EXCL, so two sessions can never share (or clobber) one file.
 *
 * The chosen path is written to `out`; *diverted (if non-NULL) is set to 1
 * when it is not `path`. Returns the open fd, or -1 with errno set (ENAMETOOLONG
 * when the result does not fit in `outsz`). The fd is O_WRONLY | O_APPEND. */
int diag_rawlog_open_session(const char *path, time_t now, char *out,
                             size_t outsz, int *diverted);

/* Write the whole buffer to fd, retrying short writes. Returns 0 on success,
 * -1 on error (errno set) - e.g. a full disk or a vanished path. */
int diag_rawlog_write(int fd, const uint8_t *buf, size_t len);

#endif /* DIAG_RAWLOG_H */
