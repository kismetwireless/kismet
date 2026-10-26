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

/* kismetdb_to_qmilog -- reconstruct the QMI feed's `--qmilog` JSONL from a
 * drive's type="RawQMI" `data` rows.
 *
 * The feed (capture_cell_at/qmifeed/kismet_qmi_feed.py) builds each qmicli record ONCE
 * and hands the same dict to both sinks -- the --qmilog file line and the
 * `#rawqmi` line this tree stores verbatim as the row's json -- so the stored blob IS
 * the file line, minus its newline. Ordering, --source, the read-only open and
 * the unparseable-blob handling are kismetdb_to_atlog's, included below: see
 * that file's header. Unlike atlog=, the in-band lane and the file tee start
 * together (the feed holds pre-open records for the file), so for one source
 * the output should EQUAL that source's --qmilog file, not just contain it.
 */

#define RAWLOG_TYPE "RawQMI"
#define RAWLOG_NAME "qmilog"
#define RAWLOG_HELP \
    "Kismetdb to --qmilog JSONL\n" \
    "Reconstruct the QMI feed's raw log (one record per qmicli call,\n" \
    "argv/rc/stdout/stderr/host-monotonic instants, plus qmux frames in wire\n" \
    "mode) from a KismetDB log's type=\"RawQMI\" `data` rows, one JSON record\n" \
    "per line, sorted by the record's ts_mono_ns (capture order).\n" \
    "\n" \
    "A --qmilog file is per feed (= per cellat datasource); pass --source <uuid>\n" \
    "to reconstruct one modem's log exactly.\n"

#include "kismetdb_to_atlog.cc"
