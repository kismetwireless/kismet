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

/* capture_pcapfile
 *
 * Basic capture binary, written in pure C, which interfaces via the Kismet
 * simple capture protocol and feeds packets from a pcap file.
 *
 * This could have been implemented in C++ but serves as an example of a simple,
 * very low resource capture method.
 *
 * This uses some of the pure-C code included in Kismet - pure-c implementations
 * of the datasource protocol, a basic ringbuffer implementation, and the msgpuck
 * library which is a pure-c simple msgpack library.
 *
 * This uses basic threading to show how to do an asynchronous read from a source;
 * while a pcapfile will never stall, other sources could.  
 *
 * The select() loop for IO with the IPC channel is performed in the primary
 * thread, and an IO thread is spawned to process data from the pcap file.  This
 * allows us to expand to interesting options, like realtime pcap replay which
 * delays the IO as if they were real packets.
 *
 * The DLT is automatically propagated from the pcap file, or can be overridden
 * with a source command.
 *
 * The communications channel is a file descriptor pair, passed via command
 * line arguments, --in-fd= and --out-fd=
 *
 * We parse additional options from the source definition itself, such as a DLT
 * override, once we open the protocol
 *
 */

#include <pcap.h>
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
#include "capture_framework.h"

/* Pcap file */
pcap_t *pd;
/* Pcap DLT */
int datalink_type;
/* Overridden DLT */
int override_dlt;

int main(int argc, char *argv[]) {
    FILE *sterr;

    sterr = fopen("capture_pcapfile.stderr", "a");
    dup2(fileno(sterr), STDERR_FILENO);

    fprintf(stderr, "CAPTURE_PCAPFILE launched on pid %d\n", getpid());

    kis_capture_handler_t *caph = cf_handler_init();

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    if (cf_handler_parse_opts(caph, argc, argv) < 1) {
        fprintf(stderr, "FATAL: Missing command line parameters.\n");
        return -1;
    }

    cf_handler_loop(caph);

    fprintf(stderr, "FATAL: Exited main select() loop\n");

    cf_handler_free(caph);

    return 1;
}

