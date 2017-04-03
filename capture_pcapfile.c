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
#include <sys/stat.h>

#include <unistd.h>
#include <errno.h>

#include <arpa/inet.h>

#include "simple_datasource_proto.h"
#include "capture_framework.h"

typedef struct {
    pcap_t *pd;
    char *pcapfname;
    int datalink_type;
    int override_dlt;
} local_pcap_t;

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition) {

    char *placeholder = NULL;
    int placeholder_len;

    char *pcapfname = NULL;

    struct stat sbuf;

    local_pcap_t *local_pcap = (local_pcap_t *) caph->userdata;

    char errstr[PCAP_ERRBUF_SIZE] = "";

    /* Clean up any old state */
    if (local_pcap->pcapfname != NULL) {
        free(local_pcap->pcapfname);
        local_pcap->pcapfname = NULL;
    }

    if (local_pcap->pd != NULL) {
        pcap_close(local_pcap->pd);
        local_pcap->pd = NULL;
    }

    fprintf(stderr, "debug - pcapfile - trying to open source %s\n", definition);

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        cf_send_openresp(caph, seqno, false, 
                "Unable to find PCAP file name in definition",
                NULL, 0,
                NULL, 
                0, NULL, 0);
        return -1;
    }

    pcapfname = strndup(placeholder, placeholder_len);

    local_pcap->pcapfname = pcapfname;

    fprintf(stderr, "debug - pcapfile - got fname '%s'\n", pcapfname);

    if (stat(pcapfname, &sbuf) < 0) {
        snprintf(errstr, PCAP_ERRBUF_SIZE, "Unable to find pcapfile '%s'", pcapfname);
        fprintf(stderr, "debug - pcapfile - %s\n", errstr);
        cf_send_openresp(caph, seqno, false, errstr, NULL, 0, NULL, 0, NULL, 0);
        return -1;
    }

    if (!S_ISREG(sbuf.st_mode)) {
        snprintf(errstr, PCAP_ERRBUF_SIZE, 
                "File '%s' is not a regular file", pcapfname);
        fprintf(stderr, "debug - pcapfile - %s\n", errstr);
        cf_send_openresp(caph, seqno, false, errstr, NULL, 0, NULL, 0, NULL, 0);
        return -1;
    }

    local_pcap->pd = pcap_open_offline(pcapfname, errstr);
    if (strlen(errstr) > 0) {
        fprintf(stderr, "debug - pcapfile - %s\n", errstr);
        cf_send_openresp(caph, seqno, false, errstr, NULL, 0, NULL, 0, NULL, 0);
        return -1;
    }

    fprintf(stderr, "debug - pcapfile - opened pcap file!\n");

    /* Succesful open with no channel, hop, or chanset data */
    snprintf(errstr, PCAP_ERRBUF_SIZE,
            "Opened pcapfile '%s' for playback", pcapfname);
    cf_send_openresp(caph, seqno, true, errstr, NULL, 0, NULL, 0, NULL, 0);

    fprintf(stderr, "debug - pcapfile - returning from open handler\n");

    cf_send_message(caph, "Pcapfile ready to start playback", MSGFLAG_INFO);

    return 1;
}

int main(int argc, char *argv[]) {
    local_pcap_t local_pcap = {
        .pd = NULL,
        .pcapfname = NULL,
        .datalink_type = -1,
        .override_dlt = -1
    };

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

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &local_pcap);

    /* Set the callback for opening a pcapfile */
    cf_handler_set_open_cb(caph, open_callback);

    cf_handler_loop(caph);

    fprintf(stderr, "FATAL: Exited main select() loop, waiting to be killed\n");

    cf_handler_free(caph);

    while (1) {
        sleep(1);
    }

    return 1;
}

