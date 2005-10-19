/* stub to remove filtering support 
 * dragorn
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#include <errno.h>

#include "pcap-int.h"

#include "gencode.h"

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

int no_optimize = 1;

int
install_bpf_program(pcap_t *p, struct bpf_program *fp) {
	fprintf(stderr, "OOPS:  Something tried to install a bpf program into the "
			"stripped down Kismet libpcap.  This is probably going to cause "
			"problems or confusion later.\n");
	return 0;
}


void
pcap_freecode(struct bpf_program *program) {
	return;
}

