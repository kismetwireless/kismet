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


int
install_bpf_program(pcap_t *p, struct bpf_program *fp) {
	return 0;
}


void
pcap_freecode(struct bpf_program *program) {
	return;
}

