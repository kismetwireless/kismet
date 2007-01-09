/*
    This file is part of Kismet (sort of)

    lorcon is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    lorcon is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with lorcon; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Copyright (c) 2005 dragorn and Joshua Wright
*/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <net/if_arp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>

// Because some kernels include ethtool which breaks horribly...
// // The stock ones don't but others seem to
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
#include <linux/wireless.h>

#include <errno.h>
#include <string.h>

#include <pcap.h>

#define MAX_PACKET_LEN 8192

void usage() {
	printf("pcap-to-tuntap\n"
	       "Usage : pcap-to-tuntap [options]\n"
		   "  -p <file>            pcap file to replay\n"
		   "  -t <interface>       specify the tuntap interface name\n"
		   "  -s <delay>           startup delay before playing pcap file\n");
}

int main(int argc, char *argv[]) {
	struct ifreq ifr;

	int ret = 0, ttfd = -1, intfd = -1, flags = 0, startdelay = 0, c = 0,
		ltype = 0, stype = 0;

	char tface[16 + 1];

	char *pfile = NULL;

	pcap_t *pd;
	const u_char *pcap_pkt;
	struct pcap_pkthdr pcap_hdr;
	char errstr[PCAP_ERRBUF_SIZE + 1];

	struct timeval then, soon;

	memset(tface, 0, sizeof(tface));

	while ((c = getopt(argc, argv, "p:t:s:")) != EOF) {
		switch (c) {
		case 't':
			strncpy(tface, optarg, sizeof(tface) - 1);
			break;
		case 's':
			if (sscanf(optarg, "%d", &startdelay) != 1) {
				fprintf(stderr, "Expected integer seconds for start delay\n");
				usage();
				return -1;
			}
			break;
		case 'p':
			pfile = strdup(optarg);
			break;
		default:
			break;
		}
	}

	if (!strlen(tface)) {
		fprintf(stderr, "Must specify a tuntap interface name.\n");
		usage();
		return -1;
	}

	if (pfile == NULL) {
		fprintf(stderr, "Must specify a pcap file to load.\n");
		usage();
		return -1;
	}

	/* Create the tuntap device */
	if ((ttfd = open("/dev/net/tun", O_RDWR)) < 0) {
		perror("Could not open /dev/net/tun control file");
		return -1;
	}
	
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = (IFF_TAP | IFF_NO_PI);
	strncpy(ifr.ifr_name, tface, sizeof(tface) - 1);

	if (ioctl(ttfd, TUNSETIFF, (void *) &ifr) < 0) {
		perror("Unable to create tuntap interface");
		return -1;
	}

	/* Open the pcap file */
	errstr[0] = '\0';
	pd = pcap_open_offline(pfile, errstr);
	if (strlen(errstr) > 0) {
		fprintf(stderr, "Failed to open pcap file: %s\n", errstr);
		return -1;
	}

	ltype = pcap_datalink(pd);
	fprintf(stderr, "Opened pcap file, link type %d\n", ltype);

	if (ltype == 127) {
		stype = 803;
	} else if (ltype == 105) {
		stype = 801;
	}

	if (stype != 0) {
		if (ioctl(ttfd, TUNSETLINK, stype) < 0) {
			fprintf(stderr, "Failed to set tuntap link type to %d: %s\n", stype,
					strerror(errno));
			return -1;
		}
	}

	/* bring the tuntap up */
	if ((intfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("Failed to create AF_INET socket");
		return -1;
	}


	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, tface, IFNAMSIZ);
	if (ioctl(intfd, SIOCGIFFLAGS, &ifr) < 0) {
		perror("Failed to get interface flags for tuntap");
		return -1;
	}

	flags = ifr.ifr_flags;
	flags |= (IFF_UP | IFF_RUNNING | IFF_PROMISC);
	ifr.ifr_flags = flags;

	if (ioctl(intfd, SIOCSIFFLAGS, &ifr) < 0) {
		perror("Failed to set interface flags for tuntap");
		return -1;
	}

	close(intfd);

	if (startdelay != 0) {
		fprintf(stderr, "Sleeping %d seconds before replaying...\n", startdelay);
		sleep(startdelay);
	}

	fprintf(stderr, "Replaying pcap file...\n");

	then.tv_sec = 0;

	while (1) {
		if ((pcap_pkt = pcap_next(pd, &pcap_hdr)) == NULL) {
			pcap_perror(pd, "Failed to get next packet from file");
			break;
		}

		if (write(ttfd, (u_char *) pcap_pkt, pcap_hdr.caplen) != pcap_hdr.caplen) {
			fprintf(stderr, "Short write on pcap frame\n");
		}

		if (then.tv_sec != 0) {
			soon.tv_sec = pcap_hdr.ts.tv_sec - then.tv_sec;

			if (pcap_hdr.ts.tv_usec < then.tv_usec && soon.tv_sec > 0) {
				soon.tv_sec--;
				soon.tv_usec = (1000000 + pcap_hdr.ts.tv_usec) - then.tv_usec;
			} else {
				soon.tv_usec = pcap_hdr.ts.tv_usec - then.tv_usec;
			}

			select(0, NULL, NULL, NULL, &soon);
		}

		then.tv_sec = pcap_hdr.ts.tv_sec;
		then.tv_usec = pcap_hdr.ts.tv_usec;
	}

	return 0;
}
