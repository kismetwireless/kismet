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

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "fifodump.h"

int FifoDumpFile::OpenDump(const char *file) {
    snprintf(type, 64, "FIFO packet dump");
    snprintf(filename, 1024, "%s", file);

    num_dumped = 0;

    struct stat filestat;

    // See if it exists and it's a pipe already
    if (stat(file, &filestat) != -1) {
        if (!S_ISFIFO(filestat.st_mode)) {
            snprintf(errstr, 1024, "%s already exists and isn't a pipe.", file);
            return -1;
        }
    } else if (mknod(file, 0644 | S_IFIFO, 0) < 0) {
        snprintf(errstr, 1024, "Couldn't create pipe %s: %s", file, strerror(errno));
        return -1;
    }

    // This will now block until something is reading from the pipe.
    if ((dump_file = fopen(file, "w")) == NULL) {
        snprintf(errstr, 1024, "Couldn't open pipe %s for writing: %s", file, strerror(errno));
        return -1;
    }

    uint32_t magic = PCAP_MAGIC;
    int nwritten;

    // Write the magic file identifier
    nwritten = fwrite(&magic, 1, sizeof(magic), dump_file);
    if (nwritten != sizeof(magic)) {
        if (nwritten == 0 && ferror(dump_file))
            snprintf(errstr, 1024, "Unable to write pcap magic header. (%s)", strerror(errno));
        else
            snprintf(errstr, 1024, "Short write on pcap magic header.");

        return -1;
    }

    pcap_hdr file_hdr;

    /* current "libpcap" format is 2.4 */
    file_hdr.version_major = 2;
    file_hdr.version_minor = 4;
    file_hdr.thiszone = 0;  /* XXX - current offset? */
    file_hdr.sigfigs = 0;   /* unknown, but also apparently unused */
    file_hdr.snaplen = 2344;
    file_hdr.network = 105; /* pcap file type */

    // Write the header
    nwritten = fwrite(&file_hdr, 1, sizeof(file_hdr), dump_file);
    if (nwritten != sizeof(file_hdr)) {
        if (nwritten == 0 && ferror(dump_file))
            snprintf(errstr, 1024, "Unable to write pcap file header. (%s)", strerror(errno));
        else
            snprintf(errstr, 1024, "Short write on pcap file header.");

        return -1;
    }

    // Flush.  Always.  Otherwise the FILE* stuff gets buffered and makes the pipe
    // cranky.
    fflush(dump_file);

    return 1;
}

int FifoDumpFile::CloseDump() {
    fclose(dump_file);

    return num_dumped;
}

int FifoDumpFile::DumpPacket(const packet_info *in_info, const kis_packet *packet) {
    /*
    if (in_info->type != packet_data)
    return 0;
    */

    kis_packet *dump_packet;
    int mangled = 0;

    // Mangle decrypted and fuzzy packets into legit packets
    if ((dump_packet = MangleDeCryptPacket(packet, in_info)) != NULL)
        mangled = 1;
    else if ((dump_packet = MangleFuzzyCryptPacket(packet, in_info)) != NULL)
        mangled = 1;
    else
        dump_packet = (kis_packet *) packet;

    pcaprec_hdr packhdr;
    unsigned int nwritten;

    // Convert it to a pcap header
    packhdr.ts_sec = dump_packet->ts.tv_sec;
    packhdr.ts_usec = dump_packet->ts.tv_usec;
    packhdr.incl_len = dump_packet->caplen;
    packhdr.orig_len = dump_packet->caplen;

    nwritten = fwrite(&packhdr, 1, sizeof(pcaprec_hdr), dump_file);
    if (nwritten != sizeof(pcaprec_hdr)) {
        if (nwritten == 0 && ferror(dump_file))
            snprintf(errstr, 1024, "Unable to write pcap packet header (%s)", strerror(errno));
        else
            snprintf(errstr, 1024, "Short write on pcap packet header");

        // delete the new packet if needed
        if (mangled == 1) {
            delete[] dump_packet->data;
            delete dump_packet;
        }

        return -1;
    }

    nwritten = fwrite(dump_packet->data, 1, packhdr.incl_len, dump_file);
    if (nwritten != packhdr.incl_len) {
        if (nwritten == 0 && ferror(dump_file))
            snprintf(errstr, 1024, "Unable to write pcap packet (%s)", strerror(errno));
        else
            snprintf(errstr, 1024, "Short write on pcap packet");

        // delete the new packet if needed
        if (mangled == 1) {
            delete[] dump_packet->data;
            delete dump_packet;
        }

        return -1;
    }

    // delete the new packet if needed
    if (mangled == 1) {
        delete[] dump_packet->data;
        delete dump_packet;
    }

    num_dumped++;

    fflush(dump_file);

    return 1;
}
