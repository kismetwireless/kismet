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

#include "kis_pcapnglogfile.h"
#include "messagebus.h"

kis_pcapng_logfile::kis_pcapng_logfile(shared_log_builder in_builder) :
    kis_logfile(in_builder) {

    pcapng_stream = NULL;
    pcapng_file = NULL;
}

kis_pcapng_logfile::~kis_pcapng_logfile() {
    close_log();
}

bool kis_pcapng_logfile::open_log(std::string in_path) {
    local_locker lock(&log_mutex);

    set_int_log_path(in_path);

    // Try to open the logfile for writing as a buffer
    try {
        pcapng_file = new file_write_buffer(in_path, 16384);
    } catch (std::exception& e) {
        _MSG("Failed to open pcapng dump file '" + in_path + "': " +
                e.what(), MSGFLAG_ERROR);
        return false;
    }

    // Make a buffer handler stub to write to our file
    bufferhandler.reset(new buffer_handler<file_write_buffer>(NULL, pcapng_file));

    // Generate the pcap stream itself
    pcapng_stream = new pcap_stream_packetchain(Globalreg::globalreg, bufferhandler, NULL, NULL);

    _MSG("Opened pcapng log file '" + in_path + "'", MSGFLAG_INFO);

    set_int_log_open(true);

    return true;
}

void kis_pcapng_logfile::close_log() {
    local_locker lock(&log_mutex);

    set_int_log_open(false);

    if (pcapng_stream != NULL) {
        pcapng_stream->stop_stream("Log closing");
        delete(pcapng_stream);
        pcapng_stream = NULL;
    }

    bufferhandler.reset();
    pcapng_file = NULL;
}

