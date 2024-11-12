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

#include "configfile.h"
#include "kis_pcapnglogfile.h"
#include "messagebus.h"

kis_pcapng_logfile::kis_pcapng_logfile(shared_log_builder in_builder) :
    kis_logfile(in_builder) {
    buffer = new future_chainbuf(4096, 1024);
    pcapng = nullptr;
    pcapng_file = nullptr;

    log_duplicate_packets =
        Globalreg::globalreg->kismet_config->fetch_opt_bool("pcapng_log_duplicate_packets", true);
    truncate_duplicate_packets =
        Globalreg::globalreg->kismet_config->fetch_opt_bool("pcapng_truncate_duplicate_packets", false);
    log_data_packets =
        Globalreg::globalreg->kismet_config->fetch_opt_bool("pcapng_log_data_packets", true);

    // Max size in mb
    max_size = 
        Globalreg::globalreg->kismet_config->fetch_opt_ulong("pcapng_log_max_mb", 0L);
    max_size = max_size * 1024 * 1024;

    auto packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>("PACKETCHAIN");
    pack_comp_common = packetchain->register_packet_component("COMMON");
    pack_comp_l1data = packetchain->register_packet_component("L1RAW");
    pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
}

kis_pcapng_logfile::~kis_pcapng_logfile() {
    close_log();
    delete buffer;
}

bool kis_pcapng_logfile::open_log(const std::string& in_template, 
        const std::string& in_path) {
    kis_lock_guard<kis_mutex> lk(log_mutex);

    set_int_log_path(in_path);
    set_int_log_template(in_template);

    pcapng_file = fopen(in_path.c_str(), "w");

    if (pcapng_file == nullptr) {
        _MSG_ERROR("Failed to open pcapng log '{}' - {}",
                in_path, kis_strerror_r(errno));
        return false;
    }

    auto l1data_selector = std::function<std::shared_ptr<kis_datachunk>(std::shared_ptr<kis_packet>)>();

    if (truncate_duplicate_packets) {
        l1data_selector = [this](std::shared_ptr<kis_packet> in_packet) -> std::shared_ptr<kis_datachunk> {
            if (in_packet->duplicate) {
                auto target_datachunk = in_packet->fetch<kis_datachunk>(pack_comp_l1data);
                if (target_datachunk == nullptr) {
                    auto target_datachunk = in_packet->fetch<kis_datachunk>(pack_comp_linkframe);
                }

                return target_datachunk;
            }

            return in_packet->fetch<kis_datachunk>(pack_comp_linkframe);
        };
    } else {
        l1data_selector = nullptr;
    }

    pcapng = new pcapng_stream_packetchain(buffer, 
            pcapng_logfile_accept_ftor(log_duplicate_packets, log_data_packets),
            pcapng_logfile_select_ftor(truncate_duplicate_packets), (size_t) 16384);

    _MSG_INFO("Opened pcapng log file '{}'", in_path);

    set_int_log_open(true);

    auto thread_p = std::promise<void>();
    auto thread_f = thread_p.get_future();

    stream_t = std::thread([this, thread_p = std::move(thread_p)]() mutable {
            thread_p.set_value();

            while (pcapng_file != nullptr && (buffer->running() || buffer->size() > 0)) {
                buffer->wait();

                char *data;

                auto sz = buffer->get(&data);

                if (sz > 0) {
                    if (fwrite(data, sz, 1, pcapng_file) == 0) {
                        _MSG_ERROR("Error writing to pcapng log '{}' - {}", get_log_path(),
                                kis_strerror_r(errno));
                        close_log();
                        return;
                    }
                }

                buffer->consume(sz);

                log_size += sz;

                // Flush the buffer, close the log, and make a new one
                if (log_size >= max_size && max_size != 0) {
                    log_size = 0;
                    rotate_log();
                }
            }

        });

    thread_f.wait();
    pcapng->start_stream();

    return true;
}

void kis_pcapng_logfile::rotate_log() {
    // Rotate log is called inside the stream lambda, so the stream lambda thread 
    // can't be touching the old log

    // Move the old buffer and file, replace with new
    auto old_buffer = buffer;
    auto old_pcapng_file = pcapng_file;
    auto old_path = get_log_path();

    // Reset the buffer and pcap log; this will make a new SHB in the new buffer
    // immediately, and leave the remnants of the old packets in the old buffer
    buffer = pcapng->restart_stream(new future_chainbuf(4096, 1024));

    // Generate a new log file from the template and open it
    auto logtracker = 
        Globalreg::fetch_mandatory_global_as<log_tracker>();

    auto logpath =
        logtracker->expand_template(get_log_template(), builder->get_log_class());
    set_int_log_path(logpath);

    _MSG_INFO("Rotating to new pcapng log {}", logpath);

    pcapng_file = fopen(logpath.c_str(), "w");

    if (pcapng_file == nullptr) {
        _MSG_ERROR("Failed to open pcapng log '{}' - {}",
                logpath, kis_strerror_r(errno));
        close_log();
        return;
    }

    // Flush out the contents of the old buffer direct to the old file; the buffer will
    // empty because the stream has the new buffer assigned already
    while (old_buffer->size() > 0) {
        char *data;

        auto sz = old_buffer->get(&data);

        if (sz > 0) {
            if (fwrite(data, sz, 1, old_pcapng_file) == 0) {
                _MSG_ERROR("Error writing to pcapng log '{}' - {}", old_path,
                        kis_strerror_r(errno));
                close_log();
                return;
            }
        }

        old_buffer->consume(sz);
    }

    // Close the old file and remove the old buffer
    fclose(old_pcapng_file);
    delete old_buffer;

    // Return to the packet handling loop thread and let it start processing packets again
}

void kis_pcapng_logfile::close_log() {
    kis_lock_guard<kis_mutex> lk(log_mutex);

    set_int_log_open(false);

    buffer->cancel();

    if (stream_t.joinable())
        stream_t.join();

    if (pcapng_file)
        fclose(pcapng_file);

    pcapng_file = nullptr;
}

