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

#ifndef __KIS_PCAPNGLOGFILE_H__
#define __KIS_PCAPNGLOGFILE_H__

#include "config.h"

#include "globalregistry.h"
#include "logtracker.h"

#include "pcapng_stream_ringbuf.h"
#include "filewritebuf.h"

class KisPcapNGLogfile : public KisLogfile {
public:
    KisPcapNGLogfile(SharedLogBuilder in_builder);
    virtual ~KisPcapNGLogfile();

    virtual bool Log_Open(std::string in_path) override;
    virtual void Log_Close() override;

protected:
    Pcap_Stream_Packetchain *pcapng_stream;
    std::shared_ptr<BufferHandler<FileWritebuf> > bufferhandler;
    FileWritebuf *pcapng_file;
};

class KisPcapNGLogfileBuilder : public KisLogfileBuilder {
public:
    KisPcapNGLogfileBuilder() :
        KisLogfileBuilder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    KisPcapNGLogfileBuilder(int in_id) :
        KisLogfileBuilder(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    KisPcapNGLogfileBuilder(int in_id, std::shared_ptr<TrackerElementMap> e) :
        KisLogfileBuilder(in_id, e) {
        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~KisPcapNGLogfileBuilder() { }

    virtual SharedLogfile build_logfile(SharedLogBuilder builder) {
        return SharedLogfile(new KisPcapNGLogfile(builder));
    }

    virtual void initialize() {
        set_log_class("pcapng");
        set_log_name("PcapNG pcap");
        set_stream(true);
        set_singleton(false);
        set_log_description("PcapNG multi-interface capture with full original per-packet "
                "metadata headers");
    }

};

#endif

