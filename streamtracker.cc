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

#include "config.hpp"

#include "streamtracker.h"
#include "entrytracker.h"

StreamTracker::StreamTracker(GlobalRegistry *in_globalreg) :
    Kis_Net_Httpd_CPPStream_Handler(in_globalreg), 
    LifetimeGlobal() {

    globalreg = in_globalreg;

    shared_ptr<EntryTracker> entrytracker = 
        static_pointer_cast<EntryTracker>(globalreg->FetchGlobal("ENTRY_TRACKER"));

    info_builder.reset(new streaming_info_record(globalreg, 0));
    info_builder_id = entrytracker->RegisterField("kismet.stream.stream",
            info_builder, "Export stream");

}

StreamTracker::~StreamTracker() {

}

bool StreamTracker::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") != 0) 
        return false;

    if (!Httpd_CanSerialize(path))
        return false;

    string stripped = httpd->StripSuffix(path);

    if (stripped == "/streams/all_streams") {
        return true;
    }

    vector<string> tokenurl = StrTokenize(path, "/");

    // /streams/by-id/[NUM]/stream_info
    // /streams/by-id/[NUM]/close_stream

    if (tokenurl.size() < 5)
        return false;

    if (tokenurl[1] != "streams")
        return false;

    if (tokenurl[2] != "by-id")
        return false;

    uint64_t sid;
    std::stringstream ss(tokenurl[3]);
    ss >> sid;

    if (stream_map.find(sid) == stream_map.end())
        return false;

    if (tokenurl[4] == "stream_info")
        return true;

    if (tokenurl[4] == "close_stream")
        return true;

    return false;
}

void StreamTracker::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        Kis_Net_Httpd_Connection *connection,
        const char *path, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

    if (strcmp(method, "GET") != 0) {
        return;
    }

    if (!Httpd_CanSerialize(path))
        return;

    string stripped = httpd->StripSuffix(path);

    if (stripped == "/streams/all_streams") {
        Httpd_Serialize(path, stream, tracked_stream_map);
        return;
    }

    vector<string> tokenurl = StrTokenize(path, "/");

    // /streams/by-id/[NUM]/stream_info
    // /streams/by-id/[NUM]/close_stream

    if (tokenurl.size() < 5)
        return;

    if (tokenurl[1] != "streams")
        return;

    if (tokenurl[2] != "by-id")
        return;

    uint64_t sid;
    std::stringstream ss(tokenurl[3]);
    ss >> sid;

    auto smi = stream_map.find(sid);

    if (smi == stream_map.end())
        return;

    if (tokenurl[4] == "stream_info") {
        Httpd_Serialize(path, stream, smi->second);
        return;
    }

    if (tokenurl[4] == "close_stream") {
        if (!httpd->HasValidSession(connection)) {
            connection->httpcode = 400;
            return;
        }

        shared_ptr<streaming_info_record> ir = 
            static_pointer_cast<streaming_info_record>(smi->second);

        ir->get_agent()->stop_stream("stream closed from web");

        return;
    }
}

