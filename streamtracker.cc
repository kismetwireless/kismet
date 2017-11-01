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

    tracked_stream_map.reset(new TrackerElement(TrackerDoubleMap));
    stream_map = TrackerElementDoubleMap(tracked_stream_map);

    next_stream_id = 1;
}

StreamTracker::~StreamTracker() {
    local_eol_locker lock(&mutex);
}

bool StreamTracker::Httpd_VerifyPath(const char *path, const char *method) {
    local_demand_locker lock(&mutex);

    if (strcmp(method, "GET") != 0) 
        return false;

    if (!Httpd_CanSerialize(path))
        return false;

    string stripped = httpd->StripSuffix(path);

    if (stripped == "/streams/all_streams") {
        return true;
    }

    vector<string> tokenurl = StrTokenize(stripped, "/");

    // /streams/by-id/[NUM]/stream_info
    // /streams/by-id/[NUM]/close_stream

    if (tokenurl.size() < 5)
        return false;

    if (tokenurl[1] != "streams")
        return false;

    if (tokenurl[2] != "by-id")
        return false;

    double sid;
    std::stringstream ss(tokenurl[3]);
    ss >> sid;

    lock.lock();
    if (stream_map.find(sid) == stream_map.end())
        return false;
    lock.unlock();

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

    local_locker lock(&mutex);

    if (strcmp(method, "GET") != 0) {
        return;
    }

    if (!Httpd_CanSerialize(path))
        return;

    string stripped = httpd->StripSuffix(path);

    if (stripped == "/streams/all_streams") {
        SharedTrackerElement outvec(new TrackerElement(TrackerVector));
        TrackerElementVector outv(outvec);

        for (auto si = stream_map.begin(); si != stream_map.end(); ++si) {
            outv.push_back(si->second);
        }

        Httpd_Serialize(path, stream, outvec);
        return;
    }

    vector<string> tokenurl = StrTokenize(stripped, "/");

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

        stream << "OK";

        return;
    }
}

void StreamTracker::register_streamer(streaming_agent *in_agent,
        string in_name, string in_type, string in_path, string in_description) {

    local_locker lock(&mutex);

    shared_ptr<streaming_info_record> streamrec = 
        static_pointer_cast<streaming_info_record>(info_builder->clone_type());

    streamrec->set_agent(in_agent);
    in_agent->set_stream_id(next_stream_id++);

    streamrec->set_log_name(in_name);
    streamrec->set_log_type(in_type);
    streamrec->set_log_path(in_path);
    streamrec->set_log_description(in_description);

    TrackerElementDoubleMap::pair p(in_agent->get_stream_id(), streamrec);
    stream_map.insert(p);
}

void StreamTracker::remove_streamer(double in_id) {
    local_locker lock(&mutex);

    auto si = stream_map.find(in_id);

    if (si == stream_map.end())
        return;

    shared_ptr<streaming_info_record> a =
        static_pointer_cast<streaming_info_record>(si->second);
    a->get_agent()->stop_stream("stream removed");

    stream_map.erase(si);
}

