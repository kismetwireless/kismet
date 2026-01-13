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

#include "eventbus.h"
#include "kis_net_beast_httpd.h"

event_bus::event_bus() :
    lifetime_global(),
    deferred_startup() {

    mutex.set_name("event_bus");
    handler_mutex.set_name("event_bus_handler");

    Globalreg::enable_pool_type<eventbus_event>([](auto *a) { a->reset(); });

    next_cbl_id = 1;

    shutdown = false;

    eventbus_event_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.eventbus.event",
                tracker_element_factory<eventbus_event>(),
                "Eventbus event");

    event_cl.lock();

    event_dispatch_t =
        std::thread([this]() {
                thread_set_process_name("eventbus");
                event_queue_dispatcher();
            });

}

event_bus::~event_bus() {
    shutdown = true;

    event_cl.unlock(0);
    event_dispatch_t.join();
}

void event_bus::trigger_deferred_startup() {
    auto httpd = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    httpd->register_websocket_route("/eventbus/events", httpd->RO_ROLE, {"ws"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {

                std::unordered_map<std::string, unsigned long> reg_map;

                auto ws =
                    std::make_shared<kis_net_web_websocket_endpoint>(con,
                        [this, &reg_map](std::shared_ptr<kis_net_web_websocket_endpoint> ws,
                            std::shared_ptr<boost::asio::streambuf> buf, bool text) mutable {

                            if (!text) {
                                ws->close();
                                return;
                            }

                            std::stringstream ss(boost::beast::buffers_to_string(buf->data()));
                            nlohmann::json json;

                            std::string jsontype = "json";

                            try {
                                ss >> json;
                            } catch (const std::exception& e) {
                                _MSG_ERROR("Invalid websocket request (could not parse JSON message) on "
                                        "/eventbus/events.ws");
                                return;
                            }

                            if (!json["format"].is_null()) {
                                jsontype = json["format"].get<std::string>();
                            }

                            if (!json["SUBSCRIBE"].is_null()) {
                                auto e_k = reg_map.find(json["SUBSCRIBE"].get<std::string>());
                                if (e_k != reg_map.end()) {
                                    remove_listener(e_k->second);
                                    reg_map.erase(e_k);
                                }

                                auto id =
                                    register_listener(json["SUBSCRIBE"].get<std::string>(),
                                            [ws, json, jsontype](std::shared_ptr<eventbus_event> evt) {
                                                std::stringstream os;
                                                Globalreg::globalreg->entrytracker->serialize_with_json_summary(jsontype, os,
                                                        evt->get_event_content(), json);
												auto data = os.str();
                                                ws->write(data);
                                            });

                                reg_map[json["SUBSCRIBE"].get<std::string>()] = id;
                            }

                            if (!json["UNSUBSCRIBE"].is_null()) {
                                auto e_k = reg_map.find(json["UNSUBSCRIBE"].get<std::string>());
                                if (e_k != reg_map.end()) {
                                    remove_listener(e_k->second);
                                    reg_map.erase(e_k);
                                }

                            }
                        });

                ws->text();

                // Blind-catch all errors b/c we must release our listeners at the end
                try {
                    ws->handle_request(con);
                } catch (const std::exception& e) {
                    ws->close();
                }

                for (auto s : reg_map)
                    remove_listener(s.second);
                }));

}

std::shared_ptr<eventbus_event> event_bus::get_eventbus_event(const std::string& event_type) {
    auto evt = Globalreg::globalreg->entrytracker->new_from_pool<eventbus_event>();
    evt->set_id(eventbus_event_id);
    evt->set_event_id(event_type);
    return evt;
}

void event_bus::event_queue_dispatcher() {
    //kis_unique_lock<kis_mutex> lock(mutex, std::defer_lock, "event_bus event_queue_dispatcher");
    std::unique_lock<kis_mutex> lock(mutex, std::defer_lock);

    while (!shutdown &&
            !Globalreg::globalreg->spindown &&
            !Globalreg::globalreg->fatal_condition &&
            !Globalreg::globalreg->complete) {

        // Lock while we examine the queue
        lock.lock();
        std::shared_ptr<eventbus_event> e;
        if (event_queue.size() > 0) {
            e = event_queue.front();
            event_queue.pop();
        }
        lock.unlock();

        if (e != nullptr) {
            // Lock the handler mutex while we're processing an event
            // kis_unique_lock<kis_mutex> rl(handler_mutex, std::defer_lock, "event_bus dispatch");
            std::unique_lock<kis_mutex> rl(handler_mutex, std::defer_lock);

            rl.lock();

            auto ch_listeners = callback_table.find(e->get_event_id());
            auto ch_all_listeners = callback_table.find("*");

            if (ch_listeners == callback_table.end() && ch_all_listeners == callback_table.end()) {
                continue;
            }

            // Copy into a workvec in case one of the event handlers removes itself from the events
            // in the future
            std::vector<std::shared_ptr<callback_listener>> workvec;

            if (ch_listeners != callback_table.end()) {
                for (const auto& cbl : ch_listeners->second)  {
                    workvec.push_back(cbl);
                }
            }

            if (ch_all_listeners != callback_table.end()) {
                for (const auto& cbl : ch_all_listeners->second) {
                    workvec.push_back(cbl);
                }
            }

            rl.unlock();

            for (const auto& cbl : workvec) {
                try {
                    cbl->cb(e);
                } catch (const std::exception& e) {
                    _MSG_ERROR("Error in eventbus handler: {}", e.what());
                }
            }

            // Loop for more events
            continue;
        }

        // Reset the lock
        event_cl.lock();

        // Wait until new events
        event_cl.block_until();
    }
}

unsigned long event_bus::register_listener(const std::string& channel, cb_func cb) {
    return register_listener(std::list<std::string>{channel}, cb);
}

unsigned long event_bus::register_listener(const std::list<std::string>& channels, cb_func cb) {
    std::lock_guard<kis_mutex> lk(handler_mutex);
    // kis_lock_guard<kis_mutex> lk(handler_mutex, "event_bus register_listener (vector)");

    auto cbl = std::make_shared<callback_listener>(channels, cb, next_cbl_id++);

    for (auto i : channels) {
        callback_table[i].push_back(cbl);
    }

    callback_id_table[cbl->id] = cbl;

    return cbl->id;
}

void event_bus::remove_listener(unsigned long id) {
    std::lock_guard<kis_mutex> lk(handler_mutex);
    // kis_lock_guard<kis_mutex> lk(handler_mutex, "event_bus remove_listener");

    // Find matching cbl
    auto cbl = callback_id_table.find(id);
    if (cbl == callback_id_table.end())
        return;

    // Match all channels this cbl is subscribed to
    for (auto c : cbl->second->channels) {

        // remove from each channel
        for (auto cbi = callback_table[c].begin(); cbi != callback_table[c].end(); ++cbi) {
            if ((*cbi)->id == id) {
                callback_table[c].erase(cbi);
                break;
            }
        }
    }

    // Remove from CBL ID table
    callback_id_table.erase(cbl);
}

