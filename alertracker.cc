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

#include "alertracker.h"
#include "server_globals.h"
#include "kismet_server.h"

Alertracker::Alertracker() {
    next_alert_id = 0;
    max_backlog = 0;
    server = NULL;
    protoref = -1;
}

Alertracker::~Alertracker() {
    for (map<int, alert_rec *>::iterator x = alert_ref_map.begin();
         x != alert_ref_map.end(); ++x)
        delete x->second;
}

void Alertracker::AddTcpServer(TcpServer *in_server) {
    server = in_server;
}

void Alertracker::AddAlertProtoRef(int in_ref) {
    protoref = in_ref;
}

void Alertracker::SetAlertBacklog(int in_max) {
    max_backlog = in_max;
}

int Alertracker::RegisterAlert(const char *in_header, alert_time_unit in_unit, int in_rate,
                               int in_burst) {

    // Bail if this header is registered
    if (alert_name_map.find(in_header) != alert_name_map.end())
        return -1;

    alert_rec *arec = new alert_rec;

    arec->ref_index = next_alert_id++;
    arec->header = in_header;
    arec->limit_unit = in_unit;
    arec->limit_rate = in_rate;
    arec->limit_burst = in_burst;
    arec->burst_sent = 0;

    alert_name_map[arec->header] = arec->ref_index;
    alert_ref_map[arec->ref_index] = arec;

    return arec->ref_index;
}

int Alertracker::FetchAlertRef(string in_header) {
    if (alert_name_map.find(in_header) != alert_name_map.end())
        return alert_name_map[in_header];

    return -1;
}

int Alertracker::CheckTimes(alert_rec *arec) {
    // Is this alert rate-limited?
    if (arec->limit_rate == 0) {
        return 1;
    }

    // Have we hit the burst limit?  If not, we'll be find to send.
    if (arec->burst_sent < arec->limit_burst) {
        return 1;
    }

    // If we're past the burst but we don't have anything in the log...
    if (arec->alert_log.size() == 0) {
        return 1;
    }

    struct timeval now;
    gettimeofday(&now, NULL);

    // Dig down through the list and throw away any old ones floating
    // on the top.  A record is old if it's more than the limit unit.
    while (arec->alert_log.size() > 0) {
        struct timeval *rec_tm = arec->alert_log.front();

        if (rec_tm->tv_sec < (now.tv_sec - alert_time_unit_conv[arec->limit_unit])) {
            delete arec->alert_log.front();
            arec->alert_log.pop_front();
        } else {
            break;
        }
    }

    // Zero the burst counter if we haven't had any traffic within the
    // time unit
    if (arec->alert_log.size() == 0)
        arec->burst_sent = 0;

    // Finally, we'll send the alert if the number of alerts w/in the time
    // unit is less than our limit.
    if ((int) arec->alert_log.size() < arec->limit_rate)
        return 1;

    return 0;

}

int Alertracker::PotentialAlert(int in_ref) {
    map<int, alert_rec *>::iterator aritr = alert_ref_map.find(in_ref);

    if (aritr == alert_ref_map.end())
        return -1;

    alert_rec *arec = aritr->second;

    return CheckTimes(arec);
}

int Alertracker::RaiseAlert(int in_ref, 
                            mac_addr bssid, mac_addr source, mac_addr dest, mac_addr other,
                            string in_text) {
    map<int, alert_rec *>::iterator aritr = alert_ref_map.find(in_ref);

    if (aritr == alert_ref_map.end())
        return -1;

    alert_rec *arec = aritr->second;

    if (CheckTimes(arec) != 1)
        return 0;

    ALERT_data *adata = new ALERT_data;

    char tmpstr[128];
    timeval *ts = new timeval;
    gettimeofday(ts, NULL);

    snprintf(tmpstr, 128, "%ld", (long int) ts->tv_sec);
    adata->sec = tmpstr;

    snprintf(tmpstr, 128, "%ld", (long int) ts->tv_usec);
    adata->usec = tmpstr;

    adata->text = in_text;
    adata->header = arec->header;
    adata->bssid = bssid.Mac2String();
    adata->source = source.Mac2String();
    adata->dest  = dest.Mac2String();
    adata->other = other.Mac2String();

    arec->burst_sent++;
    if (arec->burst_sent >= arec->limit_burst)
        arec->alert_log.push_back(ts);

    alert_backlog.push_back(adata);
    if (alert_backlog.size() > max_backlog) {
        delete alert_backlog[0];
        alert_backlog.erase(alert_backlog.begin());
    }

    server->SendToAll(protoref, (void *) adata);

    // Hook main for sounds and whatnot on the server
    KisLocalAlert(in_text.c_str());

    return 1;
}

void Alertracker::BlitBacklogged(int in_fd) {
    for (unsigned int x = 0; x < alert_backlog.size(); x++)
        server->SendToClient(in_fd, protoref, (void *) alert_backlog[x]);
}
