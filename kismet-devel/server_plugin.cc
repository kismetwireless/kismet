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

#include <sys/time.h>
#include <map>

#include "server_plugin.h"

// Instance of the time tracker
Timetracker timetracker;

vector<ALERT_data *> pending_alerts;
vector<ALERT_data *> past_alerts;

void QueueAlert(const char *in_alert) {
    ALERT_data *adata = new ALERT_data;
    char tmpstr[128];
    timeval ts;
    gettimeofday(&ts, NULL);

    snprintf(tmpstr, 128, "%ld", (long int) ts.tv_sec);
    adata->sec = tmpstr;

    snprintf(tmpstr, 128, "%ld", (long int) ts.tv_usec);
    adata->usec = tmpstr;

    adata->text = in_alert;

    pending_alerts.push_back(adata);
}
