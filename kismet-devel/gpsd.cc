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
#include "gpsd.h"

#ifdef HAVE_GPS

GPSD::GPSD(char *in_host, int in_port) {
    sock = -1;
    lat = lon = alt = spd = hed = 0;
    mode = -1;

    sock = -1;
    errstr[0] = '\0';
    data[0] = '\0';

    host = strdup(in_host);
    port = in_port;
}

GPSD::~GPSD(void) {
    if (sock != -1)
        close(sock);

    sock = -1;
}

char *GPSD::FetchError() {
    return errstr;
}

int GPSD::OpenGPSD() {
    // Find our host
    h = gethostbyname(host);
    if (h == NULL) {
        snprintf(errstr, 1024, "GPSD unknown host '%s'", host);
        return -1;
    }

    // Fill in our server
    servaddr.sin_family = h->h_addrtype;
    memcpy((char *) &servaddr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
    servaddr.sin_port = htons(port);

    // Create the socket
    if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        snprintf(errstr, 1024, "GPSD cannot open socket: %s", strerror(errno));
        return -1;
    }

    // Bind to any local port
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    localaddr.sin_port = htons(0);

    if (bind(sock, (struct sockaddr *) &localaddr, sizeof(localaddr)) < 0) {
        snprintf(errstr, 1024, "GPSD cannot bind port: %s", strerror(errno));
        return -1;
    }

    // Connect
    if (connect(sock, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        snprintf(errstr, 1024, "GPSD cannot connect: %s", strerror(errno));
        return -1;
    }

    // Set nonblocking mode
    int save_mode = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, save_mode | O_NONBLOCK);

    // Kick a command off into the system, too
    if (write(sock, gpsd_command, sizeof(gpsd_command)) < 0) {
        if (errno != EAGAIN) {
            snprintf(errstr, 1024, "GPSD write error: %s", strerror(errno));
            CloseGPSD();
            return -1;
        }
    }

    return 1;
}

int GPSD::CloseGPSD() {
    if (sock != -1)
        close(sock);

    sock = -1;

    return 1;
}

// The guts of it
int GPSD::Scan() {
    char buf[1024];
    int ret;

    if (sock < 0)
        return -1;

    // Read as much as we have
    ret = read(sock, buf, 1024);
    if (ret <= 0 && errno != EAGAIN) {
        snprintf(errstr, 1024, "GPSD error reading data, aborting GPS");
        sock = -1;
        mode = -1;
        return -1;
    }

    // Combine it
    // What's wrong with this?  That's right, we're appending maxbuf to whatever the
    // buf was before.  Very much bad.
    //
    //    strncat(data, buf, 1024);

    // Instead, we'll munge them together safely, AND we'll catch if we've filled the
    // data buffer last time and still didn't get anything, if we did, we eliminate it
    // and we only work from the new data buffer.
    if (strlen(data) == 1024)
        data[0] = '\0';

    char concat[1024];
    snprintf(concat, 1024, "%s%s", data, buf);
    strncpy(data, concat, 1024);

    char *live;
    int scanret;

    if ((live = strstr(data, "GPSD,")) == NULL) {
        return 1;
    }

    //GPSD,P=41.711592 -73.931137,A=49.500000,V=0.000000,M=1
    if ((scanret = sscanf(live, "GPSD,P=%f %f,A=%f,V=%f,M=%d,H=%f",
               &lat, &lon, &alt, &spd, &mode, &hed)) < 5) {

        lat = lon = spd = alt = hed = 0;
        mode = 0;

        return 0;
    }

    // Maybe calc this live in the future?
    if (scanret == 5)
        hed = 0;

    spd = spd * (6076.12 / 5280);

    alt = alt * 3.3;

    // Override mode
    if ((options & GPSD_OPT_FORCEMODE) && mode == 0)
        mode = 2;

    // Zero the buffer
    buf[0] = '\0';
    data[0] = '\0';

    // And reissue a command
    if (write(sock, gpsd_command, sizeof(gpsd_command)) < 0) {
        if (errno != EAGAIN) {
            snprintf(errstr, 1024, "GPSD error while writing data: %s", strerror(errno));
            CloseGPSD();
            return -1;
        }
    }

    return 1;
}

int GPSD::FetchLoc(float *in_lat, float *in_lon, float *in_alt, float *in_spd, float *in_hed, int *in_mode) {
    *in_lat = lat;
    *in_lon = lon;
    *in_alt = alt;
    *in_spd = spd;
    *in_mode = mode;
    *in_hed = hed;

    return mode;
}

#endif
