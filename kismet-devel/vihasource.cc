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

#include "vihasource.h"

#ifdef HAVE_VIHAHEADERS

int VihaSource::OpenSource(const char *dev, card_type ctype) {
    pthread_t read_loop;

    snprintf(type, 64, "Viha Mac OSX airport card");
    cardtype = ctype;

    /* Open source */
    wlsource = new WLPacketSource(11);
    wlsource->open();
    wldi = wlsource->getDriverInterface();

    /* Make pipe */
    if ( pipe(pipe_fds) < 0 ) {
        snprintf(errstr, 1024, "VihaSource could not create pipe: %d %s",
                 errno, strerror(errno));
        return -1;
    }

    // Initialize our locking controls
    frame_full = 0;
    frame = NULL;
    pthread_mutex_init(&capture_lock, NULL);
    pthread_cond_init(&capture_wait, NULL);

    /* Start read loop */
    pthread_create(&read_loop, NULL, ReadPacketLoop, this);

    return 1;
}

int VihaSource::CloseSource() {
    /* Stop capture */
    wlsource->close();
    delete wlsource;

    /* Unlock the capture so he can exit */
    pthread_mutex_unlock(&capture_lock);

    close(pipe_fds[0]);
    close(pipe_fds[1]);

    return 1;
}

int VihaSource::SetChannel(unsigned int chan) {

    wldi->stopCapture();
    wldi->startCapture(chan);

    return 1;
}

int VihaSource::FetchChannel() {
    return (wldi->getChannel());
}

int VihaSource::FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    int bytes;
    char byte;

    /* Read byte from pipe */
    read(pipe_fds[0], &byte, 1);

    /* This should never be locked for very long so it shouldn't cause blocking issues */
    pthread_mutex_lock(&capture_lock);
    if (frame_full != 1) {
        // If the frame isn't full something funny is happening since we had a byte in the
        // pipe, but just return 0.  we don't have to sleep since it won't have another byte
        // in the pipe until theres another packet
        pthread_mutex_unlock(&capture_lock);
        return 0;
    }

    if ( frame == NULL ) {

        snprintf(errstr, 1024, "Something bad happened, frame was null. -_-");

        bytes = -1;
    }
    else {
        bytes = Viha2Common(packet, data, moddata);
    }

    frame_full = 0;
    frame = NULL;

    pthread_mutex_unlock(&capture_lock);
    pthread_cond_broadcast(&capture_wait);

    return bytes;
}

int VihaSource::Viha2Common(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    int header_len;
    uint8_t byte;

    /* Alias our frame control */
    frame_control *fc = (frame_control *)&frame->frameControl;
    /* Alias our frame */
    uint8_t *intframe = (uint8_t *)frame;

    /* is it a 4-mac or 3-mac header? */
    if (fc->from_ds && fc->to_ds)
        header_len = 30;
    else
        header_len = 24;

    memset(packet, 0, sizeof(kis_packet));

    gettimeofday(&packet->ts, NULL);

    packet->data = data;

    packet->moddata = moddata;
    packet->modified = 0;

    if ( frame->dataLen + header_len > MAX_PACKET_LEN ) {
        snprintf(errstr, 1024, "Packet was too big. -_-");
        return -1;
    }

    packet->caplen = frame->dataLen + header_len;
    packet->len = packet->caplen;
    packet->signal = frame->signal;
    packet->noise = frame->silence;

    packet->channel = FetchChannel();

    memcpy(packet->data, &intframe[14], header_len);
    memcpy(packet->data+header_len, &intframe[sizeof(WLFrame)], frame->dataLen);

    for ( int i = 0; i < header_len; i+=2 ) {
        byte = data[i];
        data[i] = data[i+1];
        data[i+1] = byte;
    }

    packet->carrier = carrier_80211b;
    packet->datarate = frame->rate;

    if (gpsd != NULL) {
        gpsd->FetchLoc(&packet->gps_lat, &packet->gps_lon, &packet->gps_alt,
                       &packet->gps_spd, &packet->gps_fix);
    }


    return packet->len + header_len;
}

/* Thread proc for blocking readPacket() calls */
void *ReadPacketLoop(void *vsp) {
    char byte = 42;

    VihaSource *vs = (VihaSource *)vsp;

    pthread_detach(pthread_self());

    while ( 1 ) {
        /* Wait until we can fetch a packet */
        pthread_mutex_lock(&(vs->capture_lock));

        /* Has frame been read? */
        if (vs->frame_full != 0) {
            /* Unlock capture lock and wait */
            pthread_mutex_unlock(&(vs->capture_lock));

            pthread_cond_wait(&(vs->capture_wait), &(vs->capture_lock));
            // continue;
        }

        vs->frame_full = 0;
        vs->frame = NULL;
        
        /* Get next frame */
        while ( vs->frame == NULL ) {
            vs->frame = vs->wlsource->readPacket();
        }

        vs->frame_full = 1;

        /* We have a packet.  Unlock ourselves and write a byte to trigger select */
        pthread_mutex_unlock(&(vs->capture_lock));
        write(vs->pipe_fds[1], &byte, 1);

    }

    return NULL;
}

#endif
