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

#include <memory>

#include "kis_external.h"
#include "kis_external_packet.h"

#include "endian_magic.h"

KisExternalInterface::KisExternalInterface(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

    timetracker = 
        Globalreg::FetchMandatoryGlobalAs<Timetracker>(globalreg, "TIMETRACKER");

    seqno = 0;

    last_pong = 0;

    ping_timer_id = -1;

}

KisExternalInterface::~KisExternalInterface() {
    local_eol_locker el(&ext_mutex);

    timetracker->RemoveTimer(ping_timer_id);

    // If we have a ringbuf handler, remove ourselves as the interface, trigger an error
    // to shut it down, and delete our shared reference to it
    if (ringbuf_handler != NULL) {
        ringbuf_handler->RemoveReadBufferInterface();
        ringbuf_handler->ProtocolError();
        ringbuf_handler.reset();
    }

    // Remove the IPC remote reference
    ipc_remote.reset();
}

void KisExternalInterface::connect_buffer(std::shared_ptr<BufferHandlerGeneric> in_ringbuf) {
    local_locker lock(&ext_mutex);

    if (ringbuf_handler != NULL && ringbuf_handler != in_ringbuf) {
        ringbuf_handler.reset();
    }

    ringbuf_handler = in_ringbuf;
    ringbuf_handler->SetReadBufferInterface(this);
}

void KisExternalInterface::trigger_error(std::string in_error) {
    local_locker lock(&ext_mutex);

    timetracker->RemoveTimer(ping_timer_id);

    // If we have a ringbuf handler, remove ourselves as the interface, trigger an error
    // to shut it down, and delete our shared reference to it
    if (ringbuf_handler != NULL) {
        ringbuf_handler->RemoveReadBufferInterface();
        ringbuf_handler->ProtocolError();
        ringbuf_handler.reset();
    }

    // Remove the IPC remote reference
    ipc_remote.reset();

    BufferError(in_error);
}

void KisExternalInterface::BufferAvailable(size_t in_amt __attribute__((unused))) {
    local_locker lock(&ext_mutex);

    kismet_external_frame_t *frame;
    uint8_t *buf = NULL;
    uint32_t frame_sz, data_sz;
    uint32_t data_checksum;

    // Consume everything in the buffer that we can
    while (1) {
        if (ringbuf_handler == NULL)
            return;

        // See if we have enough to get a frame header
        size_t buffamt = ringbuf_handler->GetReadBufferUsed();

        if (buffamt < sizeof(kismet_external_frame_t))
            return;

        // Peek at the header
        buffamt = ringbuf_handler->PeekReadBufferData((void **) &buf, buffamt);

        // Make sure we got the right amount
        if (buffamt < sizeof(kismet_external_frame_t)) {
            ringbuf_handler->PeekFreeReadBufferData(buf);
            return;
        }

        // Turn it into a frame header
        frame = (kismet_external_frame_t *) buf;

        // Check the frame signature
        if (kis_ntoh32(frame->signature) != KIS_EXTERNAL_PROTO_SIG) {
            ringbuf_handler->PeekFreeReadBufferData(buf);

            _MSG("Kismet external interface got command frame with invalid signature", MSGFLAG_ERROR);
            trigger_error("Invalid signature on command frame");

            return;
        }

        // Check the length
        data_sz = kis_ntoh32(frame->data_sz);
        frame_sz = data_sz + sizeof(kismet_external_frame);

        // If we'll never be able to read it, blow up
        if (frame_sz >= ringbuf_handler->GetReadBufferAvailable()) {
            ringbuf_handler->PeekFreeReadBufferData(buf);

            _MSG("Kismet external interface got command frame too large to ever be read", 
                    MSGFLAG_ERROR);
            trigger_error("Command frame too large for buffer");

            return;
        }

        // If we don't have the whole buffer available, bail on this read
        if (frame_sz < buffamt) {
            ringbuf_handler->PeekFreeReadBufferData(buf);
            return;
        }

        // We have a complete payload, checksum 
        data_checksum = Adler32Checksum((const char *) frame->data, data_sz);

        if (data_checksum != kis_ntoh32(frame->data_checksum)) {
            ringbuf_handler->PeekFreeReadBufferData(buf);

            _MSG("Kismet external interface got command frame with invalid checksum",
                    MSGFLAG_ERROR);
            trigger_error("command frame has invalid checksum");

            return;
        }

        // Process the data payload as a protobuf frame
        std::shared_ptr<KismetExternal::Command> cmd(new KismetExternal::Command());

        if (!cmd->ParseFromArray(frame->data, data_sz)) {
            ringbuf_handler->PeekFreeReadBufferData(buf);

            _MSG("Kismet external interface could not interpret the payload of the "
                    "command frame", MSGFLAG_ERROR);
            trigger_error("unparseable command frame");

            return;
        }

        fprintf(stderr, "debug - KISEXTERNALAPI got command '%s' seq %u sz %lu\n",
                cmd->command().c_str(), cmd->seqno(), cmd->content().length());

        // Consume the buffer now that we're done; we only consume the 
        // frame size because we could have peeked a much larger buffer
        ringbuf_handler->PeekFreeReadBufferData(buf);
        ringbuf_handler->ConsumeReadBufferData(frame_sz);

        // Dispatch the received command
        dispatch_rx_packet(cmd);
    }
}

void KisExternalInterface::BufferError(std::string in_error) {
    close_external();
}

bool KisExternalInterface::launch_ipc() {
    local_locker lock(&ext_mutex);

    std::stringstream ss;

    if (external_binary == "") {
        _MSG("Kismet external interface did not have an IPC binary to launch", MSGFLAG_ERROR);

        return false;
    }

    return true;
}

void KisExternalInterface::close_external() {
    local_locker lock(&ext_mutex);

    timetracker->RemoveTimer(ping_timer_id);

    if (ringbuf_handler != NULL) {
        ringbuf_handler->RemoveReadBufferInterface();
        ringbuf_handler->ProtocolError();
        ringbuf_handler.reset();
    }

    if (ipc_remote != NULL) 
        ipc_remote->soft_kill();

    // Remove the IPC remote reference
    ipc_remote.reset();
}

bool KisExternalInterface::send_packet(std::shared_ptr<KismetExternal::Command> c) {
    local_locker lock(&ext_mutex);

    if (ringbuf_handler == NULL)
        return false;

    uint32_t data_csum;

    // Get the serialized size of our message
    size_t content_sz = c->ByteSize();

    // Calc frame size
    ssize_t frame_sz = sizeof(kismet_external_frame_t) + content_sz;

    // Our actual frame
    kismet_external_frame_t *frame;

    // Reserve the frame in the buffer
    if (ringbuf_handler->ReserveWriteBufferData((void **) &frame, frame_sz) < frame_sz) {
        ringbuf_handler->CommitWriteBufferData(NULL, 0);
        _MSG("Kismet external interface couldn't find space in the output buffer for "
                "the next command, something may have stalled.", MSGFLAG_ERROR);
        trigger_error("write buffer full");
        return false;
    }

    // Fill in the headers
    frame->signature = kis_hton32(KIS_EXTERNAL_PROTO_SIG);
    frame->data_sz = kis_hton32(content_sz);

    // Serialize into our array
    c->SerializeToArray(frame->data, content_sz);

    // Calculate the checksum and set it in the frame
    data_csum = Adler32Checksum((const char *) frame->data, content_sz); 
    frame->data_checksum = kis_hton32(data_csum);

    // Commit our write buffer
    ringbuf_handler->CommitReadBufferData((void *) frame, frame_sz);

    return true;
}

void KisExternalInterface::dispatch_rx_packet(std::shared_ptr<KismetExternal::Command> c) {
    // Simple dispatcher; this should be called by child implementations who
    // add their own commands
    if (c->command() == "MESSAGE") {
        handle_packet_message(c->seqno(), c->content());
    } else if (c->command() == "PING") {
        handle_packet_ping(c->seqno(), c->content());
    } else if (c->command() == "PONG") {
        handle_packet_pong(c->seqno(), c->content());
    } else if (c->command() == "SHUTDOWN") {
        handle_packet_shutdown(c->seqno(), c->content());
    }
}

void KisExternalInterface::handle_packet_message(uint32_t in_seqno, std::string in_content) {
    KismetExternal::MsgbusMessage m;

    if (!m.ParseFromString(in_content)) {
        _MSG("Kismet external interface got an unparseable MESSAGE", MSGFLAG_ERROR);
        trigger_error("Invalid MESSAGE");
        return;
    }

    _MSG(m.msgtext(), m.msgtype());
}

void KisExternalInterface::handle_packet_ping(uint32_t in_seqno, std::string in_content) {
   send_pong(in_seqno);
}

void KisExternalInterface::handle_packet_pong(uint32_t in_seqno, std::string in_content) {
    local_locker lock(&ext_mutex);

    KismetExternal::Pong p;
    if (!p.ParseFromString(in_content)) {
        _MSG("Kismet external interface got an unparseable PONG packet", MSGFLAG_ERROR);
        trigger_error("Invalid PONG");
        return;
    }

    last_pong = time(0);
}

void KisExternalInterface::handle_packet_shutdown(uint32_t in_seqno, std::string in_content) {
    local_locker lock(&ext_mutex);

    KismetExternal::Shutdown s;
    if (!s.ParseFromString(in_content)) {
        _MSG("Kismet external interface got an unparseable SHUTDOWN", MSGFLAG_ERROR);
        trigger_error("invalid SHUTDOWN");
        return;
    }

    _MSG(std::string("Kismet external interface shutting down: ") + s.reason(), MSGFLAG_INFO); 
    trigger_error(std::string("Remote connection requesting shutdown: ") + s.reason());
}

void KisExternalInterface::send_ping() {
    std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());

    c->set_seqno(seqno++);
    c->set_command("PING");

    KismetExternal::Ping p;
    c->set_content(p.SerializeAsString());

    send_packet(c);
}

void KisExternalInterface::send_pong(uint32_t ping_seqno) {
    std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());

    c->set_seqno(seqno++);
    c->set_command("PONG");

    KismetExternal::Pong p;
    p.set_ping_seqno(ping_seqno);

    c->set_content(p.SerializeAsString());

    send_packet(c);
}

void KisExternalInterface::send_shutdown(std::string reason) {
    std::shared_ptr<KismetExternal::Command> c(new KismetExternal::Command());

    c->set_seqno(seqno++);
    c->set_command("SHUTDOWN");

    KismetExternal::Shutdown s;
    s.set_reason(reason);

    c->set_content(s.SerializeAsString());

    send_packet(c);
}

bool KisExternalInterface::Httpd_VerifyPath(const char *path, const char *method) {

    return false;
}

int KisExternalInterface::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    return 0;
}

int KisExternalInterface::Httpd_PostComplete(Kis_Net_Httpd_Connection *con) {
    return 0;
}

