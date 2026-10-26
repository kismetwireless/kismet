/* diag_gsmtap_sink.h - the live GSMTAP UDP sink, natively (gsmtap=).
 *
 * This process frames each GSMTAP-expressible record itself and sends it here.
 * The counters:
 *
 *   sent     -- datagrams handed to the kernel.
 *   declined -- an eligible code whose record produced no frame: no PDU, a
 *               channel with no GSMTAP sub-type (BCCH-BCH), or -- natively --
 *               a code this binary has no framer for yet (`no_framer`, a
 *               subset of declined, reported beside it).
 *   errors   -- the send failed. A transport fault, never a decode one.
 *
 * A code outside the eligible set is not counted at all: it was never a
 * candidate.
 *
 * NEVER BLOCKS. The socket is O_NONBLOCK and the send is called from the DIAG
 * read path: a full socket buffer is a counted error, never a wait (the
 * reader must never be the thread that waits).
 *
 * Pure libc.
 */
#ifndef DIAG_GSMTAP_SINK_H
#define DIAG_GSMTAP_SINK_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

/* The codes with a GSMTAP encoding. LTE RRC
 * and LTE NAS; NR RRC (0xB821) is absent because GSMTAP has no NR-RRC type. */
extern const uint16_t DIAG_GSMTAP_ELIGIBLE_CODES[];
extern const size_t   DIAG_GSMTAP_ELIGIBLE_COUNT;
int diag_gsmtap_eligible(uint16_t code);

typedef struct {
    int      fd;               /* -1 = not open */
    struct sockaddr_in to;     /* the destination, for sendto() */
    char     dest[32];         /* "a.b.c.d:port", for the report */
    uint64_t sent;
    uint64_t declined;
    uint64_t no_framer;        /* of declined: no native framer for the code */
    uint64_t errors;
    int      first_errno;      /* the first send failure, for its one notice */
    int      error_reported;
} diag_gsmtap_sink_t;

/* Open a non-blocking AF_INET datagram socket to `dest` ("a.b.c.d:port", as
 * diag_optset_gsmtap_dest writes it). 0 on success, -1 (errno set) if not. */
int  diag_gsmtap_sink_open(diag_gsmtap_sink_t *s, const char *dest);
void diag_gsmtap_sink_close(diag_gsmtap_sink_t *s);

/* Send one frame. 1 = sent, 0 = failed and counted (errors). Never blocks. */
int  diag_gsmtap_sink_send(diag_gsmtap_sink_t *s, const uint8_t *frame, size_t len);

/* The finish-time report line:
 * "gsmtap <dest> sent=N declined=N errors=N", plus " (no native framer: N)"
 * when any. snprintf contract. */
int  diag_gsmtap_sink_report(const diag_gsmtap_sink_t *s, char *out, size_t outsz);

#endif
