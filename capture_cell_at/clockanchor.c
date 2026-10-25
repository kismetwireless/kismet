/* clockanchor.c - host<->modem-RTC clock-anchor record. See clockanchor.h.
 *
 * libc-only, like atlog.c: no Kismet, no serial. JSON escaping is reused from
 * atlog.c (atlog_json_escape) so the two record products escape identically;
 * test_clockanchor links both TUs, exactly as the capture binary does.
 */

#include "clockanchor.h"
#include "atlog.h"   /* atlog_json_escape */

#include <stdio.h>
#include <string.h>

int cclk_extract(const char *resp, char *out, size_t outsz) {
    if (resp == NULL || out == NULL || outsz == 0)
        return -1;
    out[0] = '\0';

    const char *tag = strstr(resp, "+CCLK:");
    if (tag == NULL)
        return -1;

    /* The value is quoted: `+CCLK: "..."`. Find the opening quote after the tag,
     * then copy to the closing quote. Anything the modem puts between them
     * (date, time, signed quarter-hour TZ) is copied verbatim -- we do not parse
     * or normalise it here (see clockanchor.h). */
    const char *open = strchr(tag, '"');
    if (open == NULL)
        return -1;
    open++;
    const char *close = strchr(open, '"');
    if (close == NULL)
        return -1;

    size_t len = (size_t)(close - open);
    if (len + 1 > outsz)
        return -1;
    memcpy(out, open, len);
    out[len] = '\0';
    return 0;
}

/* Escape `s` (NULL -> "") into a caller buffer; returns the buffer. On escape
 * overflow the buffer holds a truncated-but-terminated prefix (atlog_json_escape
 * guarantees NUL-termination), which the bounded record snprintf then further
 * bounds -- a truncated field is preferable to a dropped anchor here, but the
 * buffers below are sized so no legitimate field truncates. */
static const char *esc(const char *s, char *buf, size_t bufsz) {
    if (atlog_json_escape(s ? s : "", s ? strlen(s) : 0, buf, bufsz) < 0)
        buf[bufsz - 1] = '\0';
    return buf;
}

/* One formatter for both shapes: `rtt` NULL is the 9-field record, else
 * host_rtt_ns is appended as the 10th field. */
static int format_record(char *out, size_t outsz,
                         const char *transport, const char *source_name,
                         uint64_t seq, const char *edge,
                         const char *host_utc, uint64_t host_mono_ns,
                         const char *source_clock_kind,
                         const char *source_clock_value, const uint64_t *rtt) {
    char e_transport[32], e_source[512], e_edge[32], e_hostutc[128];
    char e_kind[64], e_value[512];
    char rtt_field[48] = "";

    if (out == NULL || outsz == 0)
        return -1;
    out[0] = '\0';

    if (rtt != NULL)
        snprintf(rtt_field, sizeof(rtt_field), ", \"host_rtt_ns\": %llu",
                 (unsigned long long)*rtt);

    int n = snprintf(out, outsz,
        "{\"schema\": \"clock-anchor/1\", \"transport\": \"%s\", "
        "\"source_name\": \"%s\", \"seq\": %llu, \"edge\": \"%s\", "
        "\"host_utc\": \"%s\", \"host_mono_ns\": %llu, "
        "\"source_clock_kind\": \"%s\", \"source_clock_value\": \"%s\"%s}\n",
        esc(transport, e_transport, sizeof(e_transport)),
        esc(source_name, e_source, sizeof(e_source)),
        (unsigned long long)seq,
        esc(edge, e_edge, sizeof(e_edge)),
        esc(host_utc, e_hostutc, sizeof(e_hostutc)),
        (unsigned long long)host_mono_ns,
        esc(source_clock_kind, e_kind, sizeof(e_kind)),
        esc(source_clock_value, e_value, sizeof(e_value)),
        rtt_field);

    if (n < 0 || (size_t)n >= outsz) {
        out[0] = '\0';
        return -1;
    }
    return 0;
}

int clockanchor_format_record(char *out, size_t outsz,
                              const char *transport, const char *source_name,
                              uint64_t seq, const char *edge,
                              const char *host_utc, uint64_t host_mono_ns,
                              const char *source_clock_kind,
                              const char *source_clock_value) {
    return format_record(out, outsz, transport, source_name, seq, edge,
                         host_utc, host_mono_ns, source_clock_kind,
                         source_clock_value, NULL);
}

int clockanchor_format_record_rtt(char *out, size_t outsz,
                                  const char *transport, const char *source_name,
                                  uint64_t seq, const char *edge,
                                  const char *host_utc, uint64_t host_mono_ns,
                                  const char *source_clock_kind,
                                  const char *source_clock_value,
                                  uint64_t host_rtt_ns) {
    return format_record(out, outsz, transport, source_name, seq, edge,
                         host_utc, host_mono_ns, source_clock_kind,
                         source_clock_value, &host_rtt_ns);
}

void clockanchor_bracket(const struct timeval *tv_ref, uint64_t mono_ref,
                         uint64_t mono_lo, uint64_t mono_hi,
                         struct timeval *tv_mid, uint64_t *mono_mid,
                         uint64_t *rtt_ns) {
    uint64_t width = mono_hi > mono_lo ? mono_hi - mono_lo : 0;
    uint64_t mid = mono_lo + width / 2;
    uint64_t ahead = mid > mono_ref ? mid - mono_ref : 0;
    uint64_t usec = (uint64_t)tv_ref->tv_usec + ahead / 1000ULL;

    tv_mid->tv_sec  = tv_ref->tv_sec + (time_t)(usec / 1000000ULL);
    tv_mid->tv_usec = (suseconds_t)(usec % 1000000ULL);
    *mono_mid = mid;
    *rtt_ns = width;
}
