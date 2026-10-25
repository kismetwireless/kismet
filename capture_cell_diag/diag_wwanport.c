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

    See diag_wwanport.h for what this is and why there are two conventions.
*/

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "diag_wwanport.h"

/* Mainline wwan port-type tokens, from drivers/net/wwan/wwan_core.c's
 * wwan_port_types[]. Kept as a table rather than a chain of strstr() calls so
 * that adding a future type is a one-line change and so the DIAG entry sits
 * visibly alongside the ones it must NOT be confused with. */
static const struct {
    const char *token;
    const char *label;
    int is_diag;
    int is_at;
} kMainlineTypes[] = {
    { "qcdm",     "diag",     1, 0 },   /* Qualcomm DIAGnostic Monitor == DIAG */
    { "at",       "at",       0, 1 },
    { "mbim",     "mbim",     0, 0 },
    { "qmi",      "qmi",      0, 0 },
    { "firehose", "firehose", 0, 0 },
    { "xmmrpc",   "xmmrpc",   0, 0 },
};

/* Out-of-tree MHI channel names. Uppercase on the wire; matched
 * case-insensitively because vendor trees are not consistent about it.
 *
 * QDSS is listed EXPLICITLY as not-DIAG. It is the Qualcomm Debug Subsystem
 * trace channel: it opens cleanly and never answers a LOG_CONFIG, so selecting
 * it produces exactly the 20 s-per-exchange timeout this detection exists to
 * prevent -- and the failure looks like a broken modem, not a wrong port. */
static const struct {
    const char *chan;
    const char *label;
    int is_diag;
    int is_at;
} kMhiChannels[] = {
    { "DIAG",   "diag",     1, 0 },
    { "DUN",    "dun",      0, 1 },   /* Dial-Up Networking == the AT surface */
    { "QMI",    "qmi",      0, 0 },
    { "QMI0",   "qmi",      0, 0 },
    { "MBIM",   "mbim",     0, 0 },
    { "SAHARA", "sahara",   0, 0 },
    { "EDL",    "sahara",   0, 0 },
    { "QDSS",   "trace",    0, 0 },
    { "IP_HW0", "net",      0, 0 },
    { "LOOPBACK", "loopback", 0, 0 },
};

/* Basename of a possibly-full path. Returns a pointer into `node`. */
static const char *basename_of(const char *node) {
    const char *slash = strrchr(node, '/');
    return slash ? slash + 1 : node;
}

static int ci_prefix(const char *s, const char *prefix) {
    while (*prefix) {
        if (tolower((unsigned char)*s) != tolower((unsigned char)*prefix))
            return 0;
        s++; prefix++;
    }
    return 1;
}

/* Resolve a node to (family, is_diag, is_at, label) in one pass; the four public
 * entry points are thin wrappers so they can never disagree about a name.
 *
 * is_diag and is_at come out of the SAME table row, which is the point: the two
 * capture sources ask opposite questions of one classifier, so a node can never
 * be the DIAG port to celldiag and also the AT port to cellat. */
static diag_wwan_family_t classify(const char *node, int *is_diag, int *is_at,
                                   const char **label) {
    if (is_diag)
        *is_diag = 0;
    if (is_at)
        *is_at = 0;
    if (label)
        *label = "unknown";
    if (node == NULL || *node == '\0')
        return DIAG_WWAN_NONE;

    const char *name = basename_of(node);

    /* --- out-of-tree MHI: "mhi_<CHANNEL>[<device index>]" ---------------- */
    if (ci_prefix(name, "mhi_")) {
        const char *chan = name + 4;
        /* The driver appends a device index to every node of a second modem
         * (mhi_DUN1, mhi_DIAG1, mhi_QMI01). So the channel is the LONGEST
         * table name the node starts with, and only digits may follow it:
         * mhi_QMI01 is QMI0 + 1, never QMI + 01, and mhi_DUNX is no channel. */
        size_t best = 0, best_len = 0;
        for (size_t i = 0; i < sizeof(kMhiChannels) / sizeof(kMhiChannels[0]); i++) {
            size_t clen = strlen(kMhiChannels[i].chan);
            if (clen <= best_len || !ci_prefix(chan, kMhiChannels[i].chan))
                continue;
            const char *q = chan + clen;
            while (isdigit((unsigned char)*q))
                q++;
            if (*q != '\0')
                continue;
            best = i;
            best_len = clen;
        }
        if (best_len) {
            if (is_diag)
                *is_diag = kMhiChannels[best].is_diag;
            if (is_at)
                *is_at = kMhiChannels[best].is_at;
            if (label)
                *label = kMhiChannels[best].label;
            return DIAG_WWAN_MHI_OOT;
        }
        /* An mhi_ node with a channel we do not know is still an MHI node -- the
         * family is evidence a modem is present -- but it is NOT assumed to be
         * DIAG. Guessing here is how mhi_QDSS gets selected on a vendor tree
         * that spells it differently. */
        return DIAG_WWAN_MHI_OOT;
    }

    /* --- mainline wwan: "wwan<N><type><M>" ------------------------------ */
    if (ci_prefix(name, "wwan")) {
        const char *p = name + 4;
        /* Skip the device index. Require at least one digit: a bare "wwan0" is
         * the NETWORK interface, not a character device, and must not classify
         * as a port of any kind. */
        if (!isdigit((unsigned char)*p))
            return DIAG_WWAN_NONE;
        while (isdigit((unsigned char)*p))
            p++;
        if (*p == '\0')
            return DIAG_WWAN_NONE;   /* "wwan0" -- the netdev */

        for (size_t i = 0; i < sizeof(kMainlineTypes) / sizeof(kMainlineTypes[0]); i++) {
            const char *tok = kMainlineTypes[i].token;
            size_t tlen = strlen(tok);
            if (ci_prefix(p, tok)) {
                /* The type token must be followed by the per-type index only --
                 * otherwise "at" would match the leading "at" of a longer future
                 * type name and mislabel it. */
                const char *rest = p + tlen;
                if (*rest == '\0')
                    continue;
                int all_digits = 1;
                for (const char *q = rest; *q; q++) {
                    if (!isdigit((unsigned char)*q)) {
                        all_digits = 0;
                        break;
                    }
                }
                if (!all_digits)
                    continue;
                if (is_diag)
                    *is_diag = kMainlineTypes[i].is_diag;
                if (is_at)
                    *is_at = kMainlineTypes[i].is_at;
                if (label)
                    *label = kMainlineTypes[i].label;
                return DIAG_WWAN_MAINLINE;
            }
        }
        return DIAG_WWAN_MAINLINE;   /* wwan port of an unknown type */
    }

    return DIAG_WWAN_NONE;
}

diag_wwan_family_t diag_wwan_classify(const char *node, int *is_diag) {
    return classify(node, is_diag, NULL, NULL);
}

const char *diag_wwan_label(const char *node) {
    const char *label = "unknown";
    classify(node, NULL, NULL, &label);
    return label;
}

int diag_wwan_is_at(const char *node) {
    int is_at = 0;
    if (classify(node, NULL, &is_at, NULL) == DIAG_WWAN_NONE)
        return 0;
    return is_at;
}

int diag_wwan_pick(const char *const *nodes, int n) {
    int found = -1;

    if (nodes == NULL || n <= 0)
        return -1;

    for (int i = 0; i < n; i++) {
        int is_diag = 0;
        if (classify(nodes[i], &is_diag, NULL, NULL) == DIAG_WWAN_NONE)
            continue;
        if (!is_diag)
            continue;
        if (found >= 0)
            return -2;   /* ambiguous -- see the header for why we do not choose */
        found = i;
    }
    return found;
}

void diag_wwan_format(int rc, const char *const *nodes, int n,
                      char *out, size_t outsz) {
    if (out == NULL || outsz == 0)
        return;
    out[0] = '\0';

    int off = 0;
    if (rc == -2) {
        off = snprintf(out, outsz,
                       "Multiple DIAG nodes present on this transport and nothing "
                       "in their names binds one to a specific modem; pass "
                       "diagport=<node> to choose. Found:");
    } else {
        off = snprintf(out, outsz,
                       "No DIAG node found on the wwan/MHI transport (looking for "
                       "a mainline 'wwanNqcdmM' or an out-of-tree 'mhi_DIAG'). "
                       "Seen:");
    }
    if (off < 0)
        return;

    if (n <= 0) {
        snprintf(out + off, outsz - (size_t)off,
                 " (no wwan/MHI nodes at all -- is the modem enumerated, and is "
                 "the MHI/wwan driver loaded?)");
        return;
    }

    for (int i = 0; i < n && (size_t)off < outsz; i++) {
        int is_diag = 0;
        const char *label = "unknown";
        if (classify(nodes[i], &is_diag, NULL, &label) == DIAG_WWAN_NONE)
            continue;
        int w = snprintf(out + off, outsz - (size_t)off, " %s(%s)",
                         basename_of(nodes[i]), label);
        if (w < 0)
            return;
        off += w;
    }
}

/* -----------------------------------------------------------------------
 * Selftest
 * ----------------------------------------------------------------------- */
#ifdef DIAG_WWANPORT_SELFTEST

static int failures = 0;

static void check(int cond, const char *what) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", what);
        failures++;
    } else {
        printf("PASS: %s\n", what);
    }
}

static int is_diag_of(const char *node) {
    int d = 0;
    diag_wwan_classify(node, &d);
    return d;
}

int main(void) {
    /* 1. Mainline wwan: the DIAG port is "qcdm" and NOTHING in its name contains
     * the string "diag". A substring search for "diag" -- the obvious first
     * implementation -- finds the DIAG port on ZERO mainline parts. */
    check(diag_wwan_classify("wwan0qcdm0", NULL) == DIAG_WWAN_MAINLINE,
          "wwan0qcdm0 classifies as a mainline wwan port");
    check(is_diag_of("wwan0qcdm0"), "wwan0qcdm0 IS the DIAG port (qcdm == DIAG)");
    check(strstr("wwan0qcdm0", "diag") == NULL,
          "...and its name contains no 'diag' substring (why the token table exists)");
    check(is_diag_of("/dev/wwan0qcdm0"), "a full /dev path classifies the same");

    /* 2. Its siblings are recognized but are NOT DIAG. Opening wwan0at0 as DIAG
     * would wait out the full LOG_CONFIG deadline per exchange. */
    check(!is_diag_of("wwan0at0"), "wwan0at0 is not DIAG");
    check(!is_diag_of("wwan0mbim0"), "wwan0mbim0 is not DIAG");
    check(!is_diag_of("wwan0qmi0"), "wwan0qmi0 is not DIAG");
    check(!is_diag_of("wwan0firehose0"), "wwan0firehose0 is not DIAG");
    check(diag_wwan_classify("wwan0at0", NULL) == DIAG_WWAN_MAINLINE,
          "a non-DIAG sibling still reports its family (evidence a modem is here)");

    /* 3. The netdev is not a port. "wwan0" is the network interface; classifying
     * it as a port would offer a node that cannot be opened as a character
     * device at all. */
    check(diag_wwan_classify("wwan0", NULL) == DIAG_WWAN_NONE,
          "wwan0 (the netdev) is not a port");
    check(diag_wwan_classify("wwan", NULL) == DIAG_WWAN_NONE,
          "bare 'wwan' is not a port");

    /* 4. Second device index -- a multi-modem PCIe host. */
    check(is_diag_of("wwan1qcdm0"), "wwan1qcdm0 (second modem) is DIAG");
    check(is_diag_of("wwan12qcdm3"), "multi-digit device and port indices parse");

    /* 5. Out-of-tree MHI: here DIAG *is* spelled DIAG, and "qcdm" appears
     * nowhere -- the mirror-image blind spot. */
    check(diag_wwan_classify("mhi_DIAG", NULL) == DIAG_WWAN_MHI_OOT,
          "mhi_DIAG classifies as an out-of-tree MHI node");
    check(is_diag_of("mhi_DIAG"), "mhi_DIAG IS the DIAG node");
    check(is_diag_of("/dev/mhi_diag"), "MHI channel names match case-insensitively");
    check(!is_diag_of("mhi_DUN"), "mhi_DUN (AT) is not DIAG");
    check(!is_diag_of("mhi_QMI0"), "mhi_QMI0 is not DIAG");
    check(!is_diag_of("mhi_SAHARA"), "mhi_SAHARA (EDL) is not DIAG");

    /* 6. THE near-miss that matters. QDSS is the debug-TRACE channel. It opens
     * cleanly and never answers a LOG_CONFIG, so selecting it presents as a
     * broken modem rather than a wrong port, at 20 s per exchange. */
    check(!is_diag_of("mhi_QDSS"),
          "mhi_QDSS (trace) is NOT DIAG -- it opens fine and never answers");
    check(strcmp(diag_wwan_label("mhi_QDSS"), "trace") == 0,
          "mhi_QDSS is labelled 'trace', so a diagnostic says why it was passed over");

    /* 7. An unknown channel on a known family is NOT assumed to be DIAG.
     * Guessing is how a differently-spelled trace channel gets selected. */
    check(diag_wwan_classify("mhi_FUTURECHAN", NULL) == DIAG_WWAN_MHI_OOT,
          "an unknown MHI channel still reports the MHI family");
    check(!is_diag_of("mhi_FUTURECHAN"), "...but is never assumed to be DIAG");
    check(!is_diag_of("wwan0futuretype0"), "same for an unknown mainline port type");

    /* 8. Non-modem nodes decline outright. */
    check(diag_wwan_classify("ttyUSB0", NULL) == DIAG_WWAN_NONE,
          "ttyUSB0 is not a wwan/MHI node (the descriptor path owns it)");
    check(diag_wwan_classify("", NULL) == DIAG_WWAN_NONE, "empty name declines");
    check(diag_wwan_classify(NULL, NULL) == DIAG_WWAN_NONE, "NULL declines");

    /* 9. Selection over a realistic mainline port set. */
    {
        const char *nodes[] = {"/dev/wwan0at0", "/dev/wwan0mbim0",
                               "/dev/wwan0qcdm0", "/dev/wwan0firehose0"};
        int rc = diag_wwan_pick(nodes, 4);
        check(rc == 2, "picks wwan0qcdm0 out of a full mainline port set");
    }
    /* ...and an out-of-tree set, where the DIAG node is not first. */
    {
        const char *nodes[] = {"/dev/mhi_SAHARA", "/dev/mhi_QDSS",
                               "/dev/mhi_DUN", "/dev/mhi_DIAG"};
        int rc = diag_wwan_pick(nodes, 4);
        check(rc == 3, "picks mhi_DIAG past the trace and AT channels");
    }

    /* 10. No DIAG node -> -1, distinct from ambiguity. */
    {
        const char *nodes[] = {"/dev/wwan0at0", "/dev/mhi_QDSS"};
        check(diag_wwan_pick(nodes, 2) == -1, "no DIAG node returns -1");
        check(diag_wwan_pick(NULL, 0) == -1, "empty candidate set returns -1");
    }

    /* 11. TWO DIAG nodes -> -2, reported, never resolved. Unlike ttyUSB, where a
     * sibling AT port anchors selection to one modem by IMEI, nothing in these
     * names binds a node to a device -- so a pick would be a coin flip that
     * presents as a working source bound to the WRONG modem. */
    {
        const char *nodes[] = {"/dev/wwan0qcdm0", "/dev/wwan1qcdm0"};
        check(diag_wwan_pick(nodes, 2) == -2,
              "two DIAG nodes are AMBIGUOUS (-2), not silently resolved");
    }
    {
        const char *nodes[] = {"/dev/mhi_DIAG", "/dev/wwan0qcdm0"};
        check(diag_wwan_pick(nodes, 2) == -2,
              "a mixed-family pair is ambiguous too (two drivers, two modems)");
    }

    /* 12. Diagnostics name what was found and what to do. */
    {
        char buf[512];
        const char *nodes[] = {"/dev/wwan0at0", "/dev/mhi_QDSS"};
        diag_wwan_format(-1, nodes, 2, buf, sizeof(buf));
        check(strstr(buf, "wwan0at0(at)") != NULL &&
              strstr(buf, "mhi_QDSS(trace)") != NULL,
              "the not-found diagnostic lists each node WITH its function");

        const char *amb[] = {"/dev/wwan0qcdm0", "/dev/wwan1qcdm0"};
        diag_wwan_format(-2, amb, 2, buf, sizeof(buf));
        check(strstr(buf, "diagport=") != NULL,
              "the ambiguous diagnostic names the operator's resolution");

        diag_wwan_format(-1, NULL, 0, buf, sizeof(buf));
        check(strstr(buf, "driver loaded") != NULL,
              "zero nodes suggests the driver, not the port -- a different fix");

        /* A tiny buffer must not overflow or leave the string unterminated. */
        char tiny[16];
        diag_wwan_format(-2, amb, 2, tiny, sizeof(tiny));
        check(tiny[sizeof(tiny) - 1] == '\0', "a short output buffer stays NUL-terminated");
    }

    /* 13. The AT surface -- cellat's half of the same classifier.
     * The two families spell it differently, which is why neither source can
     * get away with one glob and a substring test. */
    check(diag_wwan_is_at("wwan0at0"), "wwan0at0 IS the mainline AT port");
    check(diag_wwan_is_at("mhi_DUN"), "mhi_DUN IS the out-of-tree AT port (DUN)");
    check(diag_wwan_is_at("/dev/mhi_dun"), "the AT match is case-insensitive too");
    check(strstr("mhi_DUN", "at") == NULL,
          "...and 'mhi_DUN' contains no 'at' substring -- the mirror blind spot");
    check(strstr("wwan0at0", "dun") == NULL,
          "...nor does 'wwan0at0' contain 'dun' (the other direction)");
    check(diag_wwan_is_at("wwan1at0"), "a second modem's AT port matches");
    check(!diag_wwan_is_at("ttyUSB0"),
          "ttyUSB0 is not a wwan/MHI AT port (the glob path owns it)");
    check(!diag_wwan_is_at(""), "empty name is not AT");
    check(!diag_wwan_is_at(NULL), "NULL is not AT");
    check(!diag_wwan_is_at("wwan0"), "the netdev is not AT");

    /* 14. The refusals that make this a SAFETY filter, not a ranking hint.
     * cellat probes an admitted node by WRITING an AT command to it. These are
     * the nodes where that write is not merely useless. */
    check(!diag_wwan_is_at("mhi_SAHARA"),
          "mhi_SAHARA is NOT AT -- probing it writes ATI into the EDL channel");
    check(!diag_wwan_is_at("mhi_EDL"), "mhi_EDL is NOT AT (same channel, alias)");
    check(!diag_wwan_is_at("wwan0firehose0"),
          "wwan0firehose0 is NOT AT -- the mainline spelling of the same hazard");
    check(!diag_wwan_is_at("mhi_QDSS"), "mhi_QDSS (trace) is NOT AT");
    check(!diag_wwan_is_at("mhi_DIAG"), "mhi_DIAG is NOT AT");
    check(!diag_wwan_is_at("wwan0qcdm0"), "wwan0qcdm0 (DIAG) is NOT AT");
    check(!diag_wwan_is_at("wwan0mbim0"), "wwan0mbim0 is NOT AT");
    check(!diag_wwan_is_at("mhi_QMI0"), "mhi_QMI0 is NOT AT");
    check(!diag_wwan_is_at("mhi_FUTURECHAN"),
          "an unknown MHI channel is never ASSUMED to be AT either");
    check(!diag_wwan_is_at("wwan0futuretype0"),
          "...nor an unknown mainline port type");

    /* 15. DIAG and AT are DISJOINT over every name the tables know. Both flags
     * come from one row, so this cannot drift -- but assert it, because the
     * failure it forbids is the two capture sources fighting over one node. */
    {
        const char *every[] = {
            "wwan0qcdm0", "wwan0at0", "wwan0mbim0", "wwan0qmi0",
            "wwan0firehose0", "wwan0xmmrpc0", "wwan0futuretype0", "wwan0",
            "mhi_DIAG", "mhi_DUN", "mhi_QMI", "mhi_QMI0", "mhi_MBIM",
            "mhi_SAHARA", "mhi_EDL", "mhi_QDSS", "mhi_IP_HW0", "mhi_LOOPBACK",
            "mhi_FUTURECHAN", "ttyUSB0", "",
        };
        int both = 0, at_count = 0, diag_count = 0;
        for (size_t i = 0; i < sizeof(every) / sizeof(every[0]); i++) {
            int d = 0;
            diag_wwan_classify(every[i], &d);
            int a = diag_wwan_is_at(every[i]);
            if (d && a) both++;
            if (a) at_count++;
            if (d) diag_count++;
        }
        check(both == 0, "no node is BOTH the DIAG and the AT function");
        check(at_count == 2, "exactly two names are AT: one per family");
        check(diag_count == 2, "exactly two names are DIAG: one per family");
    }

    /* 16. The out-of-tree MHI driver appends a device index to every node of
     * a second (third, ...) modem: mhi_DUN1, mhi_DIAG1, mhi_QMI01. The channel
     * is the longest table name the node starts with, and only digits may
     * follow it. */
    check(diag_wwan_is_at("mhi_DUN1"), "mhi_DUN1 IS the AT port of MHI device 1");
    check(diag_wwan_is_at("/dev/mhi_DUN1"), "...as a full /dev path too");
    check(strcmp(diag_wwan_label("mhi_DUN1"), "dun") == 0,
          "mhi_DUN1 is labelled 'dun', not 'unknown'");
    check(is_diag_of("mhi_DIAG1"), "mhi_DIAG1 IS the DIAG node of MHI device 1");
    check(is_diag_of("/dev/mhi_diag1"), "an indexed channel matches case-insensitively");
    check(is_diag_of("mhi_DIAG12"), "a multi-digit device index parses");
    check(strcmp(diag_wwan_label("mhi_QMI01"), "qmi") == 0,
          "mhi_QMI01 is QMI0 + index 1, labelled 'qmi'");
    check(!is_diag_of("mhi_QMI01") && !diag_wwan_is_at("mhi_QMI01"),
          "mhi_QMI01 is neither DIAG nor AT");
    check(!is_diag_of("mhi_QDSS1"),
          "mhi_QDSS1 (trace) is NOT DIAG -- an index does not lift the near-miss");
    check(strcmp(diag_wwan_label("mhi_QDSS1"), "trace") == 0,
          "mhi_QDSS1 is labelled 'trace'");
    check(!diag_wwan_is_at("mhi_SAHARA1"), "mhi_SAHARA1 (EDL) is NOT AT");
    check(!diag_wwan_is_at("mhi_BHI1") && !is_diag_of("mhi_BHI1"),
          "mhi_BHI1 (firmware download) is neither AT nor DIAG");
    check(!diag_wwan_is_at("mhi_DUNX"), "mhi_DUNX is NOT AT: only digits may follow");
    check(strcmp(diag_wwan_label("mhi_DUNX"), "unknown") == 0,
          "mhi_DUNX stays an unknown channel");
    check(!is_diag_of("mhi_DIAG1X"), "mhi_DIAG1X is NOT DIAG: a trailing non-digit");
    check(!diag_wwan_is_at("mhi_DUN_1"), "mhi_DUN_1 is NOT AT: '_' is not an index");
    check(diag_wwan_classify("mhi_DUNX", NULL) == DIAG_WWAN_MHI_OOT,
          "...but an unrecognised mhi_ node still reports the MHI family");
    {
        /* A host whose only MHI modem enumerated as device 1. */
        const char *nodes[] = {"/dev/mhi_ADB1", "/dev/mhi_BHI1", "/dev/mhi_DIAG1",
                               "/dev/mhi_DUN1", "/dev/mhi_LOOPBACK1",
                               "/dev/mhi_QMI01"};
        check(diag_wwan_pick(nodes, 6) == 2, "picks mhi_DIAG1 on a device-1-only host");
    }
    {
        /* Two MHI modems: nothing binds either DIAG node to an AT node, so the
         * pick still refuses rather than guess. */
        const char *nodes[] = {"/dev/mhi_DIAG", "/dev/mhi_DUN", "/dev/mhi_DIAG1",
                               "/dev/mhi_DUN1"};
        check(diag_wwan_pick(nodes, 4) == -2,
              "mhi_DIAG + mhi_DIAG1 is ambiguous -- refuse, do not guess");
    }
    {
        const char *indexed[] = {
            "mhi_DIAG1", "mhi_DUN1", "mhi_QMI1", "mhi_QMI01", "mhi_MBIM1",
            "mhi_SAHARA1", "mhi_EDL1", "mhi_QDSS1", "mhi_IP_HW01",
            "mhi_LOOPBACK1", "mhi_ADB1", "mhi_BHI1", "mhi_DUNX", "mhi_DIAG1X",
        };
        int both = 0, at_count = 0, diag_count = 0;
        for (size_t i = 0; i < sizeof(indexed) / sizeof(indexed[0]); i++) {
            int d = 0;
            diag_wwan_classify(indexed[i], &d);
            int a = diag_wwan_is_at(indexed[i]);
            if (d && a) both++;
            if (a) at_count++;
            if (d) diag_count++;
        }
        check(both == 0, "no indexed node is BOTH the DIAG and the AT function");
        check(at_count == 1, "exactly one indexed name is AT (mhi_DUN1)");
        check(diag_count == 1, "exactly one indexed name is DIAG (mhi_DIAG1)");
    }

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    printf("\nPASS: all diag_wwanport tests\n");
    return 0;
}

#endif /* DIAG_WWANPORT_SELFTEST */
