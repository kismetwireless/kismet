/*
 * cellat_std3gpp.inc -- standard 3GPP AT command decode cores (TS 27.007).
 *
 * Generic 3GPP support plus the AT+COPS=? PLMN scan. These are the
 * VENDOR-NEUTRAL fallback: a modem with no engineering command (no AT+QENG,
 * #RFSTS, AT+CPSI?, AT^SCELLINFO) still answers these, so the source can place a
 * tower and a signal reading from any 3GPP-compliant modem.
 *
 * REQUIRES the shared helpers from cellat_qeng.inc (parse_int, parse_hex,
 * strip_quotes, plmn_split_mccmnc, build_cell_json) and JSON_BUF_MAX -- include
 * this file AFTER cellat_qeng.inc, exactly as cellat_qscan.inc does.
 *
 * Every parse_* fn takes the raw AT response and fills json_out[][JSON_BUF_MAX]
 * with build_cell_json-shaped Cell observation objects, returning the count.
 * All emitted objects carry "observation_type" so phy_cell can attribute the
 * source command, and "is_serving" per the TS 27.007 semantics of the command.
 *
 * Ground truth: captured live from
 * EG25-G (no SIM), LM960A18 (SIM, unregistered), RM520N-GL (SIM, 5G-SA on
 * T-Mobile). See the fixtures in test_cellat_std3gpp.c -- each is a verbatim
 * transcript. CESQ populated-signal conversions are anchored to the TS 27.007
 * mapping tables (neither Quectel supports CESQ; the LM960 was unregistered),
 * and are flagged as such in the test.
 */

/* --- <AcT> / COPS access-technology code -> canonical RAT string (TS 27.007
 * §7.3 <AcT>). Returns a string normalize_rat() also returns, or NULL for a
 * code we do not model. Note this is a SUPERSET of cellat_qeng.inc's
 * cops_rat_name(), which maps only {0,2,7,12} and returns NULL for 11 (NR
 * connected to 5GCN) -- the value a real RM520N-GL reports for 5G-SA. */
static const char *stdat_act_to_rat(long act) {
    switch (act) {
        case 0:  return "GSM";    /* GSM */
        case 1:  return "GSM";    /* GSM Compact */
        case 2:  return "WCDMA";  /* UTRAN */
        case 3:  return "GSM";    /* GSM w/EGPRS */
        case 4:  return "WCDMA";  /* UTRAN w/HSDPA */
        case 5:  return "WCDMA";  /* UTRAN w/HSUPA */
        case 6:  return "WCDMA";  /* UTRAN w/HSDPA and HSUPA */
        case 7:  return "LTE";    /* E-UTRAN */
        case 8:  return "GSM";    /* EC-GSM-IoT (A/Gb mode) */
        case 9:  return "LTE";    /* E-UTRAN (NB-S1 mode) */
        case 10: return "LTE";    /* E-UTRA connected to a 5GCN */
        case 11: return "NR";     /* NR connected to a 5GCN */
        case 12: return "NR";     /* NG-RAN */
        case 13: return "LTE";    /* E-UTRA-NR dual connectivity (LTE anchor) */
        default: return NULL;
    }
}

/* CSQ <rssi> index (TS 27.007 §8.5): 0 -> -113 dBm, step 2 dB, 31 -> -51 dBm.
 * 99 = not known/detectable; 100..199 extended (TD-SCDMA) not modelled here.
 * Returns 1 and sets *dbm on a mappable index, else 0. */
static int stdat_csq_rssi_dbm(long idx, long *dbm) {
    if (idx < 0 || idx > 31)
        return 0;
    *dbm = -113 + 2 * idx;
    return 1;
}

/* CESQ <rsrp> index (TS 36.133): 0 -> < -140 dBm, step 1 dB, 97 -> >= -44 dBm.
 * 255 = not known/detectable. */
static int stdat_cesq_rsrp_dbm(long idx, long *dbm) {
    if (idx < 0 || idx > 97)
        return 0;
    *dbm = -140 + idx;
    return 1;
}

/* CESQ <rsrq> index (TS 36.133): 0 -> < -19.5 dB, step 0.5 dB, 34 -> >= -3 dB.
 * build_cell_json stores rsrq as an integer dB, so we report the half-dB
 * mapping truncated to a whole dB: rsrq_dB = (idx - 40) / 2 (C integer
 * division). idx 34 -> -3, idx 30 -> -5, idx 20 -> -10. 255 = unknown. */
static int stdat_cesq_rsrq_db(long idx, long *db) {
    if (idx < 0 || idx > 34)
        return 0;
    *db = (idx - 40) / 2;
    return 1;
}

/* CESQ <rxlev> index (TS 45.008 RXLEV): 0 -> < -110 dBm, step 1 dB,
 * 63 -> >= -48 dBm. Reported as an RSSI dBm. 99 = unknown. GSM-centric; on an
 * LTE/NR modem this field is almost always 99. */
static int stdat_cesq_rxlev_dbm(long idx, long *dbm) {
    if (idx < 0 || idx > 63)
        return 0;
    *dbm = -110 + idx;
    return 1;
}

/* Locate the value body of an AT response line beginning with `prefix`
 * (e.g. "+CEREG:"). Returns a pointer past the prefix + spaces into a private
 * strtok'd copy, or NULL. The caller owns `*heap` and must free it. */
static char *stdat_find_prefix_body(const char *response, const char *prefix,
                                    char **heap) {
    *heap = NULL;
    char *copy = strdup(response);
    if (!copy)
        return NULL;
    size_t plen = strlen(prefix);
    char *saveptr = NULL;
    char *line = strtok_r(copy, "\n", &saveptr);
    while (line) {
        while (*line == ' ' || *line == '\r')
            line++;
        if (strncmp(line, prefix, plen) == 0) {
            char *body = line + plen;
            while (*body == ' ')
                body++;
            /* trim trailing CR */
            char *cr = strchr(body, '\r');
            if (cr) *cr = '\0';
            *heap = copy;
            return body;
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }
    free(copy);
    return NULL;
}

/* --- CSQ: +CSQ: <rssi>,<ber> --- serving-cell RSSI fallback. --- */
static int parse_csq(const char *response, char json_out[][JSON_BUF_MAX],
                     int max_obs) {
    if (max_obs < 1) return 0;
    char *heap = NULL;
    char *body = stdat_find_prefix_body(response, "+CSQ:", &heap);
    if (!body) return 0;

    char *fields[4];
    int nf = split_fields(body, fields, 4);
    long rssi_idx = 0, rssi_dbm = 0;
    int have_rssi = 0;
    if (nf >= 1 && parse_int(fields[0], &rssi_idx))
        have_rssi = stdat_csq_rssi_dbm(rssi_idx, &rssi_dbm);
    free(heap);

    if (!have_rssi)
        return 0;   /* rssi=99 (unknown) or malformed -> no observable */

    int r = build_cell_json(json_out[0], JSON_BUF_MAX,
                            NULL, NULL, NULL, NULL,
                            0, 0,            /* cell_id */
                            0, 0,            /* pci */
                            0, 0,            /* tac */
                            0, 0,            /* earfcn */
                            0, 0,            /* band */
                            0, 0,            /* bandwidth */
                            0, 0,            /* rsrp */
                            0, 0,            /* rsrq */
                            0, 0,            /* sinr */
                            rssi_dbm, 1,     /* rssi */
                            "csq", 1, NULL);
    return (r > 0) ? 1 : 0;
}

/* --- CESQ: +CESQ: <rxlev>,<ber>,<rscp>,<ecno>,<rsrq>,<rsrp> ---
 * Emits rsrp (LTE, clean integer dBm), rsrq (LTE), and rssi (from rxlev). rscp
 * and ecno (UMTS) are intentionally not emitted: build_cell_json has no field
 * whose semantics they match (ecno != sinr), and the target modems are LTE/NR. */
static int parse_cesq(const char *response, char json_out[][JSON_BUF_MAX],
                      int max_obs) {
    if (max_obs < 1) return 0;
    char *heap = NULL;
    char *body = stdat_find_prefix_body(response, "+CESQ:", &heap);
    if (!body) return 0;

    char *fields[8];
    int nf = split_fields(body, fields, 8);

    long v;
    long rssi_dbm = 0, rsrq_db = 0, rsrp_dbm = 0;
    int have_rssi = 0, have_rsrq = 0, have_rsrp = 0;
    if (nf >= 1 && parse_int(fields[0], &v)) have_rssi = stdat_cesq_rxlev_dbm(v, &rssi_dbm);
    if (nf >= 5 && parse_int(fields[4], &v)) have_rsrq = stdat_cesq_rsrq_db(v, &rsrq_db);
    if (nf >= 6 && parse_int(fields[5], &v)) have_rsrp = stdat_cesq_rsrp_dbm(v, &rsrp_dbm);
    free(heap);

    if (!have_rssi && !have_rsrq && !have_rsrp)
        return 0;   /* all fields 99/255 (unknown) -> no observable */

    int r = build_cell_json(json_out[0], JSON_BUF_MAX,
                            NULL, NULL, NULL, NULL,
                            0, 0,                    /* cell_id */
                            0, 0,                    /* pci */
                            0, 0,                    /* tac */
                            0, 0,                    /* earfcn */
                            0, 0,                    /* band */
                            0, 0,                    /* bandwidth */
                            rsrp_dbm, have_rsrp,     /* rsrp */
                            rsrq_db, have_rsrq,      /* rsrq */
                            0, 0,                    /* sinr */
                            rssi_dbm, have_rssi,     /* rssi */
                            "cesq", 1, NULL);
    return (r > 0) ? 1 : 0;
}

/* --- Registration: +C(E|5G)REG: <n>,<stat>[,"<tac/lac>","<ci>"[,<AcT>...]] ---
 * A record is emitted ONLY when the modem is registered AND reports a cell
 * identity (TAC/LAC or CI). An unregistered read (`+CEREG: 2,0`) carries no
 * cell, hence no observable, so 0 records. `prefix` selects the command
 * ("+CREG:" / "+CEREG:" / "+C5GREG:"); `rat_hint` is the RAT to use when no
 * <AcT> field is present (CREG has none). */
static int parse_reg(const char *response, const char *prefix,
                     const char *rat_hint,
                     char json_out[][JSON_BUF_MAX], int max_obs) {
    if (max_obs < 1) return 0;
    char *heap = NULL;
    char *body = stdat_find_prefix_body(response, prefix, &heap);
    if (!body) return 0;

    char *fields[10];
    int nf = split_fields(body, fields, 10);
    /* fields after split_fields: [0]=<n> [1]=<stat> [2]=<tac> [3]=<ci> [4]=<AcT> ... */

    long stat = -1;
    unsigned long tac = 0, ci = 0;
    long act = -1;
    int have_tac = 0, have_ci = 0, have_act = 0;

    if (nf >= 2) parse_int(fields[1], &stat);
    if (nf >= 3) have_tac = parse_hex(fields[2], &tac);
    if (nf >= 4) have_ci  = parse_hex(fields[3], &ci);
    if (nf >= 5) have_act = parse_int(fields[4], &act);

    const char *rat = rat_hint;
    if (have_act) {
        const char *m = stdat_act_to_rat(act);
        if (m) rat = m;
    }

    /* registered == stat 1 (home) or 5 (roaming); but the load-bearing gate is
     * the presence of a cell identity, which the modem only fills when camped. */
    int registered = (stat == 1 || stat == 5);
    free(heap);

    if (!registered || (!have_tac && !have_ci))
        return 0;

    int r = build_cell_json(json_out[0], JSON_BUF_MAX,
                            rat, NULL, NULL, NULL,
                            ci, have_ci,             /* cell_id */
                            0, 0,                    /* pci */
                            tac, have_tac,           /* tac */
                            0, 0,                    /* earfcn */
                            0, 0,                    /* band */
                            0, 0,                    /* bandwidth */
                            0, 0,                    /* rsrp */
                            0, 0,                    /* rsrq */
                            0, 0,                    /* sinr */
                            0, 0,                    /* rssi */
                            "reg", 1, NULL);
    return (r > 0) ? 1 : 0;
}

/* --- COPS? current operator: +COPS: <mode>[,<format>,"<oper>"[,<AcT>]] ---
 * Emits an operator record. When <format>==2 the <oper> is a numeric PLMN and
 * is split into mcc/mnc. A mode-only read (deregistered, `+COPS: 0`) has no
 * operator, hence 0 records. */
static int parse_cops_query(const char *response, char json_out[][JSON_BUF_MAX],
                            int max_obs) {
    if (max_obs < 1) return 0;
    char *heap = NULL;
    char *body = stdat_find_prefix_body(response, "+COPS:", &heap);
    if (!body) return 0;
    /* Guard against the scan form leaking in here: +COPS: (…) starts with '(' */
    if (*body == '(') { free(heap); return 0; }

    char *fields[6];
    int nf = split_fields(body, fields, 6);

    long fmt = -1, act = -1;
    int have_act = 0;
    const char *oper = NULL;
    if (nf >= 2) parse_int(fields[1], &fmt);
    if (nf >= 3 && *fields[2]) oper = fields[2];   /* already de-quoted */
    if (nf >= 4) have_act = parse_int(fields[3], &act);

    if (!oper) { free(heap); return 0; }

    const char *rat = have_act ? stdat_act_to_rat(act) : NULL;
    char mcc[4] = {0}, mnc[4] = {0};
    const char *mccp = NULL, *mncp = NULL;
    const char *opname = oper;
    if (fmt == 2 && plmn_split_mccmnc(oper, mcc, sizeof(mcc), mnc, sizeof(mnc))) {
        mccp = mcc; mncp = mnc;
        opname = NULL;   /* numeric form carries no human name */
    }

    int r = build_cell_json(json_out[0], JSON_BUF_MAX,
                            rat, NULL, mccp, mncp,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0,
                            "cops", 1, opname);
    free(heap);
    return (r > 0) ? 1 : 0;
}

/* Split an already-extracted COPS scan group body ("2,\"T-Mobile\",...") into
 * fields on commas that are NOT inside double quotes, then de-quote each.
 * Distinct from split_fields (which splits on every comma) because operator
 * names may in principle contain a comma. Returns the field count. */
static int stdat_split_quoted_fields(char *s, char **fields, int max_fields) {
    int count = 0;
    int in_q = 0;
    char *start = s;
    fields[count] = start;
    for (char *p = s; ; p++) {
        if (*p == '"') {
            in_q = !in_q;
        } else if ((*p == ',' && !in_q) || *p == '\0') {
            int last = (*p == '\0');
            *p = '\0';
            if (count < max_fields)
                fields[count] = start;
            count++;
            if (last || count >= max_fields)
                break;
            start = p + 1;
        }
    }
    for (int i = 0; i < count && i < max_fields; i++) {
        while (*fields[i] == ' ') fields[i]++;
        fields[i] = strip_quotes(fields[i]);
    }
    return count;
}

/* --- COPS=? PLMN scan: +COPS: (<stat>,"<long>","<short>","<num>",<AcT>),
 * (…),,(<supported modes>),(<supported formats>) ---
 * One record per operator tuple. A `(…)` group is an operator IFF it contains a
 * double quote -- the trailing capability lists `(0-4),(0-2)` have none and are
 * skipped. <stat>: 0 unknown, 1 available, 2 current, 3 forbidden; is_serving
 * is set only for the current operator (stat 2). */
static int parse_cops_scan(const char *response, char json_out[][JSON_BUF_MAX],
                           int max_obs) {
    char *heap = NULL;
    char *body = stdat_find_prefix_body(response, "+COPS:", &heap);
    if (!body) return 0;

    int count = 0;
    char *p = body;
    while (count < max_obs) {
        char *open = strchr(p, '(');
        if (!open) break;
        char *close = strchr(open, ')');
        if (!close) break;

        size_t glen = (size_t)(close - open - 1);
        char group[512];
        if (glen >= sizeof(group)) glen = sizeof(group) - 1;
        memcpy(group, open + 1, glen);
        group[glen] = '\0';
        p = close + 1;

        /* operator groups contain quoted names; capability lists do not */
        if (!strchr(group, '"'))
            continue;

        char *fields[6];
        int nf = stdat_split_quoted_fields(group, fields, 6);

        long stat = -1, act = -1;
        int have_act = 0;
        if (nf >= 1) parse_int(fields[0], &stat);
        const char *longname = (nf >= 2 && *fields[1]) ? fields[1] : NULL;
        const char *numeric  = (nf >= 4 && *fields[3]) ? fields[3] : NULL;
        if (nf >= 5) have_act = parse_int(fields[4], &act);

        const char *rat = have_act ? stdat_act_to_rat(act) : NULL;
        char mcc[4] = {0}, mnc[4] = {0};
        const char *mccp = NULL, *mncp = NULL;
        if (numeric && plmn_split_mccmnc(numeric, mcc, sizeof(mcc), mnc, sizeof(mnc))) {
            mccp = mcc; mncp = mnc;
        }

        int r = build_cell_json(json_out[count], JSON_BUF_MAX,
                                rat, NULL, mccp, mncp,
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0,
                                "cops_scan", (stat == 2) ? 1 : 0, longname);
        if (r > 0)
            count++;
    }

    free(heap);
    return count;
}

/* --- Generic 3GPP serving-cell merge ---
 * The fallback for a modem with NO engineering command (no QENG/RFSTS/CPSI/...).
 * Merges the standard reads into ONE serving observation: cell identity + RAT
 * from the first registration command that camped (C5GREG->NR, else CEREG->LTE,
 * else CREG), the operator name from COPS?, and signal merged per-field from
 * CESQ (rsrp/rsrq, and rssi from its rxlev) with CSQ filling rssi when CESQ's
 * rxlev is unknown. A record is emitted ONLY when a cell
 * identity (TAC/CI) was obtained -- without it there is no tower to place.
 *
 * Every argument is a raw AT response, or NULL / "" when that command was not
 * run or errored. PURE over its inputs: the runtime gathers the responses and
 * calls this, so the merge is unit-tested (test_cellat_std3gpp) even though a
 * modem with a vendor engineering command never takes the runtime fallback:
 * the `else` branch that calls this fires only on a modem without one. */
static int parse_generic_serving(const char *c5greg, const char *cereg,
                                 const char *creg, const char *cops_q,
                                 const char *cesq, const char *csq,
                                 char json_out[][JSON_BUF_MAX], int max_obs) {
    if (max_obs < 1) return 0;

    /* 1. identity + rat from the first registration command that camped. */
    const char *rat = NULL;
    unsigned long tac = 0, ci = 0;
    int have_tac = 0, have_ci = 0;

    struct { const char *resp; const char *prefix; const char *rat_hint; } regs[3] = {
        { c5greg, "+C5GREG:", "NR" },
        { cereg,  "+CEREG:",  "LTE" },
        { creg,   "+CREG:",   NULL },
    };
    for (int i = 0; i < 3 && !have_tac && !have_ci; i++) {
        if (!regs[i].resp || !*regs[i].resp) continue;
        char *heap = NULL;
        char *body = stdat_find_prefix_body(regs[i].resp, regs[i].prefix, &heap);
        if (!body) { free(heap); continue; }
        char *f[10];
        int nf = split_fields(body, f, 10);
        long stat = -1, act = -1;
        int hact = 0, ht = 0, hc = 0;
        unsigned long t = 0, c = 0;
        if (nf >= 2) parse_int(f[1], &stat);
        if (nf >= 3) ht = parse_hex(f[2], &t);
        if (nf >= 4) hc = parse_hex(f[3], &c);
        if (nf >= 5) hact = parse_int(f[4], &act);
        if ((stat == 1 || stat == 5) && (ht || hc)) {
            have_tac = ht; tac = t;
            have_ci = hc; ci = c;
            rat = regs[i].rat_hint;
            if (hact) { const char *m = stdat_act_to_rat(act); if (m) rat = m; }
        }
        free(heap);
    }

    if (!have_tac && !have_ci)
        return 0;

    /* 2. operator name (+ RAT fallback) from COPS? */
    const char *opname = NULL;
    char opbuf[64] = {0};
    if (cops_q && *cops_q) {
        char *heap = NULL;
        char *body = stdat_find_prefix_body(cops_q, "+COPS:", &heap);
        if (body && *body != '(') {
            char *f[6];
            int nf = split_fields(body, f, 6);
            long fmt = -1, act = -1;
            int hact = 0;
            if (nf >= 2) parse_int(f[1], &fmt);
            if (nf >= 4) hact = parse_int(f[3], &act);
            if (nf >= 3 && *f[2] && fmt != 2) {
                strncpy(opbuf, f[2], sizeof(opbuf) - 1);
                opname = opbuf;
            }
            if (!rat && hact) rat = stdat_act_to_rat(act);
        }
        free(heap);
    }

    /* 3. signal: CESQ preferred (rsrp/rsrq/rssi), else CSQ (rssi). */
    long rsrp = 0, rsrq = 0, rssi = 0;
    int hrsrp = 0, hrsrq = 0, hrssi = 0;
    if (cesq && *cesq) {
        char *heap = NULL;
        char *body = stdat_find_prefix_body(cesq, "+CESQ:", &heap);
        if (body) {
            char *f[8];
            int nf = split_fields(body, f, 8);
            long v;
            if (nf >= 1 && parse_int(f[0], &v)) hrssi = stdat_cesq_rxlev_dbm(v, &rssi);
            if (nf >= 5 && parse_int(f[4], &v)) hrsrq = stdat_cesq_rsrq_db(v, &rsrq);
            if (nf >= 6 && parse_int(f[5], &v)) hrsrp = stdat_cesq_rsrp_dbm(v, &rsrp);
        }
        free(heap);
    }
    if (!hrssi && csq && *csq) {
        char *heap = NULL;
        char *body = stdat_find_prefix_body(csq, "+CSQ:", &heap);
        if (body) {
            char *f[4];
            int nf = split_fields(body, f, 4);
            long idx;
            if (nf >= 1 && parse_int(f[0], &idx)) hrssi = stdat_csq_rssi_dbm(idx, &rssi);
        }
        free(heap);
    }

    int r = build_cell_json(json_out[0], JSON_BUF_MAX,
                            rat, NULL, NULL, NULL,
                            ci, have_ci,             /* cell_id */
                            0, 0,                    /* pci */
                            tac, have_tac,           /* tac */
                            0, 0,                    /* earfcn */
                            0, 0,                    /* band */
                            0, 0,                    /* bandwidth */
                            rsrp, hrsrp,             /* rsrp */
                            rsrq, hrsrq,             /* rsrq */
                            0, 0,                    /* sinr */
                            rssi, hrssi,             /* rssi */
                            "generic", 1, opname);
    return (r > 0) ? 1 : 0;
}
