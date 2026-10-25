# Kismet Cell Tower Capture Source

A cellular modem AT command capture source for Kismet that tracks cell towers
as devices, supporting Quectel and Telit modems via their vendor-specific
engineering AT commands.

## Overview

This patch adds cell tower tracking to Kismet by communicating with cellular
modems over serial AT command interfaces. Each modem becomes a Kismet data
source that periodically queries the modem's engineering mode and reports
visible cell towers (serving and neighbor) as tracked devices.

### Components

| File | Purpose |
|------|---------|
| `capture_cell_at/capture_cell_at.c` | Pure C capture binary — serial I/O, AT parsers, scan scheduler |
| `capture_cell_at/Makefile.in` | Build system for the capture binary |
| `capture_cell_at/profiles/*.json` | Modem profile definitions with command references |
| `phy_cell.h` / `phy_cell.cc` | Cell PHY handler — device tracking, JSON dissection |
| `datasource_cell_at.h` / `datasource_cell_at.cc` | Datasource type registration |
| `http_data/js/kismet.ui.cell.js` | Web UI detail panel and device columns |
| `kis_wiglecsvlogfile.cc` / `.h` | WiGLE CSV export additions |
| `kismet_server.cc` | Server registration (PHY + datasource) |
| `Makefile.in` | Build targets for PHY and datasource objects |

### Data Flow

```
Modem RF → AT Commands → Serial Port → capture_cell_at (C binary)
    → JSON via cf_send_json() → msgpack IPC → Kismet Server
    → phy_cell.cc (dissect JSON, create/update device)
    → Device Tracker → Web UI / Database / WiGLE CSV
```

## Supported Modems

### Quectel RM500Q Series (5G NR + LTE)

**Command Reference:**
- Document: *RG50xQ&RM5xxQ Series AT Commands Manual*
- Filename: `Quectel_RG50xQ_RM5xxQ_Series_AT_Commands_Manual_V1.2.pdf`
- Version: V1.2
- Date: 2021-08-09

**Applicable models:** RM500Q-AE, RM500Q-GL, RM502Q-AE, RM505Q-AE, RM510Q-GL,
RG500Q-EA, RG502Q-EA

**Commands used:**
| Command | Section | Purpose |
|---------|---------|---------|
| `AT+QENG="servingcell"` | §5 Network Service | Serving cell info (LTE or NR5G-SA/NSA) |
| `AT+QENG="neighbourcell"` | §5 Network Service | Intra/inter-frequency LTE neighbor cells |
| `AT+QSCAN=3,1` | §5 Network Service | Full band scan across all enabled bands |

**Serving cell response format (NR5G-SA):**
```
+QENG: "servingcell","state","NR5G-SA","FDD/TDD",MCC,MNC,cellID,PCID,TAC,ARFCN,band,NR_DL_BW,RSRP,RSRQ,SINR,scs,srxlev
```

**Serving cell response format (LTE):**
```
+QENG: "servingcell","state","LTE","FDD/TDD",MCC,MNC,cellID,PCID,EARFCN,band,UL_BW,DL_BW,TAC,RSRP,RSRQ,RSSI,SINR,CQI
```

### Quectel RM520N-GL Series (5G NR + LTE, SDX62)

**Command Reference:**
- Document: *RG520N&RG525F&RG5x0F&RM5x0N Series AT Commands Manual*
- Filename: `Quectel_RG520NRG525FRG5x0FRM5x0N_Series_AT_Commands_Manual_V1.1.pdf`
- Version: V1.1
- Date: 2025-02-20

This is a **distinct profile from RM500Q** — RM500Q is SDX55, RM520N-GL is
SDX62. They share no firmware strings and use different AT manuals.

**Applicable models:** RM520N-GL, RM520N-CN, RM530N-GL, RG520N-NA, RG520N-EB,
RG520N-EU, RG520N-LA, RG520N-GT, RG525F-NA. (The manual also covers the RG520F
and RG530F series; concrete variant names are not enumerated in it.)

**Commands used:**
| Command | Section | Purpose |
|---------|---------|---------|
| `AT+QENG="servingcell"` | §5 Network Service | Serving cell info (LTE or NR5G-SA/NSA) |
| `AT+QENG="neighbourcell"` | §5 Network Service | Intra/inter-frequency LTE neighbor cells |
| `AT+QSCAN=3,1` | §5 Network Service | Full band scan, mixed NR5G/LTE rows |

Serving and neighbor response formats match the RM500Q series (above).

**Divergences from RM500Q:**
- `AT+QCFG="band"` returns ERROR — band read/force moved to
  `AT+QNWPREFCFG` (`"lte_band"`, `"nr5g_band"`, `"nsa_nr5g_band"`).
- NR EN-DC state readable via `AT+QENDC?`.
- `AT+CMEE=2` belongs in setup — the firmware returns bare `ERROR` otherwise.

**Known broken on this firmware:** `AT+CPSI?`, `AT+CNSMOD?` (SIMCom commands),
`AT+CESQ` (ERROR in no-signal state — use `AT+CSQ`), `AT+CNMP?`/`AT+CNBP?`
(use `AT+QNWPREFCFG`), `AT+CSCLK?`.

**DIAG:** the DIAG port is the lowest USB interface (if00) on
the modem's USB device (`2c7c:0801`), auto-detected by IMEI match. The target
log-code mask is `DIAG_TARGET_CODES` in `capture_cell_diag/diag_config.c`
(0xB193, 0xB0C0, 0xB192, 0xB195, 0xB821, 0xB97F). RM520N-GL is the reference
modem for the DIAG capture chain.

### Quectel EG25-G Series (LTE Cat 4)

**Command Reference:**
- Document: *EC2x&EG2x&EG9x&EM05 Series AT Commands Manual*
- Filename: `Quectel_EC2xEG2xEG9xEM05_Series_AT_Commands_Manual_V2.1.pdf`
- Version: V2.1
- Date: 2025-03-21

**Applicable models:** EG25-G, EG25-GL, EC25-AF, EC25-AU, EC25-E, EG91, EG95,
EM05-G, EM05-CE

**Commands used:**
| Command | Section | Purpose |
|---------|---------|---------|
| `AT+QENG="servingcell"` | §6 Network Service | Serving cell info (LTE only) |
| `AT+QENG="neighbourcell"` | §6 Network Service | Intra/inter-frequency LTE neighbor cells |

Note: `AT+QSCAN` is not available on the EC2x/EG2x series. `AT+COPS=?` is
available but has been observed to hang the EG25-G, requiring a power cycle.

### Telit LM960 (LTE Cat 18)

**Command Reference:**
- Document: *LM960/LM960A18 AT Commands Reference Guide*
- Filename: `Telit_LM960_AT_Commands_Reference_Guide_r3.pdf`
- Version: Rev.3
- Date: 2020-01-07

**Applicable models:** LM960, LM960A18

**Commands used:**
| Command | Section | Purpose |
|---------|---------|---------|
| `AT#RFSTS` | §5.6.1 General Configuration | Full serving cell RF status |
| `AT#SERVINFO` | §5.6.1 General Configuration | Compact serving cell info with PCI |

**AT#RFSTS response format:**
```
#RFSTS: "MCC MNC",EARFCN,RSRP,TXPWR,RSRQ,TAC(hex),BAND,,DRX,MIMO,SFN,CellID,"IMEI","Operator",MODE,DUPLEX
```

**AT#SERVINFO response format:**
```
#SERVINFO: EARFCN,RSSI,"operator","MCCMNC",cell_id,TAC,PCI,?,RSRP
```

**Known quirks:**
- `ATI` returns `332` (build number), not the model name. Use `AT+CGMM`.
- Band field `255` in `AT#RFSTS` means "not available" — must be filtered.
- `AT#CSURV` (cell survey) is broken on Generic and TMUS firmware profiles.

### Common 3GPP Commands (All Vendors)

**Standard Reference:** 3GPP TS 27.007

These commands are used for modem identification during the probe/list phase
and work identically across all supported vendors:

| Command | Purpose |
|---------|---------|
| `AT` | Basic modem check |
| `ATE0` | Disable command echo |
| `AT+CGMI` | Manufacturer identification (vendor detection) |
| `AT+CGMM` | Model identification |
| `AT+CGMR` | Firmware revision |
| `AT+CGSN` | IMEI / serial number |
| `AT+COPS=?` | PLMN operator scan (3GPP standard, all vendors) |

## Architecture Decisions

### Why a C capture binary (not Python)

Kismet 2025-09-R1 removed the Python `kismetexternal` protobuf bridge that
earlier datasources used. All capture sources must now be pure C binaries
using the `capture_framework.c` API. The capture binary communicates with the
Kismet server over IPC pipes using msgpack serialization.

The C capture binary follows the same pattern as `capture_sdr_rtl433_v2`:
- Framework handles IPC, threading, and command dispatch
- Capture thread runs the scan loop with blocking serial reads
- `cf_send_json()` queues JSON observations for the server

### Why JSON observations (not packet DLTs)

Cell tower data is metadata — there are no packets to capture. The modem
reports cell identity and signal metrics in AT command responses, which the
capture binary parses into JSON objects. This matches how RTL433, ADSB proxy,
and other non-packet sources work in Kismet.

The JSON type string `"CellModem"` is the type the **source** tags each
observation with, to route it to the Cell PHY handler. It is **not** the type a
kismetdb consumer reads back for most observations — see the next section.

### What `data.type` a kismetdb consumer sees (server re-typing)

**The `data` table's `type` column depends on the promotion outcome; it is
not stable per record kind.** An observation enters as `"CellModem"` (above), but
the server re-types it on the way into the log:

- **`Cellular`** — phy_cell **accepted** the observation: `json_to_cell()` formed a
  valid cell key (RAT plus at least a partial PCI+EARFCN identity). phy_cell then
  attaches a packet metablob typed `"Cellular"` (`phy_cell.cc`
  `set_data("Cellular", …)`), and `kis_databaselogfile.cc` logs a metablob **in
  preference to** the source's own JSON type. Nearly every decoded cell lands
  here: every serving cell, every QMI (`qmifeed`) row, every DIAG row, and every
  neighbour that carried a PCI.
- **`CellModem`** — phy_cell **rejected** the observation (no metablob), so it
  keeps the type the source sent. In practice these are `AT+QENG="neighbourcell"`
  lines that report an EARFCN but **no PCI**: with neither a full identity nor a
  PCI+EARFCN partial, `cell_decisions::derive_key()` returns invalid and the row
  is logged, un-promoted, as `CellModem`.
- **`Cell`** / **`RawAT`** / **`ClockAnchor`** — the PHY's
  pre-rename name, raw AT exchanges, and host↔modem clock anchors. None pass
  through phy_cell, so each keeps its own type.

**A kismetdb consumer must read all of these types, not one.** Filtering
`type='CellModem'` alone sees only the un-keyable EARFCN-only neighbour sightings
and **none** of the serving / QMI / DIAG / PCI-bearing-neighbour stream; filtering
`type='Cellular'` alone silently drops those EARFCN-only neighbours. The blessed
predicate that spans the full stream is `cell_types_where()` in
`log_tools/kismetdb_to_cellndjson.cc` (`Cellular` OR `CellModem` OR `Cell` OR
`RawAT` OR `ClockAnchor`); its count query and export query share the one
predicate so they cannot disagree.

On a typical EG25-G drive with `qmifeed` enabled, roughly half of the
`AT+QENG="neighbourcell"` rows are promoted to `Cellular` (they carried a PCI)
and the rest stay `CellModem` (EARFCN+RAT only, no PCI), while every
serving-cell, QMI and DIAG row is `Cellular`. The split is lossless and intentional:
`CellModem` marks exactly the observations the PHY could not key, so flattening the
two would destroy the accept/reject signal `cell_types_where()` relies on.

### Why pseudo-MAC addresses

Kismet's device tracker requires a MAC address as the primary device key.
Cell towers don't have MAC addresses, so we generate a deterministic
pseudo-MAC from the cell key string (MCC+MNC_TAC_CellID) using
`adler32_checksum` with the locally-administered bit set.

This is the same approach used by:
- `phy_adsb.cc` — ICAO hex code → pseudo-MAC via `icao_to_mac()`
- `phy_radiation.cc` — radiation sensor ID → pseudo-MAC

The web UI overrides the Address column to display the Cell Key instead of
the synthetic MAC for cell devices.

### Why ARFCN-to-frequency conversion

Modems report channel numbers (EARFCN for LTE, NR-ARFCN for 5G NR), not
frequencies. Kismet's device tracker and UI expect frequency in kHz.

The conversion functions implement:
- **NR-ARFCN:** 3GPP TS 38.104 Table 5.4.2.1-1 (three-range formula)
- **LTE EARFCN:** 3GPP TS 36.101 Table 5.7.3-1 (per-band offset table, ~50 bands)
- **WCDMA UARFCN:** Simplified 200 kHz step conversion

### Vendor detection strategy

The capture binary identifies modem vendors at runtime without requiring
user configuration:

1. Send `AT+CGMI` — returns manufacturer name ("Quectel" or "Telit")
2. Probe vendor-specific commands to confirm capabilities:
   - Quectel: `AT+QENG="servingcell"` → look for `+QENG:` response
   - Telit: `AT#RFSTS` → look for `#RFSTS:` response
3. Fall back to probing if `AT+CGMI` is ambiguous

This means the same binary handles all supported modems without
command-line flags or manual vendor selection.

### Cell key format and device merging

Cell towers are identified by a composite key: `{MCC}{MNC}_{TAC}_{CellID}`
(e.g., `310410_36103_173570843`). When multiple modems see the same tower,
Kismet's device tracker merges the observations automatically because they
hash to the same pseudo-MAC.

For neighbor cells (which lack MCC/MNC/TAC), the key falls back to
`{RAT}_pci{PCI}_f{FREQ_KHZ}` — less specific but sufficient for tracking.

The partial key carries the **resolved downlink frequency**, not the raw
EARFCN. LTE band 4 is a subset of band 66: the same 2145 MHz
carrier is EARFCN 2300 to a Quectel (`AT+QENG` reports B4) and 66786 to a Telit
(`AT#MONI` reports B66). Keyed on the raw value, two modems would track
**one tower as two devices**, splitting `observation_count`, the
RSRP range and the `seen_via` provenance between the halves. B2/B25 and
B12/B17/B85 overlap the same way. The reported band and EARFCN are kept as
display fields — they are genuine per-vendor observation data — they just do
not partition identity.

An ARFCN outside every band table range cannot be converted and falls back to
`{RAT}_pci{PCI}_e{ARFCN}`. The `f`/`e` tag is load-bearing: an NR-ARFCN reaches
3279165, so a bare number would be ambiguous between the two forms (and between
these keys and older raw-ARFCN ones).

### Observation types

Every cell observation carries an `observation_type` field describing how
complete the record is:

| Type | `is_serving` | Identity level | Sources |
|------|--------------|----------------|---------|
| `serving` | true | Full (MCC/MNC/CID/TAC/PCI) | All vendors' serving cell commands |
| `serving_secondary` | true | Partial (PCI+EARFCN) | Quectel 5G NSA secondary carrier |
| `observation` | false | Signal only (PCI+EARFCN+RSRP) | Neighbor reports, passive scans, surveys |
| `survey` | false | Full (from network survey) | Telit `AT#CSURVC` 11-field records |

Identity level is what decides the device type in Kismet: a full-identity
observation makes a **Cell Tower**, a PCI+EARFCN-only one makes a **Cell
Node**. This is the same split as the two key formats above — Cell Towers get
the composite `{MCC}{MNC}_{TAC}_{CellID}` key, Cell Nodes the partial
`{RAT}_pci{PCI}_f{FREQ_KHZ}` one.

A Cell Node is **promoted** to a Cell Tower when a full-identity observation
for it arrives — the same physical tower is often first seen as a neighbor
report and only later camped on.

### Scan strategies

Four scan profiles balance data thoroughness vs. serial port load. The full
list, intervals and labels live in one table in `cellat_options.c`; see
[Scan Strategies](#scan-strategies-1) below for what each is for.

| Strategy | Serving | Neighbor | Full Scan |
|----------|---------|----------|-----------|
| `driving` (default; `wardrive` still accepted) | 2s | 5s | — |
| `walking` | 2s | 5s | 300s |
| `stationary` | 2s | 5s | 60s |
| `serving_only` | 2s | — | — |

Driving is the default because full band scans block the serial port for up to
3 minutes, which at road speed is kilometres with no serving cell tracked.

## Modem Profile JSON Schema

Profile files in `profiles/` document modem-specific AT command sets and scan
configurations. Each profile includes:

```json
{
    "vendor": "quectel",
    "model": "rm500q",
    "firmware_match": "RM500Q*",
    "applicable_models": ["RM500Q-AE", "RM500Q-GL", ...],
    "command_reference": {
        "document": "Document title",
        "filename": "filename.pdf",
        "version": "V1.2",
        "date": "YYYY-MM-DD"
    },
    "capabilities": { ... },
    "lifecycle": { "setup": [...], "verify": [...], "shutdown": [...] },
    "scans": { ... }
}
```

The scan **profiles** (driving / walking / stationary / serving_only) are not
in these files: the table in `cellat_options.c` is the one list, and whether a
modem can run a full scan is probed at open (`fullscan_capable`). Keeping
the profiles out of these files means there is no second copy to drift.

The `command_reference` field identifies the vendor AT command manual that
documents the commands used in the profile. The `applicable_models` list
enumerates all modem variants that share the same AT command set.

Currently the C capture binary hardcodes vendor detection rather than loading
these profiles at runtime. The profiles serve as authoritative documentation
of which commands work on which modems and where the command format is
specified.

## Building from Source

### Prerequisites

Standard Kismet build dependencies — if you can build Kismet from source,
you already have everything needed. No additional libraries are required
for the cell modem capture source.

The capture binary links against `libkismetdatasource.a` (Kismet's capture
framework library) using only POSIX serial I/O (termios) and the libraries
already required by the framework (`libcap`, `libwebsockets`).

### Build Steps

```bash
# From the top of this Kismet source tree:

# Configure (standard Kismet configure — cell modem has no extra flags)
./configure
make

# Build the capture binary
cd capture_cell_at && make
cd ..

# Install (as root or with appropriate permissions)
sudo make install
```

`make install` installs `kismet_cap_cell_at` into the bin directory and its QMI
feed (`qmifeed/`, below) into `<datadir>/kismet/cell/qmifeed/`, where
`qmifeed=auto` finds it. The feed is Python: it runs only for a source that
sets `qmifeed=` (off by default), so a host without `python3` runs every other
cellat option ([4e](#4e-qmi-cell-feed-qmifeed)).

## Quick Start

### 1. Connect a Modem

Connect a supported USB cellular modem. Quectel modems typically enumerate
as `/dev/ttyUSB0` through `/dev/ttyUSB3` (4 ports); Telit modems enumerate
as `/dev/ttyUSB0` through `/dev/ttyUSB4` (5 ports). The exact port numbers
depend on what other USB serial devices are present.

A SIM card is **not required** — modems will report visible cell towers
even without network registration (limited service mode).

### 2. Determine the AT Command Port

USB cellular modems expose multiple serial ports with different functions
(diagnostics, NMEA GPS, AT commands, PPP data). You need to identify which
port is the AT command port.

**Easiest method — let the capture binary find it:**

```bash
kismet_cap_cell_at --list
```

This probes all `/dev/ttyUSB*` and `/dev/ttyACM*` ports by sending `AT`
and checking for a response. It will identify AT-responding modems by
manufacturer and firmware, and list them:

```
cellat supported data sources:
    cellat-123456789012345 (Quectel RM500Q IMEI:123456789012345)
    cellat-123456789012346 (Quectel EG25 IMEI:123456789012346)
    cellat-123456789012348 (Telit LM960A18 IMEI:123456789012348)
```

Use the interface name (e.g., `cellat-123456789012345`) as the source
definition. Sources are addressed by **IMEI**, never by tty path — the port a
modem lands on shifts between reboots and replugs, the IMEI does not. A modem
that does not report an IMEI is skipped by `--list` because it cannot be
addressed.

**Manual method — check `dmesg` after plugging in the modem:**

```bash
dmesg | grep ttyUSB
```

This shows which USB interface numbers map to which ttyUSB ports. The AT
command port is typically:
- **Quectel modems:** The 3rd port (offset +2 from the base, USB interface 2)
- **Telit LM960:** The 5th port (offset +2 from the base, USB interface 4)

The port numbers shift depending on other USB serial devices on the system.
Always verify after reboots or replugging.

**Alternative — test with a terminal emulator:**

```bash
# Try sending AT to a port and look for OK
echo -e "AT\r" > /dev/ttyUSBN && timeout 2 cat /dev/ttyUSBN
```

If the port responds with `OK`, it's an AT command port.

### 3. Start Kismet with Cell Modem Source

**Option A — command line:**

```bash
kismet -c cellat-123456789012345
```

**Option B — add to a running Kismet instance via the REST API:**

```bash
curl -u user:pass -X POST \
  --data-urlencode 'json={"definition":"cellat-123456789012345:strategy=wardrive"}' \
  http://localhost:2501/datasource/add_source.cmd
```

**Option C — via the Kismet web UI:**

Navigate to `http://localhost:2501`, go to the Data Sources panel, and
add a new source with the definition `cellat-123456789012345`.

### 4. Source Options

Append options to the source definition after a colon:

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `atport` | a `/dev/tty*` path | *(auto-detect by IMEI)* | Open this port instead of scanning. The IMEI is still verified — a mismatch is a hard open error, never a silent survey of the wrong modem. |
| `strategy` | `driving` (alias `wardrive`), `walking`, `stationary`, `serving_only` | `driving` | Scan profile (see below). An unknown value **refuses the open** and names the valid ones. |
| `debug` | `true`, `false` | `false` | Debug mode: extra per-poll messages, the IMSI and ICCID read and logged at debug level, and, if `transcript=` is not set, an automatic AT transcript at `/tmp/kismet_cellat_<IMEI>.log`. `KISMET_CELLAT_DEBUG=1` in the environment turns it on for every source; `debug=` in the definition overrides that. |
| `transcript` | a file path | *(off)* | Write a human-readable raw AT transcript (`[ISO8601] TX:/RX:` text, wall-clock). The file is created mode `0600`, since it carries the modem's identifiers. |
| `atlog` | a file path or directory spec | *(off)* | Write a machine-ingestable **raw AT capture** as JSONL, one host-timestamped record per exchange. See [Raw AT capture](#raw-at-capture-atlog) below. |
| `qmifeed` | `auto`, or a command line | *(off)* | Spawn a QMI cell feed and relay its NDJSON lines as `CellModem` observations beside the AT ones. `auto` runs the feed that ships in `qmifeed/`. **Needs `python3`**: the only cell-source option that starts one. See [QMI cell feed](#4e-qmi-cell-feed-qmifeed) below. |
| `lockstate` | a file path | `$HOME/.kismet/cellat-lock-<imei>.state` | Where the modem's band/RAT settings **as found** are saved before a lock is written. See [Band/RAT lock](#4d-bandrat-lock-the-sources-channels) below. |
| `channel` | a lock channel (`LTE`, `LTE-B66`, …) | `AUTO` | Kismet's own option: lock at bring-up. Only on a lock-capable modem. |

**An option that is not in this table is ignored, and cellat says so.**
Kismet accepts any source option silently, so without a check a misspelled or
invented key is indistinguishable from a working one. Unknown keys are reported
as a warning on the message bus (a warning, not an error: Kismet injects keys this helper
never reads, and failing on those would break on a Kismet upgrade).

Examples:

```bash
kismet -c cellat-ttyUSB3:strategy=stationary
kismet -c cellat-ttyUSB3:strategy=walking,debug=true

# Pin a source to a port when auto-detect picks wrong. Useful on hosts with two
# EG25-Gs: that model exposes no USB serial string, so /dev/serial/by-id has no
# serial segment and the two collide.
kismet -c cellat-123456789012345:atport=/dev/ttyUSB28
```

### 4a. Raw AT capture (`atlog=`)

`atlog=<spec>` tees **every AT command and its full response** to disk as JSONL
— one host-timestamped record per exchange — while cellat is decoding those
same responses into Kismet observations. It exists so that **when a drive goes
wrong you can go back and see exactly what the modem was asked and what it
answered**, byte for byte.

This is a **self-contained, DIAG-independent capture.** You do NOT need a
`celldiag` source, a concurrent DIAG capture, or anything else — an AT-only
drive arms `atlog=` and gets the complete raw record on its own:

```bash
# Pure AT drive: write a raw AT capture and nothing else. No DIAG anywhere.
kismet -c cellat-123456789012345:atlog=/captures/

# A directory spec (trailing '/') synthesizes cellat-<imei>-<ts>.jsonl inside it,
# so multiple modems never collide. A full path or %i/%m/%t template also works:
kismet -c cellat-ttyUSB3:atlog=/captures/cellat-%i-%t.jsonl
```

Path templating: `%i` → IMEI, `%m` → model (sanitized), `%t` → UTC
`YYYYmmddTHHMMSSZ`, `%%` → literal `%`.

Each line is one record:

```json
{"ts_mono_ns": 402931118273, "ts_utc": "2026-09-21T16:51:03.412887Z",
 "cmd": "AT+QENG=\"servingcell\"", "response": "+QENG: ...\r\n\r\nOK\r\n",
 "duration_ms": 38.75, "err": null}
```

- `ts_mono_ns` — host `CLOCK_MONOTONIC` nanoseconds. Monotonic, so an NTP step
  mid-drive cannot reorder exchanges. This is the record's ordering axis.
- `ts_utc` — wall-clock (ISO 8601, microseconds), secondary.
- `cmd` / `response` — the exact command sent and the full raw response, JSON-escaped.
- `duration_ms` — exchange wall time. `err` — `null`, or an error string.

**Why JSONL and not `transcript=`?** `transcript=` is a human-readable debug log
(TX:/RX: text). `atlog=` is a **data product** — every consumer reads it with a
one-line `json.loads` per line, no parser. It is written uncompressed live;
`post_capture.py` compresses it to `.zst` afterward (do not gzip inline).

**Bonus — DIAG correlation.** The record schema matches
the offline DIAG/AT correlator, so *if* you happened to run a DIAG capture at
the same time, the shared `ts_mono_ns` lets the offline correlator align AT
exchanges to DIAG frames (which carry no host clock) with no shim. That is an
optional consumer of an already-complete AT capture — never a requirement for
producing one.

### 4b. What the source reports about itself (`cellat_stats`)

Every 5 s, and immediately around a blocking full scan, the helper sends a
`cellat_stats` control line. The server turns it into
`kismet.datasource.cellat.*` fields in `/datasource/all_sources.json`, and the
web UI renders them on the source's detail panel.

| Field | Meaning |
|---|---|
| `state` | `surveying`, `full_scan` (a blocking AT+QSCAN / AT#CSURVC; `fullscan_started_epoch` says since when), or `disabled` (`enabled=false`, no port opened) |
| `strategy`, `strategy_label`, `*_interval_ms` | the armed profile and the intervals **in force** |
| `strategies` | the profiles this binary accepts, `name,label,fullscan_s;…` (the panel's selector is built from it) |
| `fullscan_capable` | the modem has a full-scan command |
| `obs_total`, `obs_per_sec`, `last_obs_epoch` | observations **sent** to Kismet |
| `rawat_records`, `rawat_dropped` | RawAT rows into the kismetdb |
| `atlog_path`, `atlog_active`, `atlog_records`, `atlog_dropped` | the `atlog=` tee |
| `anchor_count`, `anchor_last_epoch` | ClockAnchor rows |
| `lock_capable`, `lock_channel`, `lock_error` | band/RAT lock: whether the modem has it, the lock **in force** (`AUTO` = the settings as found), and why the last lock or restore failed (`""` = none) |
| `at_port`, `model`, `firmware` | what was opened |
| `stats_epoch`, `stats_interval_s` | when the line was made, and the cadence |

**A value the helper has not measured is omitted, never sent as 0.** Kismet
still serialises every registered field, so an unmeasured one shows up as its
default (`""` / `0`). Read `stats_epoch == 0` as "nothing reported yet",
`atlog_path == ""` as "no tee configured", and `last_obs_epoch == 0` as "no
observation yet". The web panel applies the same rules.

### 4c. Changing settings on a running source

Three settings can change **without restarting** the source, through Kismet's
runtime setter (`POST /datasource/by-uuid/<uuid>/set_channel.cmd` with
`{"channel": "<key>=<value>"}`) or the web panel's controls:

| Setting | Effect |
|---|---|
| `strategy=<profile>` | switch the scan profile at the next poll; the last-run stamps are cleared, so a switch to `stationary` scans at once |
| `atlog=<path or dir/>` / `atlog=off` | start, redirect or stop the raw AT log. A stop keeps the path; a redirect to an unwritable path keeps the log already running |
| `clock_anchor_sec=<n>` | change the ClockAnchor cadence (`0` = periodic off) |

`atport=`, `enabled=`, `debug=`, `transcript=` and `uuid=` are open-time only.
Sent at runtime they are refused *with that reason*, not as unknown options.
Change them by closing the source, updating its definition
(`update_definition.cmd`), and re-opening it. The panel's **Enable/Disable
capture** control does exactly that for `enabled=`.

**The HTTP reply cannot tell you whether a setting applied.** A refused
setting still answers success, because a negative return from the helper would
tear the source down. The reason goes to the message bus, and the
outcome shows in the `cellat_stats` fields within one interval.

**A setting is not a channel.** A string with no `=` (`LTE`, `LTE-B66`) is a
**channel**: a band/RAT lock (next section). A `key=value` setting is never
recorded as the source's channel, so the server neither shows
`strategy=walking` as "the channel" nor re-applies it after an error re-open —
and a setting sent while the source is hopping does not stop the hop (the
capture framework cancels a hop only for a channel).

**A runtime choice survives a reopen, and lasts until Kismet restarts.**
After any reopen of an enabled source — the panel's
Capture switch, the whole-modem switch, or Kismet's automatic re-open after a
helper error — the server re-sends the `strategy=` and `atlog=` state the
operator changed at runtime, and says so on the bus (`re-applying its runtime
choices …`). What it re-sends is the helper's **readback** of what
actually ran (`cellat.strategy`, `atlog_path`, `atlog_active`), never the last
string sent, because a refused setting also answers success: `strategy=bogus`
after `strategy=walking` restores `walking`. An `update_definition` of the same
key is the operator re-specifying it, and the definition wins.
`clock_anchor_sec=` is not carried (it has no readback field).

### 4d. Band/RAT lock: the source's channels

The Wi-Fi source's channel buttons, Lock and Hop, for a cell modem. Five
command families are probed at open, each only on its vendor and never assumed
from the vendor alone:

| Family | Modems | Channels |
|---|---|---|
| `AT+QNWPREFCFG` | Quectel RM500Q / RM520N-GL and siblings | all of the table below |
| `AT+QCFG` `"nwscanmode"` + `"band"` | Quectel EG25-G / EC2x (where QNWPREFCFG answers ERROR) | `AUTO`, `LTE`, `LTE-B<n>` for each band in the mask as found. Only the LTE mask is written: GSM/WCDMA and TD-SCDMA go as `0`, which the QCFG manual defines as "no change" |
| `AT!SELRAT` | Sierra EM9190 / EM9291 | `AUTO`, `LTE`, `NR5G`. The index is read **by name** from `AT!SELRAT=?` ("LTE Only" is 04 on 01.07.19 and 06 on 03.17.04). An EM9291 on SWIX65C_02.17.08.00 reports the 03.17.04 table (06 / 20); an LTE lock reaches normal service by the first 2 s poll, and a restore to the as-found index takes 2–4 s |
| `AT+WS46` | Telit LM960 and other 3GPP-WS46 modems | `AUTO`, `LTE` (28), `NR5G` (35) where `AT+WS46=?` lists them. The LM960 offers `(22,28,31)` |
| `AT+CNMP` | SIMCom SIM8202G-M2 and other SIMCom parts | `AUTO`, `LTE` (38), `NR5G` (71) where `AT+CNMP=?` lists them. On a SIM8202G-M2 (LE13B04SIM8202M44A-M2) each write applies at once (LTE camp in about 2.6 s, NR SA in about 2 s), and `2` restores the as-found every-RAT mask exactly. A modem that **reads `100`** ("UNKNOW", a RAT mix with no CNMP mode) is offered **no** lock: it lists `100` in `=?` but answers ERROR to `AT+CNMP=100`, so the lock could not be undone. The reason is on the bus |

On a Quectel the open reports these **channels**:

| Channel | Means |
|---|---|
| `AUTO` | the modem's settings **as found** at open (the default) |
| `LTE` | LTE only, every LTE band it had enabled |
| `NR5G` | NR standalone only, every NR band it had enabled (only if it reported a usable NR SA band list) |
| `LTE-B<n>` | LTE only, band *n* only — one per band it had enabled |
| `NR-n<n>` | NR SA only, band *n* only |
| `LTE-B<n>+<m>…` / `NR-n<n>+<m>…` | exactly that **set** of bands, e.g. `LTE-B2+4+12+66`. One channel, so a Lock target and a Hop element like any preset; every band must be one the modem had enabled as found; malformed sets (`B2++4`, `B2+2`, `B02`) are refused. Not advertised as a preset (the sets are combinatorial): set it by `channel=` or `set_channel`. At most 63 characters — a longer set is refused whole, never truncated. On an EG25-G (`AT+QCFG`) the set's bits are OR'd into the one LTE mask |

- **Lock**: `POST /datasource/by-uuid/<uuid>/set_channel.cmd` with
  `{"channel": "LTE-B66"}`, the panel's **Band / RAT lock** row, or
  `channel=LTE-B66` in the definition. The lock is written band list first,
  then the RAT, and is the source's `kismet.datasource.channel`.
- **After a reopen**: Kismet's automatic
  re-open after a helper **error** re-applies the lock in force, as a Wi-Fi
  source keeps its locked channel. An **explicit** Capture or whole-modem
  off/on comes back `AUTO`, the modem as found — an operator's off means off.
  Kismet's own error-retry replay of `get_source_channel()` does not do this
  for cellat, although it looks as if it should: the new helper's open report
  resets the channel to `AUTO` before that callback runs, so a killed helper
  would come back unlocked. The cellat datasource re-applies the lock itself.
- **Hop**: `{"channels": ["LTE-B2","LTE-B66"], "rate": 0.0167}` (rate = locks
  per second; 1/60 is one a minute) or the panel's Hop control: one lock per
  step, a synthetic slow scan. Each lock re-registers the modem, a few
  seconds without service, so the panel will not dwell under 5 s. The first
  lock lands one dwell AFTER Hop is pressed (Kismet's hop timer fires at the
  end of an interval), and until then the lock row still reads `AUTO`.
  A RAT-only lock is only as useful as the coverage: where no NR SA cell is
  in reach, an `NR5G` lock leaves the modem in PLMN search with no service for
  the whole dwell (an EM9291 stays there for at least 180 s), so an `NR5G` hop
  leg there is dead air that yields no observations.
- The source is **never hopped automatically**. It opens with
  `channel_hop=false` unless you set `channel_hop=` yourself; a global
  `channel_hop=true` at several hops a second would re-lock the modem
  continuously.
- `stats`: `lock_channel` is the lock **in force**, as written — not what was
  asked for. A write the modem refused, or that failed, is in `lock_error`
  and on the bus. A request refused *before* any write (a band the modem had
  not enabled, a malformed or over-long set, a modem with no lock support) is
  on the bus only: nothing was written, so the lock in force and `lock_error`
  are unchanged (for example `LTE-B2+66+71` on an RM500Q whose as-found list
  lacks B2).

**Every lock is written to the modem's NV and survives a reboot.** So:

1. Nothing is written at open. `AUTO` writes nothing until something else has.
2. Before the first write, the settings as found go to the `lockstate=` file.
   If that file cannot be written, the lock is refused.
3. `AUTO`, and every close (a graceful Kismet close, and the error exit),
   restore the settings as found and remove the file.
4. A helper that was killed (Kismet's hard stop sends SIGTERM, which runs no
   teardown) leaves the file behind. The **next open restores from the file**,
   before anything else, because the modem's own reading is the locked one.
5. A state file for another IMEI, or one that is malformed, is never used or
   overwritten: locking is disabled for that session and the reason is on the
   bus.

The state file records the family (`backend=`) as well as the IMEI; a file
from another family is never restored through this one. Other vendors and
levers report no channels yet. Telit `AT#BND` band locks need a
CFUN cycle and a 30 s read; SIMCom band locks (`AT+CNBP` / `AT+CBANDCFG`)
are not wired up.

### 4e. QMI cell feed (`qmifeed=`)

QMI carries cell data AT cannot: the NR Cell Identity Telit's `AT#RFSTS` omits,
and full cell identity on Sierra parts whose `AT+CEREG` / `AT+CSQ`
return ERROR. `qmifeed=<command>` spawns a child that writes one
`build_cell_json`-shaped observation per stdout line; each line is relayed to
the server as a `CellModem` record, exactly like an AT observation. The feed
stamps `"prov":{"src":"qmi",...}`, so `phy_cell` merges it with the AT and DIAG
sightings of the same tower (`seen_via`) with no server change.

> ⚠️ **`qmifeed=` needs Python.** It is the one
> option on either cell source that starts a `python3`: the feed below is a
> Python program. cellat's default (no `qmifeed=`) starts none, and
> `kismet_cap_cell_diag`'s default (`nativedecode=only`) starts none either, so
> a host with no `python3` runs both sources and loses only the QMI rows. The
> feed is outside the zero-Python path on purpose, not by omission; porting it
> to C is not planned.

The feed ships in this directory as `qmifeed/kismet_qmi_feed.py`. It
needs only `python3` (standard library) and `qmicli` (libqmi) on `$PATH`, and
polls `--nas-get-cell-location-info` + `--nas-get-signal-info`, opened with
`--device-open-proxy` so it shares the port with ModemManager.
`qmifeed=auto` runs it:

```bash
kismet -c 'cellat-<imei>:atport=/dev/ttyUSB2,qmifeed=auto'
kismet -c 'cellat-<imei>:atport=/dev/ttyUSB2,qmifeed=auto -d /dev/cdc-wdm0 --interval 5'
```

- **`auto` (or `1`)** looks for `qmifeed/kismet_qmi_feed.py` beside
  `kismet_cap_cell_at`, or `capture_cell_at/qmifeed/` beside it, in the
  binary's directory or up to 3 parents, and runs it with the system `python3`.
  Anything after `auto ` is passed to the feed as its own arguments
  (`python3 qmifeed/kismet_qmi_feed.py --help` lists them). With no `-d`, the
  feed picks the `cdc-wdm` whose IMEI matches the source (below). If no feed is
  found, `auto` is refused with a message bus ERROR naming where it looked;
  AT polling carries on. The binary reads its own location from
  `/proc/self/exe` (Linux) or dyld (macOS), so `auto` works from the build
  tree, or anywhere the binary is copied together with `qmifeed/`. A binary
  built by `./configure && make` also looks, last, in the data directory
  `make install` copies the feed to (`<datadir>/kismet/cell/qmifeed/`), so an
  installed `kismet_cap_cell_at` finds it too.
- **Any other value is a command**, run verbatim: a feed of your own, or this
  one under another interpreter.

- **Whose cells these are is checked, twice.** The feed stamps
  `prov.imei` with the IMEI its QMI device reports (DMS), and `cdc-wdm`
  numbering on a multi-modem host is not stable, so `-d` alone could put
  another modem's cells under this source.
  - The capture child exports `CELLAT_IMEI=<the IMEI verified on the AT port>`
    to the feed. `kismet_qmi_feed.py` then polls only a device whose DMS IMEI
    matches: `-d` first, then every detected `cdc-wdm`. A `-d` on another modem
    is re-routed with a note on stderr, and no match exits 3. An inherited
    `CELLAT_IMEI` is replaced, and an unverified source exports none.
  - Every line is checked anyway. A line stamped with another IMEI, or with
    none, is **dropped** and reported once on the message bus (ERROR). The
    feed-exited message counts them. A source with no verified IMEI relays
    unchecked and says so once (INFO). A third-party feed must stamp
    `prov.imei` or relay nothing.
  - `--imei` on the feed is an operator assertion that skips the DMS read; it
    is refused (exit 3) when it contradicts `CELLAT_IMEI`.
  - The feed's re-route note and its refusals reach the **message bus**
    (`#msg` lines, below), prefixed with the source's name; stderr
    still gets them for the console log. A feed that notes every poll is capped
    at 32 bus notes; the rest stay in the console log, and the feed-exited
    message counts them.
- **Raw QMI in the kismetdb.** Every qmicli call the feed makes
  becomes a `RawQMI` row in the `.kismet` `data` table, always on (like
  `RawAT`): argv, rc, stdout, stderr and host-monotonic instants on the same
  clock as `atlog=`. `log_tools/kismetdb_to_qmilog` gives them back as the
  feed's `--qmilog` JSONL, sorted by `ts_mono_ns`; for one source its output
  equals that source's `--qmilog` file record for record, byte for byte. `--qmilog <dir>/` on the feed command still writes the file
  tee, as a debug-outside copy. `--qmilog-wire` adds each QMUX frame's full
  bytes via `qmicli --verbose-full`, in both sinks; it carries the IMEI and
  costs about 10 KB per call. The Sources panel's **QMI feed** row shows
  observations, RawQMI rows, notes and drops (`qmifeed_*` / `rawqmi_*`).
- **The line protocol.** `qmifeed_start()` exports
  `CELLAT_QMIFEED_PROTO=2`. A feed that sees it may also write
  `#rawqmi {json}` (a `RawQMI` row) and `#msg info|error <text>` (a bus note).
  A feed that does not know the protocol never writes them, and an older
  capture binary exports nothing, so either side can be the older one.
- The value runs via `/bin/sh -c`. Kismet splits source options on commas and a
  quoted value ends at the next `"`, so the command may contain **neither** —
  wrap anything more complex in a script and pass `/bin/sh /path/script.sh`.
- Only lines that look like a JSON object (`{...}`) are relayed as
  observations; blank lines, banners and any observation over 4 KiB are
  dropped whole. Tagged lines may run to 64 KiB. Diagnostics belong on stderr
  (the Kismet log) or, for the operator, in a `#msg` line.
- The feed starts with the capture (never during a probe/list), and a feed that
  exits is reported once on the message bus; AT polling carries on.
- Stopping works in layers (`cellat_qmifeed.h`): Kismet's close kills the feed's
  whole process group; if the capture child is killed outright, PDEATHSIG ends
  the direct child and `kismet_qmi_feed.py` exits once it is reparented.
- Band is never emitted for QMI cells: QMI's 16-bit EARFCN TLV can wrap,
  so the prov block carries `"earfcn_ambiguous"` instead.

### 5. Multiple Modems

Multiple cell modem sources can run simultaneously. Each modem gets its own
capture process. If two modems see the same cell tower, Kismet automatically
merges the observations into a single tracked device.

```bash
kismet -c cellat-ttyUSB3 -c cellat-ttyUSB7 -c cellat-ttyUSB16
```

### 6. What You'll See

Cell towers appear in the Kismet device list with:
- **Type:** "Cell Tower"
- **PHY:** `"Cellular"` — the string `phy_cell.cc` registers, what both WiGLE exporters filter on, and what `kismet.device.base.phyname` carries. Match on `"Cellular"`, not the older `"Cell"`.
- **Name:** e.g., "NR 310260_36103_4526858551" (RAT MCC+MNC_TAC_CellID)
- **Channel:** e.g., "NR B41" or "LTE B2"
- **Signal:** RSRP in dBm (from the base signal column)

Click a cell tower device to see the **Cell Info** detail panel with full
cell identity (MCC, MNC, TAC, Cell ID, PCI), signal metrics (RSRP, RSRQ,
SINR), min/max RSRP tracking, and observation count.

The Address column shows the Cell Key (e.g., `310260_36103_4526858551`)
instead of the synthetic MAC address, since cell towers don't have MACs.

### 7. GPS

If Kismet has a GPS source configured (e.g., gpsd), cell tower observations
will be geotagged automatically. This is recommended for wardriving.

### 8. Permissions

The capture binary needs read/write access to the serial port devices.
Running Kismet as root works, or add your user to the `dialout` group:

```bash
sudo usermod -aG dialout $USER
# Log out and back in for the group change to take effect
```

### 9. Non-USB modems via AT-over-TCP (`CELLAT_EXTRA_PORTS`)

The capture binary auto-discovers modems by scanning the `/dev/ttyUSB*` and
`/dev/ttyACM*` ports that sysfs marks as suspected cell modems (§12) and
matching IMEI. For modems that are reachable only over
TCP — e.g. an in-chassis modem behind a CPE's AT-over-TCP bridge — use a
PTY shim and the `CELLAT_EXTRA_PORTS` environment variable:

```bash
# 1. Bridge the modem's AT-over-TCP port to a local PTY symlink:
socat -d PTY,raw,echo=0,link=/tmp/cfw3212-at TCP:192.168.1.1:5555 &

# 2. Tell the capture binary to scan that PTY in addition to the USB ports:
CELLAT_EXTRA_PORTS=/tmp/cfw3212-at kismet -c cellat-<imei>
```

`CELLAT_EXTRA_PORTS` is a space-separated list of literal paths or glob
patterns. The capture binary scans each extra path the same way it scans
`/dev/ttyUSB*` — it opens the device, sends `AT`, requests `AT+CGSN`, and
matches the returned IMEI against the source definition. A named path skips the
suspected-modem rule, which makes this variable the escape hatch for a modem
behind a USB-UART bridge (§12).

Space-separated rather than colon-separated because some device by-id
paths contain colons (e.g. `usb-Android_MDM9207-MTP__SN:717DDE4A_…-if03-port0`).

Devices this shim path works with:

- Casa Systems CFW-3212 — internal Quectel RG520N-NA, `at_tcp.sh`
  service on port 5555
- Orbic RC400L on-device — same shim path with the modem hosted
  remotely

### 10. Scanning only named ports (`CELLAT_SCAN_PORTS`)

`CELLAT_SCAN_PORTS` **replaces** the scan's port universe, where
`CELLAT_EXTRA_PORTS` adds to it. Same syntax (space-separated literal paths or
globs); a path named twice is scanned once. It is the twin of celldiag's
`CELLDIAG_SCAN_PORTS`.

```bash
# Address the modem by IMEI, but never AT-probe anything except these ports:
CELLAT_SCAN_PORTS="/dev/ttyUSB2 /dev/ttyUSB3" kismet -c cellat-<imei>
```

Use it to keep the scan off a port it must not probe (a non-target modem's NMEA
tty) while still addressing by IMEI. An operator naming one AT node wants
`atport=`, which skips the scan. The offline harness
(`celltools/tests/test_cellat_scan_ports.py`) drives the real scan against
PTY fake modems this way, and asserts that no host tty is opened.

A path named in either variable is trusted, **except** under `/dev/mhi_*`
and `/dev/wwan*`. There the shared classifier still decides, because
`/dev/mhi_*` also matches `mhi_SAHARA` and `mhi_BHI`, the EDL and
firmware-download channels. A symlink's target is checked too.
`CELLAT_SCAN_PORTS=/dev/mhi_*` therefore scans `mhi_DUN` and nothing else.

### 11. What the open says about a busy port

A concurrent multi-source open scans the same ports at the same moment, and a
port another process holds the claim to is skipped rather than shared.
Three lines report it:

| line | meaning |
|---|---|
| `cellat AT scan: IMEI … not found while N port(s) were held by another process; rescanned: …` | the scan came back empty with busy ports; one rescan followed after 250–775 ms |
| `cellat: /dev/ttyUSB5 was held by another process when the capture opened it (a sibling source's probe); took it after N ms` | the scan found the port, then a sibling's probe took its claim before the capture's own open; the open waited it out |
| `Failed to open …: Resource temporarily unavailable (held by another process for the whole N ms wait)` | the claim was held past the 3 s wait: a real conflict, such as a second source on the same modem |

Without that wait, the second case would fail the launch with `Failed to open
/dev/ttyUSB5: Resource temporarily unavailable` and rely on Kismet's 5 s retry.

### 12. Which ports the scan probes and what it leaves behind

A probe is not free for the device on the other end. To speak AT, the scan sets
the port to 115200 raw 8N1, flushes both queues and writes `AT\r\n`. On Linux the
line settings belong to the tty, not to the scan's file descriptor, so every
other reader of the port sees them too. A GNSS receiver on a CH340 bridge, read
at 460800 by `str2str` (which takes no `flock`), would be left at 115200 by one
scan and read line noise until something reset the port.

So the scan does two things:

**It opens only suspected cell modems.** Each `/dev/ttyUSB*` and `/dev/ttyACM*`
is decided from sysfs *before* `open()`. A port that is not admitted is never
opened: no `open()`, no `tcsetattr()`, no flush, no `AT`. The rule is an
allowlist, shared with celldiag's IMEI scan (`capture_cell_diag/diag_portadmit.c`):

| the tty is bound to | verdict |
|---|---|
| a cellular usb-serial driver: `option` (sysfs spells it `option1`), `qcserial`, `sierra` | probed |
| `cdc_acm`, on a cellular vendor id (Quectel, Telit, Sierra, Qualcomm, SIMCom, Fibocom, Huawei, ZTE, Dell, …) | probed |
| `cdc_acm` on any other vendor (u-blox GNSS `1546`, Arduino, …) | **not opened** |
| a USB-UART bridge (`ch341-uart`, `ftdi_sio`, `pl2303`, `cp210x`, …), the `generic` usb-serial driver, no driver, no sysfs entry | **not opened** |
| an admitted modem's **measured DIAG or NMEA interface**: the exact VID:PID, `bInterfaceNumber` and class/subclass/protocol in the table below | **not opened** |

`/dev/wwan*` and `/dev/mhi_*` keep their own classifier (§10).

**A modem's own DIAG and NMEA ports.** The scan tries a modem's
interfaces highest first and stops at the first answer. When a sibling source
holds the AT ports, the scan would otherwise go on down into the modem's NMEA
and DIAG functions, writing `AT` into the DIAG node and flushing an NMEA
reader's bytes. With this rule, a drive running cellat and celldiag side by side
opens each DIAG tty only from its own `diagport=` capture and each NMEA tty
never. The table holds only measured interfaces:

| modem | VID:PID | refused | kept (answers AT) |
|---|---|---|---|
| Quectel EG25-G | `2c7c:0125` | if00 DIAG `ff/ff/ff`, if01 NMEA `ff/00/00` | if02, if03 |
| Quectel RM500Q-AE | `2c7c:0800` | if00 DIAG `ff/ff/30`, if01 NMEA `ff/00/00` | if02, if03 |
| Quectel RM520N-GL (USB) | `2c7c:0801` | if00 DIAG `ff/ff/30`, if01 NMEA `ff/00/40` | if02, if03 |
| Telit LM960A18 | `1bc7:1040` | if00 DIAG `ff/ff/ff`, if03 NMEA `ff/00/00` | if04, if05, if06 |

It is keyed by the exact VID:PID, never by vendor: on `2c7c:0700`, if00–if02 are
all `ff/ff/ff` and if02 answers AT. The descriptor has to match as well, so a
different composition of a listed modem (a `usbcfg` change, another firmware) is
probed as before, and so is a port whose descriptor cannot be read. A modem not
in the table is also probed as before.

Each refused port is logged once per helper process on stderr, and named in the
open's messages:

```
cellat: skip /dev/ttyUSB0: ch341-uart 1a86:7523, not a suspected cell modem (name it in CELLAT_EXTRA_PORTS, or use atport=, to probe it)
cellat: skip /dev/ttyUSB13: option1 2c7c:0125 if01 NMEA, a cell modem's known non-AT port (name it in CELLAT_EXTRA_PORTS, or use atport=, to probe it)
cellat AT scan: not probed (not suspected cell modems, or a modem's known non-AT port): ttyUSB0(ch341-uart 1a86:7523),ttyUSB13(option1 2c7c:0125 if01 NMEA) (name one in CELLAT_EXTRA_PORTS to probe it)
```

**A modem behind a USB-UART bridge is refused as the bridge.** A SIM7600 hat
on a CH340 and a Quectel EVB's UART enumerate as `ch341-uart` / `ftdi_sio`. The
escape hatch is naming the port: `CELLAT_EXTRA_PORTS` (adds), `CELLAT_SCAN_PORTS`
(replaces) or `atport=` (skips the scan). A named port is admitted as named, since
naming it is the decision. celldiag's hatch is `CELLDIAG_SCAN_PORTS` or `atport=`.
A modem-maker's cdc_acm vendor id missing from the table takes the same hatch.

**It puts back what it changed.** A probe records the port's termios as it found
it and restores it (`TCSANOW`) before it closes, whether or not the port answered.
That covers the ports the rules admit but which are not this source's target:
the DIAG or NMEA tty of a modem the table does not list, or a port someone
named. What it cannot undo is
the flush and the `AT\r\n` it wrote. A reader of an admitted port that does not
`flock` still loses about one exchange of bytes, so take the claim (`flock`) on
any port you read beside a Kismet drive.

## Scan Strategies

| Strategy | Label | Serving Cell | Neighbor Cells | Full Band Scan |
|----------|-------|-------------|----------------|----------------|
| `driving` (default) | Driving | Every 2s | Every 5s | — |
| `walking` | Walking | Every 2s | Every 5s | Every 300s |
| `stationary` | Stationary survey | Every 2s | Every 5s | Every 60s |
| `serving_only` | Serving cell only | Every 2s | — | — |

The profiles differ mainly in how often they run the full band scan
(AT+QSCAN, up to 2 minutes; AT#CSURVC, up to 3). The scan is the only thing
that finds cells on bands the modem is not camped on, and it blocks the serial
port — and so the serving and neighbor polls — for its whole duration. How much
that blind window costs depends on how fast you are moving:

- **driving** — Best for mobile use. Fast serving + neighbor cell polling,
  never a full scan. `strategy=wardrive`, the former name, still works and
  reports as `driving` (renamed partly because celldiag has an unrelated
  `wardrive` *mask* preset).
- **walking** — A full scan every 5 minutes, about every 400 m at walking pace;
  a 2-minute scan blinds ~170 m of that.
- **stationary** — For fixed-location surveys. A full scan every 60 s after the
  previous one finishes.
- **serving_only** — Minimal load. Only polls the serving cell.

The interval is measured from the **end** of the previous scan, so a long scan
never runs back-to-back into the next one.

A profile that asks for a full scan on a modem with no full-scan command
(no AT+QSCAN and no AT#CSURVC) still opens, and runs its serving and neighbor
polls, but warns on the message bus that the full scan will not run.

There is **no PLMN (`AT+COPS=?`) scan** in any profile; the capture loop never
issues it.

Note: the full band scan is probed at open, not assumed from the model. A
Quectel modem gets `AT+QSCAN=?` and full-scans only if it answers with a
`+QSCAN:` row and `OK` (the RM500Q-AE and RM520N-GL do; the EG25-G answers
`ERROR`). A Telit modem gets `AT#CSURVC=?` instead. Neighbor cell queries are
Quectel-only (AT+QENG).

## Tested Configurations

| Modem | Firmware | RAT | Verified |
|-------|----------|-----|----------|
| Quectel RM500Q-AE | RM500QAEAAR11A21M4G | NR5G-SA, LTE | Yes |
| Quectel EG25-G | EG25GGBR07A08M2G | LTE | Yes |
| Telit LM960A18 | 32.01.110 (Generic) | LTE | Yes |
