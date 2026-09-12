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

The JSON type string `"CellModem"` is used to route observations to the
Cell PHY handler.

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
`{RAT}_pci{PCI}_{EARFCN}` — less specific but sufficient for tracking.

### Scan strategies

Three scan strategies balance data thoroughness vs. serial port load:

| Strategy | Serving | Neighbor | Full Scan | PLMN |
|----------|---------|----------|-----------|------|
| `wardrive` (default) | 2s | 5s | — | — |
| `stationary` | 2s | 5s | 60s | 300s |
| `serving_only` | 2s | — | — | — |

Wardrive is the default because neighbor cell queries can block the serial
port for several seconds, and full band scans can take 2+ minutes — both
unsuitable for mobile use.

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
    "scans": { ... },
    "strategies": { ... }
}
```

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
# Clone or update the Kismet source tree (this branch)
git clone -b poc-cell-phy https://github.com/lukejenkins/kismet.git
cd kismet

# Configure (standard Kismet configure — cell modem has no extra flags)
./configure
make

# Build the capture binary
cd capture_cell_at && make
cd ..

# Install (as root or with appropriate permissions)
sudo make install

# The capture binary must also be installed manually for now:
sudo install -m 755 capture_cell_at/kismet_cap_cell_at /usr/local/bin/
```

Note: The cell modem capture source is not yet wired into `configure.ac`
and `DATASOURCE_BINS`, so `make install` does not automatically install
`kismet_cap_cell_at`. The manual install step above is required until
this is integrated into the Kismet build system.

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
    cellat-ttyUSB3 (Quectel RM500Q IMEI:XXXXXXXXXXXXXXX)
    cellat-ttyUSB7 (Quectel EG25 IMEI:XXXXXXXXXXXXXXX)
    cellat-ttyUSB16 (Telit LM960A18 IMEI:XXXXXXXXXXXXXXX)
```

Use the interface name (e.g., `cellat-ttyUSB3`) as the source definition.

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
kismet -c cellat-ttyUSB3
```

**Option B — add to a running Kismet instance via the REST API:**

```bash
curl -u user:pass -X POST \
  --data-urlencode 'json={"definition":"cellat-ttyUSB3:strategy=wardrive"}' \
  http://localhost:2501/datasource/add_source.cmd
```

**Option C — via the Kismet web UI:**

Navigate to `http://localhost:2501`, go to the Data Sources panel, and
add a new source with the definition `cellat-ttyUSB3`.

### 4. Source Options

Append options to the source definition after a colon:

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `strategy` | `wardrive`, `stationary`, `serving_only` | `wardrive` | Scan strategy (see below) |
| `debug` | `true`, `false` | `false` | Enable debug messages in Kismet log |

Examples:

```bash
kismet -c cellat-ttyUSB3:strategy=stationary
kismet -c cellat-ttyUSB3:strategy=wardrive,debug=true
```

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
- **PHY:** "Cell"
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

The capture binary auto-discovers modems by scanning `/dev/ttyUSB*` and
`/dev/ttyACM*` and matching IMEI. For modems that are reachable only over
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
matches the returned IMEI against the source definition.

Space-separated rather than colon-separated because some device by-id
paths contain colons (e.g. `usb-Android_MDM9207-MTP__SN:717DDE4A_…-if03-port0`).

Concrete deployments this shim path has been used with:

- Casa Systems CFW-3212 — internal Quectel RG520N-NA, `at_tcp.sh`
  service on port 5555 (#327)
- Orbic RC400L on-device — same shim path with the modem hosted
  remotely (#329)

## Scan Strategies

| Strategy | Serving Cell | Neighbor Cells | Full Band Scan | PLMN Scan |
|----------|-------------|----------------|----------------|-----------|
| `wardrive` (default) | Every 2s | Every 5s | — | — |
| `stationary` | Every 2s | Every 5s | Every 60s | Every 300s |
| `serving_only` | Every 2s | — | — | — |

- **wardrive** — Best for mobile use. Fast serving + neighbor cell polling
  with minimal serial port blocking.
- **stationary** — For fixed-location surveys. Adds full band scan
  (AT+QSCAN, up to 2 minutes) and PLMN operator scan (AT+COPS=?).
  The full scan commands block the serial port while running.
- **serving_only** — Minimal load. Only polls the serving cell.

Note: Full band scan (AT+QSCAN) is only available on Quectel RM500Q series
and other 5G Quectel modems. Telit modems use AT#RFSTS which only reports
the serving cell. Neighbor cell queries are Quectel-only (AT+QENG).

## Tested Configurations

| Modem | Firmware | RAT | Verified |
|-------|----------|-----|----------|
| Quectel RM500Q-AE | RM500QAEAAR11A21M4G | NR5G-SA, LTE | Yes |
| Quectel EG25-G | EG25GGBR07A08M2G | LTE | Yes |
| Telit LM960A18 | 32.01.110 (Generic) | LTE | Yes |
