# kismet_cap_cell_qmi

A cellular modem's serving and neighbour cells, read over QMI.

The source polls the modem's NAS service on its QMI control node and sends each
cell to Kismet as a `CellModem` record, the record the AT (`cellat`) and DIAG
(`celldiag`) sources send. The cellular phy merges a cell seen by several
sources into one device, and lists `qmi` among the sources in its `seen_via`.

## Use

```
kismet -c cdc-wdm0:type=cellqmi
kismet -c cellqmi:device=/dev/wwan0qmi0
```

A source names the modem's control node: `cdc-wdmN` (USB, `qmi_wwan` or
`cdc_mbim`), `wwanNqmiM` / `wwanNmbimM` (the kernel WWAN subsystem), or
`mhi_QMIN` / `mhi_MBIMN` (Quectel's PCIe MHI driver). The node is root-only, so
the source runs as root.

| option | default | |
|---|---|---|
| `interval=<ms>` | 2000 | poll period, at least 500 |
| `open=auto\|proxy\|direct` | auto | how the node is reached, below |
| `framing=qmux\|mbim` | from the node | when the node's driver cannot be read |

## How the node is reached

The node speaks bare QMUX (`qmi_wwan`, the WWAN and MHI QMI nodes) or MBIM
(`cdc_mbim`). On an MBIM node QMI travels inside MBIM, on the QMI service
`d1a30bc2-f97a-6e43-bf65-c7e24fb0f0d3`.

With `open=auto` the source shares the node when it can and stays off it when
it cannot:

1. **Proxy.** libqmi's `qmi-proxy` (QMUX) or libmbim's `mbim-proxy` (MBIM) is
   listening and nothing else holds the node: the source joins the proxy as one
   more client, beside ModemManager or anything else on it.
2. **Refuse.** Another program holds the node (uqmi, a vendor connection
   manager, a proxy of the other framing): the source names it and does not
   open the node, because a second reader would take that program's replies.
3. **Direct.** No proxy and no holder: the source opens the node itself, the
   only option on hosts without libqmi.

The source detects a proxy from `/proc/net/unix` and never starts one: a started
`mbim-proxy` outlives its client and keeps the node open. Holders are read from
`/proc/<pid>/fd` before the helper drops its privileges.

Rules that follow from sharing a modem:

- The source never sends QMI CTL Sync. Through a proxy it would reset every
  other client's client IDs.
- It releases its NAS client ID when it closes, and on SIGTERM, SIGINT and
  SIGHUP. Neither the modem nor the proxies reclaim a dead client's IDs, and
  each service has only a few.
- No handler runs on SIGKILL, so a direct open also records its client ID in
  `~/.kismet/cellqmi-<node>.cid`, written at the caller's own ids under a
  suid install. The next direct open of the same node releases a recorded ID
  before asking for its own, and says so in the Kismet messages. The record
  names the node by device number, inode and change time, so after a modem
  re-enumerates (its node is made again, and the reset freed its IDs) an old
  number is never released. The record is emptied on every release. Through a
  proxy nothing is recorded, because other clients share the modem's IDs
  there. Without a `~/.kismet` directory nothing is recorded.
- On a direct QMUX node it asks for a client ID once and waits for the answer
  through whatever the node delivers first. While a node is closed, the modem
  queues indications for every client nobody released, and `cdc-wdm` hands
  them over one per interrupt poll (32 ms on `qmi_wwan`), so a cold open can
  read hundreds of them before the reply. The wait ends after the open timeout
  of silence, or 20 s in all. Giving up early and asking again would allocate
  a second client whose reply is never read, and that client would add to the
  next open's backlog.
- The `MBIM_OPEN` asks for no larger control transfer than the node's own
  buffer (`IOCTL_WDM_MAX_COMMAND`, 512 bytes on an Intel XMM7360). Told it may
  send more, an XMM7360 sent a 1 KB reply in one transfer the node could not
  hold, and its MBIM function then answered nothing until the modem was reset.
- On a direct MBIM node it sends `MBIM_OPEN` only if the function answers that
  it is not open: opening an open function resets it, which ends any data
  session another program set up. It closes the function afterwards only if it
  opened it. Through `mbim-proxy` it sends neither; the proxy owns the function.

A modem whose MBIM function carries no QMI service is refused with a message.
It needs a native MBIM reader, which this source does not have yet.

## What it reads

Each poll sends three NAS requests: Get System Info (0x004D), Get Cell Location
Info (0x0043) and Get Signal Info (0x004F).

- **LTE serving cell:** PLMN, TAC, ECI, PCI and EARFCN from cell location;
  RSRP, RSRQ, RSSI and SNR from signal info.
- **LTE neighbours:** each intra- and inter-frequency cell as PCI + EARFCN, with
  its RSRP, RSRQ and RSSI.
- **NR serving cell:** PLMN, TAC, NCI, PCI and NR-ARFCN, with RSRP, RSRQ and SNR,
  from cell location.
- When cell location names no cell of a camped RAT, the serving identity comes
  from system info.

Rules:

- The 16-bit EARFCN fields wrap above 65535: band 65 channel 65636 reads as
  100, a band 1 channel. Cell location repeats the EARFCNs as 32-bit values
  (TLVs 0x27 and 0x28), and the source writes an EARFCN only when a 32-bit value
  confirms it. A serving cell without one keeps its global identity but has no
  EARFCN. A neighbour without one has no identity, so it is left out.
- System info's service status decides whether there is service. With none or
  power-save on every RAT there is no cell to report, and the source says so
  once. Out of coverage reads as power-save.
- Cell location also answers "no network found" when the network refused the
  modem's registration (no SIM, a forbidden PLMN), while system info still names
  the cell the modem camps on. That cell is real and is reported.

## Selftest

`./configure --enable-cell-selftest` builds `test_cellqmi`: the framing, the NAS
decoders, the observation records and the open order, on synthetic frames, with
no modem and no server. It exits non-zero on a failure.
