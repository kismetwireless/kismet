#!/usr/bin/env python3
"""Auto-detect QMI/MBIM control devices and determine correct qmicli open flags.

Scans /sys/bus/usb/devices for cdc-wdm control devices, identifies the modem
vendor from USB VID/PID, and returns the device path with the correct
``--device-open-*`` flags for qmicli.

Usage as library:
    from qmifeed.detect import detect_qmi_devices, QMIDevice
    for dev in detect_qmi_devices():
        print(dev.device, dev.open_flags)

Usage as CLI:
    python3 -m qmifeed.detect             # List all QMI devices
    python -m qmifeed.detect --json       # JSON output
"""

from __future__ import annotations

import glob
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional


# ---------------------------------------------------------------------------
# USB VID → vendor mapping
# ---------------------------------------------------------------------------

VENDOR_BY_VID: dict[str, str] = {
    "2c7c": "quectel",
    "1e0e": "simcom",
    "1199": "sierra",
    "1bc7": "telit",
    "2cb7": "fibocom",
    "413c": "foxconn",   # Dell OEM (Foxconn/T77W968)
    "05c6": "qualcomm",  # Generic Qualcomm (Orbic, etc.)
    # WNC/Wistron NeWeb VID, named for the selling brand, "mikrotik".
    "2cd2": "mikrotik",  # WNC ODM; sold as MikroTik R11e-LTE-US
}

MODEL_BY_VIDPID: dict[str, str] = {
    "2c7c:0125": "EG25-G",
    "2c7c:0512": "EG12-GT",
    "2c7c:0306": "EG06/EP06/EM06",
    "2c7c:0800": "RM500Q-AE",
    # PID alone cannot disambiguate M1 vs M3, and a BG95-M1 answers on it, so
    # a bare "BG95-M3" would mislabel one.
    "2c7c:0700": "BG95-M1/BG95-M3",
    # Model unresolved; it is not an EM120R-GL.
    "2c7c:030a": "unresolved",
    "1e0e:9001": "SIM7600NA-H",
    "1199:9071": "MC7455",
    "1199:9091": "MC7411",
    "1199:90d3": "EM9190",
    "1bc7:1040": "LM960A18",
    "1bc7:1050": "FN980",
    "2cb7:0007": "L850-GL",
    "413c:81d7": "T77W968",
    "05c6:f622": "RC400L",
    "2cd2:0002": "R11e-LTE-US",
}

# Drivers that indicate QMI vs MBIM transport
_QMI_DRIVERS = {"qmi_wwan", "qmi_wwan_q"}
_MBIM_DRIVERS = {"cdc_mbim"}


@dataclass
class QMIDevice:
    """A detected QMI/MBIM control device with its open flags."""

    device: str                     # e.g. "/dev/cdc-wdm0"
    driver: str                     # "qmi_wwan" or "cdc_mbim"
    transport: str                  # "qmi" or "mbim"
    vendor: str                     # "quectel", "sierra", etc.
    model: str                      # "RM500Q-AE", "unknown", etc.
    vid_pid: str                    # "2c7c:0800"
    usb_path: str                   # sysfs USB device path, e.g. "1-2"
    interface_num: int              # USB interface number
    open_flags: list[str] = field(default_factory=list)

    @property
    def open_flags_str(self) -> str:
        """Flags as a single string for command-line use."""
        return " ".join(self.open_flags)

    def qmicli_args(self, proxy: bool = True) -> list[str]:
        """Return qmicli argument list for this device.

        Args:
            proxy: If True, use --device-open-proxy for shared access.
                   This is the default and recommended setting — it allows
                   multiple QMI clients to share the control port.
        """
        args = ["-d", self.device]
        if proxy:
            args.append("--device-open-proxy")
        else:
            args.extend(self.open_flags)
        return args


def _read_sysfs(path: str) -> str:
    """Read a sysfs attribute file, return stripped content or empty string."""
    try:
        return Path(path).read_text().strip()
    except (OSError, IOError):
        return ""


def _find_parent_usb_device(intf_path: str) -> Optional[str]:
    """Walk up from a USB interface sysfs path to find the parent USB device.

    USB interfaces look like: /sys/bus/usb/devices/1-2:1.4
    The parent device is:     /sys/bus/usb/devices/1-2
    """
    # Interface paths contain a colon: "1-2:1.4"
    base = os.path.basename(intf_path)
    if ":" in base:
        return base.split(":")[0]
    return None


def _find_cdc_wdm_in_interface(intf_path: str) -> Optional[str]:
    """Find /dev/cdc-wdm* device node under a USB interface sysfs path."""
    # Look for usbmisc/cdc-wdm* directly under the interface
    patterns = [
        os.path.join(intf_path, "usbmisc", "cdc-wdm*"),
        os.path.join(intf_path, "*", "usbmisc", "cdc-wdm*"),
    ]
    for pattern in patterns:
        matches = glob.glob(pattern)
        if matches:
            return f"/dev/{os.path.basename(matches[0])}"
    return None


def detect_qmi_devices(sysfs_base: str = "/sys/bus/usb/devices") -> List[QMIDevice]:
    """Scan sysfs for all QMI/MBIM control devices.

    Walks USB interfaces looking for qmi_wwan or cdc_mbim drivers,
    then resolves the corresponding /dev/cdc-wdm* device and identifies
    the modem vendor/model from the parent USB device's VID/PID.

    Returns:
        List of QMIDevice instances, one per detected control device.
    """
    devices: list[QMIDevice] = []

    try:
        entries = os.listdir(sysfs_base)
    except OSError:
        return devices

    for entry in sorted(entries):
        # USB interfaces have a colon in their name: "1-2:1.4"
        if ":" not in entry:
            continue

        intf_path = os.path.join(sysfs_base, entry)
        driver_link = os.path.join(intf_path, "driver")

        if not os.path.islink(driver_link):
            continue

        driver = os.path.basename(os.readlink(driver_link))

        if driver in _QMI_DRIVERS:
            transport = "qmi"
        elif driver in _MBIM_DRIVERS:
            transport = "mbim"
        else:
            continue

        # Find the /dev/cdc-wdm* device
        dev_path = _find_cdc_wdm_in_interface(intf_path)
        if not dev_path:
            continue

        # Parse interface number from sysfs name (e.g., "1-2:1.4" → 4)
        try:
            intf_num = int(entry.rsplit(".", 1)[-1])
        except (ValueError, IndexError):
            intf_num = -1

        # Find parent USB device and read VID/PID
        usb_dev_name = _find_parent_usb_device(entry)
        vid_pid = ""
        vendor = "unknown"
        model = "unknown"

        if usb_dev_name:
            usb_dev_path = os.path.join(sysfs_base, usb_dev_name)
            vid = _read_sysfs(os.path.join(usb_dev_path, "idVendor")).lower()
            pid = _read_sysfs(os.path.join(usb_dev_path, "idProduct")).lower()
            if vid and pid:
                vid_pid = f"{vid}:{pid}"
                vendor = VENDOR_BY_VID.get(vid, "unknown")
                model = MODEL_BY_VIDPID.get(vid_pid, "unknown")

        # Determine open flags
        open_flags: list[str] = []
        if transport == "qmi":
            open_flags = ["--device-open-qmi"]
        elif transport == "mbim":
            open_flags = ["--device-open-mbim"]

        devices.append(QMIDevice(
            device=dev_path,
            driver=driver,
            transport=transport,
            vendor=vendor,
            model=model,
            vid_pid=vid_pid,
            usb_path=usb_dev_name or "",
            interface_num=intf_num,
            open_flags=open_flags,
        ))

    return devices


def detect_qmi_device_for_modem(
    vendor: Optional[str] = None,
    model: Optional[str] = None,
) -> Optional[QMIDevice]:
    """Find the best QMI device for a specific modem.

    If vendor/model are given, filters to matching devices.
    If multiple devices match, returns the first one.
    If no filters given, returns the first detected device.
    """
    devices = detect_qmi_devices()
    if not devices:
        return None

    if vendor:
        vendor_lower = vendor.lower()
        devices = [d for d in devices if vendor_lower in d.vendor.lower()]

    if model:
        model_lower = model.lower().replace("-", "").replace("_", "")
        devices = [
            d for d in devices
            if model_lower in d.model.lower().replace("-", "").replace("_", "")
        ]

    return devices[0] if devices else None


def main() -> None:
    """CLI: detect and display QMI devices."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Detect QMI/MBIM control devices for cellular modems"
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--vendor", help="Filter by vendor (e.g., quectel)")
    parser.add_argument("--model", help="Filter by model (e.g., RM500Q)")
    args = parser.parse_args()

    devices = detect_qmi_devices()

    if args.vendor:
        v = args.vendor.lower()
        devices = [d for d in devices if v in d.vendor.lower()]
    if args.model:
        m = args.model.lower().replace("-", "").replace("_", "")
        devices = [
            d for d in devices
            if m in d.model.lower().replace("-", "").replace("_", "")
        ]

    if args.json:
        print(json.dumps([asdict(d) for d in devices], indent=2))
    elif not devices:
        print("No QMI/MBIM devices found.", file=sys.stderr)
        sys.exit(1)
    else:
        for d in devices:
            proxy_args = " ".join(d.qmicli_args(proxy=True))
            print(f"{d.device}  {d.vendor}/{d.model}  "
                  f"driver={d.driver}  transport={d.transport}")
            print(f"  qmicli {proxy_args} --nas-get-signal-info")
            print()


if __name__ == "__main__":
    main()
