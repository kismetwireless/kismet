#!/usr/bin/env python3
"""Tests for qmifeed.detect — QMI device auto-detection.

Since detection reads sysfs, tests use a mock sysfs tree in /tmp.
"""

import json
import os
import tempfile
import unittest

from qmifeed.detect import (
    QMIDevice,
    detect_qmi_devices,
    detect_qmi_device_for_modem,
)


def _create_mock_sysfs(base: str, devices: list[dict]) -> None:
    """Create a mock /sys/bus/usb/devices tree.

    Each device dict has:
        usb_path: str       e.g. "1-2"
        vid: str            e.g. "2c7c"
        pid: str            e.g. "0800"
        interfaces: list of dicts with:
            num: int        interface number
            driver: str     e.g. "qmi_wwan", "cdc_mbim", "option"
            cdc_wdm: str    optional, e.g. "cdc-wdm0"
    """
    for dev in devices:
        usb_path = dev["usb_path"]
        dev_dir = os.path.join(base, usb_path)
        os.makedirs(dev_dir, exist_ok=True)

        # Write VID/PID
        with open(os.path.join(dev_dir, "idVendor"), "w") as f:
            f.write(dev["vid"])
        with open(os.path.join(dev_dir, "idProduct"), "w") as f:
            f.write(dev["pid"])
        with open(os.path.join(dev_dir, "busnum"), "w") as f:
            f.write("1")
        with open(os.path.join(dev_dir, "devnum"), "w") as f:
            f.write("2")

        # Create interfaces
        for intf in dev.get("interfaces", []):
            intf_name = f"{usb_path}:1.{intf['num']}"
            intf_dir = os.path.join(base, intf_name)
            os.makedirs(intf_dir, exist_ok=True)

            # Create driver symlink
            if intf.get("driver"):
                driver_target = os.path.join("/tmp/fake_drivers", intf["driver"])
                os.makedirs(driver_target, exist_ok=True)
                driver_link = os.path.join(intf_dir, "driver")
                os.symlink(driver_target, driver_link)

            # Create cdc-wdm device node reference
            if intf.get("cdc_wdm"):
                usbmisc_dir = os.path.join(intf_dir, "usbmisc")
                os.makedirs(usbmisc_dir, exist_ok=True)
                wdm_dir = os.path.join(usbmisc_dir, intf["cdc_wdm"])
                os.makedirs(wdm_dir, exist_ok=True)


class TestDetectQMIDevices(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="test_qmi_detect_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_quectel_qmi_device(self):
        """Quectel RM500Q with qmi_wwan driver."""
        _create_mock_sysfs(self.tmpdir, [{
            "usb_path": "2-1",
            "vid": "2c7c",
            "pid": "0800",
            "interfaces": [
                {"num": 4, "driver": "qmi_wwan", "cdc_wdm": "cdc-wdm1"},
            ],
        }])

        devices = detect_qmi_devices(self.tmpdir)
        self.assertEqual(len(devices), 1)
        d = devices[0]
        self.assertEqual(d.device, "/dev/cdc-wdm1")
        self.assertEqual(d.driver, "qmi_wwan")
        self.assertEqual(d.transport, "qmi")
        self.assertEqual(d.vendor, "quectel")
        self.assertEqual(d.model, "RM500Q-AE")
        self.assertEqual(d.vid_pid, "2c7c:0800")
        self.assertEqual(d.open_flags, ["--device-open-qmi"])

    def test_sierra_mbim_device(self):
        """Sierra EM9190 with cdc_mbim driver."""
        _create_mock_sysfs(self.tmpdir, [{
            "usb_path": "1-3",
            "vid": "1199",
            "pid": "90d3",
            "interfaces": [
                {"num": 0, "driver": "cdc_mbim", "cdc_wdm": "cdc-wdm0"},
            ],
        }])

        devices = detect_qmi_devices(self.tmpdir)
        self.assertEqual(len(devices), 1)
        d = devices[0]
        self.assertEqual(d.device, "/dev/cdc-wdm0")
        self.assertEqual(d.driver, "cdc_mbim")
        self.assertEqual(d.transport, "mbim")
        self.assertEqual(d.vendor, "sierra")
        self.assertEqual(d.model, "EM9190")
        self.assertEqual(d.open_flags, ["--device-open-mbim"])

    def test_multiple_modems(self):
        """Two modems — Quectel QMI + Sierra MBIM."""
        _create_mock_sysfs(self.tmpdir, [
            {
                "usb_path": "1-1",
                "vid": "2c7c",
                "pid": "0125",
                "interfaces": [
                    {"num": 4, "driver": "qmi_wwan", "cdc_wdm": "cdc-wdm0"},
                ],
            },
            {
                "usb_path": "1-2",
                "vid": "1199",
                "pid": "9091",
                "interfaces": [
                    {"num": 0, "driver": "cdc_mbim", "cdc_wdm": "cdc-wdm1"},
                ],
            },
        ])

        devices = detect_qmi_devices(self.tmpdir)
        self.assertEqual(len(devices), 2)
        vendors = {d.vendor for d in devices}
        self.assertEqual(vendors, {"quectel", "sierra"})

    def test_no_qmi_devices(self):
        """Interface with option driver (serial only, no QMI)."""
        _create_mock_sysfs(self.tmpdir, [{
            "usb_path": "1-1",
            "vid": "2c7c",
            "pid": "0125",
            "interfaces": [
                {"num": 0, "driver": "option"},  # DIAG port, not QMI
            ],
        }])

        devices = detect_qmi_devices(self.tmpdir)
        self.assertEqual(len(devices), 0)

    def test_empty_sysfs(self):
        devices = detect_qmi_devices(self.tmpdir)
        self.assertEqual(len(devices), 0)

    def test_qmicli_args_with_proxy(self):
        d = QMIDevice(
            device="/dev/cdc-wdm0",
            driver="qmi_wwan",
            transport="qmi",
            vendor="quectel",
            model="EG25-G",
            vid_pid="2c7c:0125",
            usb_path="1-1",
            interface_num=4,
            open_flags=["--device-open-qmi"],
        )
        args = d.qmicli_args(proxy=True)
        self.assertEqual(args, ["-d", "/dev/cdc-wdm0", "--device-open-proxy"])

    def test_qmicli_args_without_proxy(self):
        d = QMIDevice(
            device="/dev/cdc-wdm0",
            driver="cdc_mbim",
            transport="mbim",
            vendor="sierra",
            model="EM9190",
            vid_pid="1199:90d3",
            usb_path="1-3",
            interface_num=0,
            open_flags=["--device-open-mbim"],
        )
        args = d.qmicli_args(proxy=False)
        self.assertEqual(args, ["-d", "/dev/cdc-wdm0", "--device-open-mbim"])


if __name__ == "__main__":
    unittest.main()
