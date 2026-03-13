# WCH BLE Analyzer Pro

A Kismet capture driver for the WCH BLE Analyzer Pro unit, derived from the
reverse engineered drivers by
[xecaz](https://github.com/xecaz/BLE-Analyzer-pro-linux-capture/tree/main),
released under the "do whatever you want" license and graciously contributed.

## Device architecture

The WCH Analyzer Pro consists of 3 MCUs with BTLE support, and a USB hub.
Kismet will identify the three devices and aggregate them into a single logical
device, or can individually address each MCU as a separate capture device.

## Limitations

Currently the WCH drivers do not have a mechanism to return the CRC (if even
present in the hardware); this results in a run-time calculation of the CRC
based on the provided data, which unfortunately is not able to filter out bogus
capture content.

When using these drivers there may be excessive false devices found.
