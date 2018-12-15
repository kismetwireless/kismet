---
title: "Wi-Fi fingerprinting"
permalink: /docs/devel/webui_rest/phy80211_fingerprints/
toc: true
---
The Kismet phy80211 fingerprinting system is used for device whitelisting, device modification alerts, and other device tracking.

The fingerprint API can be found under multiple paths, but all will follow this API.  (Documentation to be improved as final paths are chosen).  

__This api is currently incomplete__ and under development.

## Fingerprints

* URL \\
        .../fingerprints/all_fingerprints.json

* Methods \\
        `GET`

* Results \\
        Array of all defined fingerprints.

## Adding fingerprints
New fingerprints can be defined run-time.

__LOGIN REQUIRED__

* URL \\
        .../fingerprints/new/insert.cmd

* Methods \\
        `POST`


* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key | Description |
| --- | ----------- |
| macaddr | MAC address of fingerprint device |
| beacon_hash | (optional) Kismet xxhash32 hash for static beacon IE fields, as found in the `dot11.device/dot11.device.beacon_fingerprint` field |
| probe_hash | (optional) Kismet xxhash32 hash for static probe IE fields, as found in the `dot11.device/dot11.device.probe_fingerprint` field |
| response_hash | (optional) Kismet xxhash32 hash for static response IE fields, as found in the `dot11.device/dot11.device.response_fingerprint` field |

* Results \\
        `HTTP 200` on success
        HTTP error on failure

## Updating fingerprints
Fingerprints may be modified at run-time.

__LOGIN REQUIRED__

* URL \\
        .../fingerprints/by-mac/*[MACADDRESS]*/update.cmd

* Methods \\
        `POST`

* URL parameters

| Key | Description |
| -- | -- |
| *[MACADDRESS]* | MAC address of device fingerprint to be updated |

* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key | Description |
| --- | ----------- |
| beacon_hash | (optional) Kismet xxhash32 hash for static beacon IE fields, as found in the `dot11.device/dot11.device.beacon_fingerprint` field |
| probe_hash | (optional) Kismet xxhash32 hash for static probe IE fields, as found in the `dot11.device/dot11.device.probe_fingerprint` field |
| response_hash | (optional) Kismet xxhash32 hash for static response IE fields, as found in the `dot11.device/dot11.device.response_fingerprint` field |

* Results \\
        `HTTP 200` on success
        HTTP error on failure

## Removing fingerprints

__LOGIN REQUIRED__

* URL \\
        .../fingerprints/by-mac/*[MACADDRESS]*/delete.cmd

* Methods \\
        `POST`

* URL parameters

| Key | Description |
| -- | -- |
| *[MACADDRESS]* | MAC address of device fingerprint to be deleted |

* POST parameters \\
        None

* Results \\
        `HTTP 200` on success
        HTTP error on failure

## Bulk-create fingerprints
Sometimes it may be necessary to creaate a large number of new fingerprints at once.  This API facilitates doing that in a single query.

__LOGIN REQUIRE__D

* URL \\
    .../fingerprints/bulk/insert.cmd

* Methods \\
        `POST`

* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key | Description |
| --- | ----------- |
| fingerprints | Array of fingerprint dictionaries to be inserted |

Each entry in the `fingerprints` array must include:

| Key | Description |
| --- | ----------- |
| macaddr | MAC address of fingerprint device |
| beacon_hash | (optional) Kismet xxhash32 hash for static beacon IE fields, as found in the `dot11.device/dot11.device.beacon_fingerprint` field |
| probe_hash | (optional) Kismet xxhash32 hash for static probe IE fields, as found in the `dot11.device/dot11.device.probe_fingerprint` field |
| response_hash | (optional) Kismet xxhash32 hash for static response IE fields, as found in the `dot11.device/dot11.device.response_fingerprint` field |

* Results \\
        `HTTP 200` on success
        HTTP error on failure

## Bulk-delete fingerprints
Similarly, it may be necessary to remove many fingerprints at once.

__LOGIN REQUIRE__D

* URL \\
    .../fingerprints/bulk/delete.cmd

* Methods \\
        `POST`

* POST parameters \\
A [command dictionary](/docs/devel/webui_rest/commands/) containing:

| Key | Description |
| --- | ----------- |
| fingerprints | Array of fingerprint MAC address IDs to be removed. |

* Results \\
        `HTTP 200` on success
        HTTP error on failure

