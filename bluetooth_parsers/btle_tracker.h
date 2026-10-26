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
*/

#ifndef __BTLE_TRACKER_H__
#define __BTLE_TRACKER_H__

/* Bluetooth LE location trackers (item finders) which advertise their state in
 * the clear.  Only the public, unencrypted parts of the advertisement are decoded:
 * nothing here identifies the owner or talks to the vendor network.
 *
 * Samsung Galaxy SmartTag / SmartTag2 (SmartThings Find), 16-bit service data
 * with the Samsung UUID 0xFD5A.  Layout of the payload after the UUID:
 *
 *   0       frame id (upper 5 bits) and operating state (lower 3 bits)
 *   1-3     aging counter, 24 bit little endian
 *   4-11    privacy ID; rotates, not a permanent identity
 *   12      flags: battery level in bits 0-1, UWB support in bit 2; the region and
 *           encryption bits are not publicly documented
 *   13-     not publicly documented; not decoded
 *
 * Observed on a separated SmartTag over an hour: the random address changed about every
 * 15 minutes, the aging counter went up by one about as often, and the privacy ID, the
 * flags and bytes 13-15 (zero) stayed the same, so while separated the privacy ID links
 * the advertisements across address changes.  Bytes 16-19 changed with the aging
 * counter, a signature by the look of it.
 *
 * Operating states: 1 premature offline, 2 offline, 3 overmature offline (away from
 * the owner for more than 24 hours), 4-6 connected to one or more owner devices.
 *
 * Sources: T. Yu, J. Henderson, A. Tiu, T. Haines, "Security and Privacy Analysis of
 * Samsung's Crowd-Sourced Bluetooth Location Tracking System", USENIX Security 2024;
 * the field offsets match the SamsungTracker decoder of SEEMOO's AirGuard
 * (github.com/seemoo-lab/AirGuard).  This is an independent implementation.
 *
 * Apple Find My (offline finding), manufacturer data with Apple's company ID 0x004C.
 * The payload after the company ID starts with Apple's type 0x12 and a length byte:
 *
 *   0       type 0x12
 *   1       length: 0x19 while separated from the owner, 0x02 while near it
 *   2       status: device type in bits 4-5 (0 Apple device such as an iPhone or Mac,
 *           1 AirTag, 2 Find My network accessory, 3 AirPods), battery level in bits 6-7
 *           (0 full, 1 medium, 2 low, 3 very low)
 *   3-24    separated frame: bytes 6-27 of the rotating public key; together with the
 *           address, which holds key bytes 0-5, this is the whole key
 *   25      separated frame: the two top bits of key byte 0
 *   26      separated frame: hint
 *
 * The device type and battery bits are not decoded from any other part of the frame.
 * Apple devices (type 0) send the same frame when they are lost or switched off; they
 * are not location trackers and are not reported as such.
 *
 * Sources: A. Heinrich, M. Stute, T. Kornhuber, M. Hollick, "Who Can Find My Devices?
 * Security and Privacy of Apple's Crowd-Sourced Bluetooth Location Tracking System",
 * PETS 2021, and the advertisement of SEEMOO's OpenHaystack firmware
 * (github.com/seemoo-lab/openhaystack) for the separated frame; the status bits as
 * used by AirGuard (AppleFindMy, DeviceManager).  The near-owner frame is not in these
 * sources; it was checked against a real AirTag near its owner's iPhone.
 *
 * Google Find My Device network (FMDN, Find Hub), 16-bit service data with the
 * Eddystone UUID 0xFEAA and an FMDN frame type:
 *
 *   0       frame type: 0x40, or 0x41 in unwanted tracking protection mode
 *   1-20    ephemeral identifier (160-bit curve), or
 *   1-32    ephemeral identifier (256-bit curve, extended advertising only)
 *   21/33   hashed flags (optional): battery level and unwanted tracking protection
 *           mode, xor-ed with a byte derived from the ephemeral key; not decodable
 *           without the key and not decoded
 *
 * The ephemeral identifier rotates every 1024 seconds.  Unwanted tracking protection
 * mode is switched on through the Find Hub network so that phones nearby can detect
 * the tag; the tag then rotates its address only once a day.  The frame does not say
 * in the clear whether the tag is away from its owner: FMDN tags follow DULT (below)
 * for that.
 *
 * Source: Google, "Find My Device Network Accessory Specification" (Fast Pair
 * extension, developers.google.com/nearby/fast-pair/specifications/extensions/fmdn),
 * advertised frames and unwanted tracking protection mode.
 *
 * Detecting Unwanted Location Trackers (DULT), 16-bit service data with the UUID
 * 0xFCB2, the platform-independent payload a location tracker has to advertise while
 * it is separated from its owner, and may advertise while near it:
 *
 *   0       network ID of the finding network; the registry is not published yet
 *   1       near-owner bit in bit 0 (1 near owner, 0 separated), bits 1-7 reserved
 *   2-      proprietary company payload; not decoded
 *
 * While near the owner the tag rotates its address every 15 minutes, while separated
 * once every 24 hours.
 *
 * Source: B. Ledvina, D. Lazarov, B. Detwiler, S. P. Polatkan, "Detecting Unwanted
 * Location Trackers Accessory Protocol", draft-ietf-dult-accessory-protocol-00,
 * sections 3.4 to 3.9.
 *
 * The decoders only depend on the standard library and bounds check everything.
 */

#include <cstddef>
#include <cstdint>
#include <string>

namespace btle_tracker {

enum class tracker_type : uint8_t {
    none = 0,
    samsung_smarttag = 1,
    apple_findmy = 2,
    google_fmdn = 3,
    dult = 4,
};

enum class battery_level : uint8_t {
    very_low = 0,
    low = 1,
    medium = 2,
    full = 3,
};

/* Samsung's 16-bit service UUID */
constexpr uint16_t samsung_service_uuid = 0xFD5A;

/* SmartTag frame id, matched under smarttag_frame_mask against byte 0 */
constexpr uint8_t smarttag_frame_id = 0x10;
constexpr uint8_t smarttag_frame_mask = 0xF8;

/* Payload bytes up to and including the flags byte */
constexpr size_t smarttag_min_len = 13;
constexpr size_t smarttag_privacy_id_len = 8;

struct smarttag_info {
    uint8_t state = 0;
    uint32_t aging_counter = 0;
    /* Raw bytes, smarttag_privacy_id_len long */
    std::string privacy_id;
    uint8_t flags = 0;

    /* Premature, regular, or overmature offline: not near any of the owner's devices */
    bool separated() const {
        return state >= 1 && state <= 3;
    }

    battery_level battery() const {
        return static_cast<battery_level>(flags & 0x03);
    }

    bool uwb() const {
        return (flags & 0x04) != 0;
    }
};

/* Apple's company ID and the Find My (offline finding) type and lengths */
constexpr uint16_t apple_company_id = 0x004C;
constexpr uint8_t findmy_type = 0x12;
constexpr uint8_t findmy_len_separated = 0x19;
constexpr uint8_t findmy_len_near_owner = 0x02;

/* Find My device types in bits 4-5 of the status byte */
constexpr uint8_t findmy_device_apple = 0;
constexpr uint8_t findmy_device_airtag = 1;
constexpr uint8_t findmy_device_accessory = 2;
constexpr uint8_t findmy_device_airpods = 3;

struct findmy_info {
    uint8_t status = 0;
    /* The long frame, sent while away from the owner */
    bool separated_frame = false;

    bool separated() const {
        return separated_frame;
    }

    uint8_t device_type() const {
        return (status >> 4) & 0x03;
    }

    /* Apple counts the battery level down from 0 (full) */
    battery_level battery() const {
        return static_cast<battery_level>(3 - ((status >> 6) & 0x03));
    }

    /* AirTags, Find My network accessories and AirPods; not iPhones, iPads or Macs */
    bool location_tracker() const {
        return device_type() != findmy_device_apple;
    }
};

/* Eddystone's 16-bit service UUID, which FMDN shares, and the FMDN frame types */
constexpr uint16_t google_fmdn_service_uuid = 0xFEAA;
constexpr uint8_t fmdn_frame = 0x40;
constexpr uint8_t fmdn_frame_utp = 0x41;
constexpr size_t fmdn_eid_len_160 = 20;
constexpr size_t fmdn_eid_len_256 = 32;

struct fmdn_info {
    uint8_t frame_type = 0;
    /* Raw bytes, fmdn_eid_len_160 or fmdn_eid_len_256 long */
    std::string ephemeral_id;
    bool hashed_flags = false;

    bool unwanted_tracking_protection() const {
        return frame_type == fmdn_frame_utp;
    }
};

/* DULT 16-bit service UUID */
constexpr uint16_t dult_service_uuid = 0xFCB2;

/* Payload bytes up to and including the near-owner byte */
constexpr size_t dult_min_len = 2;

struct dult_info {
    uint8_t network_id = 0;
    /* Near-owner bit and the reserved bits, raw */
    uint8_t status = 0;

    bool near_owner() const {
        return (status & 0x01) != 0;
    }

    bool separated() const {
        return !near_owner();
    }
};

/* 16-bit service data (the AD record after the 0x16 type byte: UUID, then payload).
 * Returns false unless it is a SmartTag frame of at least the documented length. */
bool decode_samsung_smarttag(const uint8_t *data, size_t len, smarttag_info& out);

/* Manufacturer data (the AD record after the 0xFF type byte: company ID, then payload).
 * Returns false unless it is an Apple Find My frame of one of the two known lengths;
 * check location_tracker() before treating the sender as a tracker. */
bool decode_apple_findmy(const uint8_t *data, size_t len, findmy_info& out);

/* 16-bit service data.  Returns false unless it is an FMDN frame of a documented length;
 * Eddystone frames in the same UUID are not FMDN frames. */
bool decode_google_fmdn(const uint8_t *data, size_t len, fmdn_info& out);

/* 16-bit service data.  Returns false unless it is a DULT frame of at least the
 * documented length. */
bool decode_dult(const uint8_t *data, size_t len, dult_info& out);

const char *tracker_type_str(tracker_type type);
const char *battery_level_str(battery_level level);

/* premature_offline, offline, overmature_offline, connected, or unknown */
const char *smarttag_state_str(uint8_t state);

/* apple_device, airtag, findmy_accessory, or airpods */
const char *findmy_device_type_str(uint8_t device_type);

/* separated or near_owner, for the Apple Find My and the DULT frames */
const char *separated_state_str(bool separated);

/* unwanted_tracking_protection or normal */
const char *fmdn_state_str(const fmdn_info& info);

}

#endif
