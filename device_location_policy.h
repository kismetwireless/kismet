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

    The testable decision behind device_location_signal_threshold.

    The threshold gate is three lines inside device_tracker::update_common_device,
    a method that cannot be called without a packet chain, an entrytracker and
    the devicelist mutex, i.e. most of the server.  The decision inside it is
    arithmetic on three scalars, so it lives here (the same mutation-vs-decision
    split phy_cell_decisions.h makes) where a selftest can reach it.

    Upstream commit 6c47a9e84 ("Add experimental device_location_signal_threshold
    config option") added conf/kismet_filter.conf's documentation and
    devicetracker.cc's implementation in one changeset, and they disagree twice:

    1. The documented key was never read.  The config file's only
       operator-facing line is

           #device_location_signal_threshold_dbm=-65

       and the code fetched `device_location_signal_threshold`, without `_dbm`,
       so uncommenting the shipped line applied no threshold at all.  Both
       spellings are accepted now; the documented one wins when both are
       present.

    2. The semantics were inverted for signal-less packets.  The same comment
       block states the contract:

           "Signal is in dBm and applied to all packet types; packet types which
            do not report a signal level will use all packets."

       The implementation required `pack_l1info != nullptr` before a location
       could be recorded, so a packet carrying no signal level was silently
       excluded, the opposite of "will use all packets".

    Why it matters for phy_cell: on phy_80211 essentially every packet carries
    an l1info, so defect 2 is close to unobservable.  `phy_cell.cc` populates
    `kis_layer1_packinfo` only when `have_usable_rsrp`, and several 0xB193
    subpacket versions (v18 / v22 / v35 / v36) have no grounded RSRP scale, so
    those rows are emitted identity-only by design.  Under a non-zero threshold,
    every one of those observations would lose its location.  The loss is also
    selective by modem, so it presents as "this modem geo-tags and that one
    doesn't", a per-device symptom with a global cause.
*/

#ifndef __DEVICE_LOCATION_POLICY_H__
#define __DEVICE_LOCATION_POLICY_H__

namespace device_location_policy {

/* Should this packet's GPS fix be admitted into the device's running location
 * average?
 *
 * Deliberately header-only and dependency-free so the selftest links nothing:
 * the value of pulling this out is that it can be exercised without a server.
 *
 *   threshold_dbm  the configured device_location_signal_threshold[_dbm];
 *                  0 means the feature is off
 *   have_signal    whether the packet carries a kis_layer1_packinfo at all
 *   signal_dbm     that packinfo's signal_dbm; meaningless when !have_signal
 *
 * The `!have_signal -> true` arm is deliberate.  Returning false there is
 * defensible in the abstract ("we cannot prove it is close enough"), but it is
 * not what the feature documents, and it silently deletes an entire class of
 * observation rather than filtering a weak one.
 *
 * Do not "simplify" this to `signal_dbm >= threshold_dbm` guarded by the
 * caller's null check.  With the null check in the same boolean expression as
 * the comparison, the exclusion reads as a precondition rather than as a
 * decision. */
inline bool admits_location(int threshold_dbm, bool have_signal, int signal_dbm) {
    /* Feature off (the default) -- every packet with a fix is geo-tagged. */
    if (threshold_dbm == 0)
        return true;

    /* Documented: "packet types which do not report a signal level will use
     * all packets." No measurement means nothing to threshold against. */
    if (!have_signal)
        return true;

    return signal_dbm >= threshold_dbm;
}

}  // namespace device_location_policy

#endif /* __DEVICE_LOCATION_POLICY_H__ */
