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

    The testable decision layer of phy_cell.

    phy_cell.cc is the single funnel every cell observation passes through on
    its way from a capture helper into Kismet's device tree -- both `cellat`
    and `celldiag`, every RAT, every DIAG log code. This header pulls the pure
    decisions out of it so they can be unit tested.

    The motivating failure mode is silence. A guard in json_to_cell such as

        auto rsrp_j = json["rsrp"];
        if (!rsrp_j.is_number() || rsrp_j.get<int>() == 0)
            return false;

    deletes the entire DIAG leg on any modem whose 0xB193 subpacket version
    has no grounded RSRP scale (v18/v22/v35/v36/v48-RSRQ, roughly half of
    observed traffic), while the datasource still reports running, no errors,
    a live helper and a growing observation count -- and produces zero devices.

    What this file is, and is not. json_to_cell is not a pure function: it
    calls update_common_device, entrytracker, fetch_or_add and takes the
    devicelist mutex. Testing it whole means linking most of the server. What
    is pure is every decision made before that boundary, and those decisions
    determine whether a device appears at all, what MAC it gets, and what it
    is called. So this header holds them, json_to_cell calls them, and
    test_phy_cell_decisions links only this plus fmt.

    The split is between mutation and decision. Both of these are decisions
    and live here:

      * seen_via accumulation  -> prov_field_keys / contributed_fields /
        merge_prov_fields / prov_origin_wins. The entrytracker only allocates
        the record; what goes in it is arithmetic on strings.
      * pci_to_full_identity promotion -> pci_promotion(). The device tree only
        resolves a key to a device; which keys to look up, and whether to look
        at all, is pure. Writing it down is what exposes the cross-RAT
        collision documented on pci_promotion() below.

    Deliberately not covered here, so nobody reads a passing suite as more
    coverage than it is:
      * update_common_device / signal tracking (needs the packet chain)
      * that add_related_device actually links both directions in the tracker --
        pci_promotion() decides the two keys; it cannot observe the insert.
*/

#ifndef __PHY_CELL_DECISIONS_H__
#define __PHY_CELL_DECISIONS_H__

#include <cstdint>
#include <string>
#include <vector>

#include "nlohmann/json.hpp"

namespace cell_decisions {

/* The outcome of key derivation -- the decision that determines whether an
 * observation becomes a device at all, and which device.
 *
 * `key` becomes the device MAC (via cellkey_to_mac), so its format is part of
 * the on-disk contract: change the format string and every existing device forks
 * into a new one, silently, with no error anywhere. The tests pin the literal
 * strings for that reason. */
struct cell_key_t {
    bool valid = false;           /* false -> the observation is dropped */
    bool full_identity = false;   /* true -> mcc+mnc+cid known (globally unique) */
    std::string key;
};

/* Derive the cell key from the identity fields.
 *
 * Two identity levels, in priority order:
 *   full    -- mcc > 0 && mnc >= 0 && cid > 0
 *              -> "{mcc:03d}{mnc:03d}_{tac}_{cid}"   (absent tac encodes as 0)
 *   partial -- pci >= 0 && have_earfcn
 *              -> "{rat}_pci{pci}_{earfcn}"
 * Neither -> valid == false.
 *
 * `mnc >= 0` while `mcc > 0`: MNC 0 is a real value (e.g. MCC 262 / MNC 00),
 * so the two bounds are deliberately different. Making them uniform would delete
 * every observation from an MNC-0 network. */
/* The carrier component of every partial-identity key: the resolved downlink
 * frequency as "f<kHz>", or "e<arfcn>" when the ARFCN falls outside every band
 * table range and cannot be converted.
 *
 * Keyed on frequency rather than the raw ARFCN. LTE band 4 is a subset of
 * band 66 -- one 2145 MHz carrier is EARFCN 2300 to a Quectel and 66786 to a
 * Telit -- so a raw-ARFCN key would track one tower as two devices and split
 * its observation count, RSRP range and seen_via provenance in half.
 * B2/B25 and B12/B17/B85 overlap the same way.
 *
 * Exposed rather than file-static because derive_key() and pci_promotion()
 * both build keys and must agree exactly: peer_cell_key is the device MAC a
 * promotion links to. One spelling, one place. */
std::string carrier_token(const std::string& rat, uint32_t earfcn);

/* ------------------------------------------------------------------------
 * PLMN identity, carried as as-broadcast digits.
 * ------------------------------------------------------------------------ */

/* MCC + MNC with the MNC's digit count intact.
 *
 * The digit count is data, not formatting. WiGLE's cell key is
 * MCC+MNC_xAC_CELLID with the MNC exactly as broadcast -- 2 or 3 digits
 * (GsmOperator.getOperatorKeyString() over CellIdentity.getMncString()), and
 * its /api/v2/cell/search?cell_op=<MCCMNC> and
 * /api/v3/detail/cell/{type}/{operator}/{lac}/{cid} endpoints key on the same
 * string. Zero-padding every MNC to three digits would send Vodafone UK
 * (MNC "15") out as `234015_...` where WiGLE has `23415_...` -- a different
 * network, for every 2-digit-MNC PLMN, which is most of the world outside
 * North America.
 *
 * It is also not recoverable after the fact: MNC "01" and MNC "001" are
 * distinct assignments under the same MCC, and only the broadcast string knows
 * which is on the air. Hence a string here and a string in the JSON contract --
 * the DIAG leg emits strings, and a consumer that
 * accepts only numbers drops every DIAG-sourced identity. */
struct plmn_t {
    bool present = false;   /* false -> no usable PLMN; do not build a full key */
    std::string mcc;        /* exactly 3 digits when present */
    std::string mnc;        /* 2 or 3 digits, AS BROADCAST */

    /* WiGLE's MCCMNC operator token -- the concatenation, never a re-padding. */
    std::string joined() const { return mcc + mnc; }
};

/* Build a PLMN from digits that arrived AS DIGITS -- the lossless path, used by
 * every source that preserved the broadcast string (DIAG/SIB1, and any AT leg
 * that stops calling parse_int on its PLMN field).
 *
 * A short MCC is left-padded to 3: the MCC is fixed at three digits by 3GPP, so
 * a 2-character MCC can only be a dropped leading zero. A short or over-long
 * MNC, or any non-digit, yields present == false rather than a guessed key. */
plmn_t plmn_from_digits(const std::string& mcc, const std::string& mnc);

/* Build a PLMN from NUMBERS, reconstructing the digit count.
 *
 * Lossy fallback, not the contract. capture_cell_at's parse_plmn() turns
 * "460-00" into the integer 0 before we ever see it (cellat_cpsi.inc), so the
 * AT leg leaves nothing to preserve and the count has to be guessed. The guess
 * is WiGLE's own: determineMnc() picks 2 vs 3 from a recognised-MNC table keyed
 * on the MCC; mcc_has_three_digit_mnc() implements the MCC-block form of it.
 *
 * An MNC >= 100 is always written with 3 digits regardless of the block --
 * truncating 262/120 to "20" would name a different network. Anything that can
 * carry the broadcast string should use plmn_from_digits() instead. */
plmn_t plmn_from_numbers(int64_t mcc, int64_t mnc);

/* Read a PLMN out of a cell observation-JSON record, accepting EITHER form.
 *
 * This is the one place that rule lives. Both the live PHY (phy_cell.cc's
 * json_to_cell) and the offline exporter (log_tools/kismetdb_to_wiglecsv.cc)
 * call it, so they cannot disagree. A copy that accepts only numbers scores
 * every DIAG-sourced SIB1 identity (strings, by design) as absent:
 * the live PHY demotes the observation to a PCI-only partial and the exporter
 * counts it as `skipped_fields`.
 *
 * Strings are preferred because they are lossless. A number is accepted and
 * reconstructed via plmn_from_numbers, and mixed forms are handled rather than
 * dropped -- a source can carry SIB1's MCC while filling the MNC from a numeric
 * AT field, and taking the lossless half beats discarding both. */
plmn_t plmn_from_json(const nlohmann::json& j);

/* True for the MCC blocks that broadcast 3-digit MNCs (North America and a
 * documented handful of others). Exposed for the test and for AT-side callers
 * that need the same rule. */
bool mcc_has_three_digit_mnc(int64_t mcc);

/* ------------------------------------------------------------------------
 * LTE ECI split.
 * ------------------------------------------------------------------------ */

/* An LTE ECI is 28 bits: high 20 = eNB-ID, low 8 = sector (3GPP TS 36.413
 * ECGI). Every engineer reading a cell list performs this split by hand.
 *
 * There is deliberately no NR equivalent. The NCI is 36 bits and the
 * gNB-ID length is operator-configured (22-32 bits, carried in SIB1, not
 * derivable from the NCI), so a split here would print a confident wrong
 * number. */
int64_t lte_enb_id(int64_t eci);
int64_t lte_sector(int64_t eci);

/* Derive the cell key from an as-broadcast PLMN. The full-identity branch is
 * "{plmn.joined()}_{tac}_{cid}" -- WiGLE's key, with NO re-padding. */
cell_key_t derive_key(const std::string& rat, const plmn_t& plmn,
        int64_t tac, int64_t cid, int64_t pci, bool have_earfcn, uint32_t earfcn);

/* Numeric-MCC/MNC overload, for callers that never had the digits. Equivalent
 * to derive_key(rat, plmn_from_numbers(mcc, mnc), ...) and kept so the AT-side
 * call sites and the existing tests read unchanged. */
cell_key_t derive_key(const std::string& rat, int64_t mcc, int64_t mnc,
        int64_t tac, int64_t cid, int64_t pci, bool have_earfcn, uint32_t earfcn);

/* Signal-presence policy.
 *
 * Returns whether to populate signal, never whether to keep the observation.
 * Conflating the two collapses "we cannot ground a dBm" and "this is not a
 * cell" into one `return false`. An observation with no usable RSRP
 * still lands as an identity-only device, exactly as the decoder intends
 * when it emits a row with no rsrp key.
 *
 * `rsrp_is_number` / `rsrp` come from the JSON. A literal 0 is treated as absent
 * -- 0 dBm is not a plausible cellular RSRP, and the AT paths use it as a
 * not-reported sentinel. */
bool have_usable_rsrp(bool rsrp_is_number, int rsrp);

/* Derive the LTE band number from an EARFCN (TS 36.101 Table 5.7.3-1).
 * Returns 0 when the EARFCN is in no known band. */
int earfcn_to_band(uint32_t earfcn);

/* ARFCN -> DL centre frequency in kHz (LTE TS 36.101, NR TS 38.104).
 * Returns 0 when the ARFCN cannot be converted. */
uint64_t arfcn_to_khz(const std::string& rat, uint32_t arfcn);

/* The channel string, or "" when no band is known.
 * `explicit_band` is the JSON's own `band` when present (> 0), else 0. */
std::string channel_string(const std::string& rat, int explicit_band,
        bool have_earfcn, uint32_t earfcn);

/* The human-readable device name. Mirrors json_to_cell's three cases:
 * full identity -> "{rat} {key}";  partial with a band -> "{rat} PCI {pci} B{n}";
 * partial without -> "{rat} PCI {pci} EARFCN {earfcn}". */
std::string device_name(const cell_key_t& key, const std::string& rat,
        int64_t pci, uint32_t earfcn, int band_num);

/* ------------------------------------------------------------------------
 * Provenance (seen_via) accumulation.
 * ------------------------------------------------------------------------ */

/* The canonical list of observation fields a provenance source can advertise.
 *
 * Order is the contract, not just the content. contributed_fields() walks
 * this list and filters, rather than walking the JSON -- so a source's field
 * list is in canonical order regardless of how its JSON was serialised, and two
 * sources reporting the same fields produce byte-identical lists. Walking the
 * JSON instead would make the output depend on key insertion order. */
const std::vector<std::string>& prov_field_keys();

/* The fields THIS observation carried, in canonical order.
 *
 * `present` is the set of JSON keys that exist and are non-null. Keys not in
 * prov_field_keys() are dropped: a source cannot advertise a field the schema
 * does not define. */
std::vector<std::string> contributed_fields(const std::vector<std::string>& present);

/* Union `incoming` into `existing`, preserving `existing`'s order and appending
 * genuinely new names.
 *
 * Union, never replace. A tower seen by both capture pipes accumulates
 * identity fields from `at` and signal fields from `diag`; an assignment here
 * would make each observation erase the other pipe's contribution, so the last
 * writer would appear to be the only source of everything. */
void merge_prov_fields(std::vector<std::string>& existing,
        const std::vector<std::string>& incoming);

/* Whether an incoming prov.origin should overwrite the stored one.
 *
 * An absent origin must NOT blank a known one -- the AT pipe stamps an origin
 * and the DIAG pipe may not, and the later observation must not erase it. */
bool prov_origin_wins(const std::string& incoming_origin);

/* ------------------------------------------------------------------------
 * PCI <-> full-identity promotion.
 * ------------------------------------------------------------------------ */

/* The two-directional link between a full-identity tower and a PCI-only sighting
 * of the same cell.
 *
 * Direction 1 (full identity): register this device under `map_key`, and link to
 *   the PCI-only device at `peer_cell_key` if it already exists.
 * Direction 2 (partial): look `map_key` up; if a full-identity device is
 *   registered there, link reciprocally.
 *
 * The RAT qualifier is load-bearing. The peer device key is
 * `"{rat}_pci{pci}_{earfcn}"`; a map key without the rat would let direction 2
 * consult a RAT-less map, and LTE EARFCNs (0..262143) and NR-ARFCNs
 * (0..3279165) overlap completely over the LTE range, as do the PCI ranges
 * (LTE 0..503, NR 0..1007). An NR cell at PCI 100 / NR-ARFCN 1850 would then
 * link itself to an LTE tower at PCI 100 / EARFCN 1850 as the same
 * `cell_identity`: two unrelated cells, related in the UI, with nothing
 * logged. `map_key` carries the rat, so the two keys agree.
 *
 * `active == false` means the whole block is skipped (no PCI, or no EARFCN) and
 * every other field is meaningless. */
struct pci_promotion_t {
    bool active = false;
    bool register_self = false;   /* full identity -> own map_key */
    bool consult_map = false;     /* partial -> look map_key up */
    std::string map_key;
    std::string peer_cell_key;    /* direction 1 only; "" otherwise */
};

pci_promotion_t pci_promotion(const std::string& rat, int64_t pci,
        bool have_earfcn, uint32_t earfcn, bool full_identity);

/* The promotion MAP key -- "{rat}_{pci}_{carrier_token}" -- as one spelling.
 *
 * This is what pci_promotion() stores in `map_key`, extracted so the offline
 * exporter keys its pass-1 PCI->identity table identically. A hand-rolled
 * `"{pci}_{earfcn}"` (raw ARFCN, no rat) would miss the cross-vendor band
 * merges the live PHY makes (B4/B66, B2/B25, B12/B17/B85 -> one carrier via
 * carrier_token), and an LTE PCI/EARFCN could false-merge against an NR
 * PCI/NR-ARFCN over the overlapping ranges. Both writers key on this one
 * function, so they cannot drift.
 *
 * Caller guarantees pci >= 0 and a real earfcn (pci_promotion gates on
 * `pci < 0 || !have_earfcn`; the exporter gates on `pci > 0 && earfcn > 0`). */
std::string promotion_map_key(const std::string& rat, int64_t pci,
        uint32_t earfcn);

/* ------------------------------------------------------------------------
 * The two related-device inserts.
 * ------------------------------------------------------------------------ */

/* One directed related-device edge: `relationship` from the observed device to
 * `peer`. `from_self == true` means the edge hangs off the device this
 * observation just updated; false means it hangs off the peer. */
struct related_link_t {
    bool from_self = false;
    const char *relationship = "";
};

/* The edges phy_cell.cc must insert once a promotion has RESOLVED a peer device.
 *
 * Why this is a decision and not "just two calls": `pci_promotion()` decides
 * the keys and cannot observe the insert, but the insert has a decision inside
 * it that the tracker plays no part in. The edge set must be symmetric and both
 * edges must carry the same relationship name.
 *
 * Kismet's related-device map is keyed by relationship name, so a mismatched
 * name at one call site does not drop a link -- it files the reverse edge under
 * a different relationship, producing a link that resolves from A to B and not
 * from B to A. In a UI that is a cell whose peer knows nothing about it, with
 * nothing logged. Neither the compiler nor any device-tree fixture that checks
 * "a link exists" would catch it.
 *
 * These edges matter on real data: on typical captures the promotion fires for
 * roughly 8-12% of PCI-only observations.
 *
 * Returns exactly two edges whenever a peer resolved, and none otherwise. */
std::vector<related_link_t> related_links(bool peer_resolved);

/* Verdict on a full-identity device claiming `map_key` in pci_to_full_identity.
 *
 * PCI is reused across a network every few kilometres, so (rat, pci, earfcn)
 * is not guaranteed unique among full-identity towers. An unconditional
 * `pci_to_full_identity[map_key] = basedev->get_key()` would be
 * last-writer-wins, and every later PCI-only sighting would link to whichever
 * tower was seen most recently: two unrelated cells, related in the UI, with
 * nothing logged -- within a single RAT, where the rat qualifier cannot help.
 *
 * In practice the map is usually injective. Full identity requires a decoded
 * SIB1, so a capture registers a handful of towers, not the hundreds of
 * PCI-only neighbours it sees. The ambiguity is rare, not impossible, and it
 * grows with capture length and route.
 *
 * Hence a report, not a redesign: `ambiguous` is returned so the caller can
 * decline to link and say so. Guessing between two towers is the thing this
 * codebase already refuses elsewhere for the identical reason -- `diag_wwan_pick`
 * returns -2 rather than choose, because "picking one would be a coin flip that
 * presents as a working source bound to the wrong device". */
enum class map_claim_t {
    claim,       /* slot free -- take it */
    reaffirm,    /* the holder IS this device -- idempotent, no report */
    ambiguous,   /* a DIFFERENT device holds it -- PCI reuse; do not link blind */
};

map_claim_t pci_map_claim(bool slot_occupied, bool holder_is_self);

/* ------------------------------------------------------------------------
 * cell_key -> device MAC.
 * ------------------------------------------------------------------------ */

/* Derive the six-byte synthetic MAC that IS the Kismet device identity for a
 * cell. Two cell_keys mapping to one MAC are one device in the UI, in the
 * device tree, and in kismetdb -- so this is the last place a distinct cell can
 * silently stop being distinct, after every decision above got it right.
 *
 * Invariants, asserted rather than described:
 *   - deterministic: one key always yields one MAC
 *   - bit 1 of byte 0 SET   -- locally administered; this address is synthetic
 *                              and must never be mistaken for an OUI assignment
 *   - bit 0 of byte 0 CLEAR -- unicast; a group-bit address is not a device
 *
 * Why not adler32: a derivation of bytes[0..3] = adler32(key), bytes[4..5] =
 * adler32(key + "_cell") & 0xFFFF does not work. Kismet's adler32 keeps `ls1`
 * as a plain byte sum, and appending a constant salt adds a constant to a byte
 * sum -- the byte sum of "_cell" is exactly 511. So bytes[4..5] would be
 * bytes[2..3] + 511 on every input: the salt contributes nothing, and a 48-bit
 * address carries at most 32 bits, of which the low half is a redundant copy.
 * Collision rates for that scheme:
 *
 *   one LTE EARFCN, every legal PCI 0..503        43% of cells merged
 *   one NR-ARFCN, every legal NR PCI 0..1007      57%
 *   full identity, 50 TAC x 100 CID, one PLMN     52%
 *   one PCI, EARFCN 1..8000                       86%
 *
 * Those are not adversarial inputs; `LTE_pci120_1850` and `LTE_pci201_1850` are
 * two ordinary neighbours on one carrier, and they collide. Full identity is no
 * safer: `310260_1_1000080` and `310260_2_1000007` differ in both TAC and CID
 * and collide. FNV-1a-64 is used instead -- self-contained, no dependency, and
 * it distributes all 48 bits.
 *
 * `cell_key` is stored on the device as-is, so a cell's identity does not
 * depend on the MAC; a MAC in a kismetdb logged with the adler32 scheme will
 * not match the FNV-1a one. */
void cell_key_to_mac_bytes(const std::string& cell_key, uint8_t out[6]);

}  // namespace cell_decisions

#endif /* __PHY_CELL_DECISIONS_H__ */
