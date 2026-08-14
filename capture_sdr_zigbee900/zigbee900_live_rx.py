#!/usr/bin/env python3
"""
Live 900MHz legacy 802.15.4 BPSK receiver tested on RTL-SDR Blog V4.

Meant to be spawned as a long-running subprocess by a Kismet C capture
helper (in the style of capture_sdr_rtl433_v2.c spawning rtl_433): Tunes
to a starting channel, decodes continuously, and accepts live channel
retunes via stdin so Kismet's normal channel-hop cadence doesn't require
respawning the process (GNU Radio/flowgraph startup is far too slow for
that; retuning an already-running osmosdr source is fast).

stdin protocol:   "CHANNEL <n>\n"   -> retune to IEEE 802.15.4-2006 channel n
                                       (906 + 2*(n-1) MHz, n=1..10, 6.1.2.1)
stdout protocol:  one hex-encoded PSDU per decoded, CRC-valid frame, e.g.
                  "PSDU <channel> <hex bytes>\n"

RF chain and chip-mapping tables are the same ones validated earlier against
the actual IEEE Std 802.15.4-2006 PDF (clause 6.6) and against a real
over-the-air capture from a Freaklabs 328P/900MHz board (55 frames, 0% loss,
CRC-valid). This file adds: continuous operation, live retuning, and a
custom real-time decode block with parallel Start-of-Frame-Delimiter (SFD) 
searching candidates gated by CRC-16 validation, so it works on arbitrary 
traffic.
"""
import os
import sys

# SoapySDR/librtlsdr's device probing (triggered by osmosdr.source()) has
# been observed to silently repoint fd 1/2 away from the pipes Kismet's C
# glue reads from; our own stdout/stderr writes after that point never
# arrive, even though the flowgraph itself starts and runs fine.
# Save the real fds now, before any of that can happen, so we
# can force them back after flowgraph construction.
_ORIG_STDOUT_FD = os.dup(1)
_ORIG_STDERR_FD = os.dup(2)

import time
import numpy as np
from gnuradio import gr, blocks, filter, analog, digital, fft
from gnuradio.filter import firdes
import osmosdr


def restore_stdio_fds():
    os.dup2(_ORIG_STDOUT_FD, 1)
    os.dup2(_ORIG_STDERR_FD, 2)

SAMP_RATE = 2.4e6
CHIP_RATE = 600e3
SPS = SAMP_RATE / CHIP_RATE          # 4.0 samples/chip
RTL_GAIN = 30.0
# Measured RTL-SDR + board crystal offset at channel 1 (906MHz); applied as
# a constant approximation across the 906-924MHz band.
FREQ_CAL_OFFSET = -29e3

TEMPLATE0 = np.array([1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0], dtype=np.uint8)
TEMPLATE1 = np.array([0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1], dtype=np.uint8)
SFD_BITS = np.array([1, 1, 1, 0, 0, 1, 0, 1], dtype=np.uint8)
BIT_WEIGHTS = (1 << np.arange(8)).astype(np.uint16)

MAX_PSDU_BYTES = 127                  # aMaxPHYPacketSize, 6.4.1
MAX_FRAME_CHIPS = (1 + MAX_PSDU_BYTES) * 8 * 15   # PHR + PSDU, generous
WINDOW_CHIPS = 20000                  # rolling buffer size, trimmed periodically

# ## O-QPSK optional PHY (902-928MHz band, same channel plan as BPSK ##
# IEEE 802.15.4-2006 Table 2, channel page 2) clause 6.8. Verified against
# the actual standard PDF text
OQPSK_CHIP_RATE = 1.0e6        # Table 1, 902-928MHz band
OQPSK_SYMBOL_RATE = 62.5e3     # = OQPSK_CHIP_RATE / 16 (16 chips/symbol)
OQPSK_SPS = SAMP_RATE / OQPSK_CHIP_RATE   # 2.4 samples/chip

# Table 37 - symbol-to-chip mapping for O-QPSK. Row index == the symbol's
# decimal value (b0 is LSB, matches the "Data symbol (decimal)" column).
OQPSK_CHIP_TABLE = np.array([
    [0,0,1,1,1,1,1,0,0,0,1,0,0,1,0,1],  # 0  (0000)
    [0,1,0,0,1,1,1,1,1,0,0,0,1,0,0,1],  # 1  (1000)
    [0,1,0,1,0,0,1,1,1,1,1,0,0,0,1,0],  # 2  (0100)
    [1,0,0,1,0,1,0,0,1,1,1,1,1,0,0,0],  # 3  (1100)
    [0,0,1,0,0,1,0,1,0,0,1,1,1,1,1,0],  # 4  (0010)
    [1,0,0,0,1,0,0,1,0,1,0,0,1,1,1,1],  # 5  (1010)
    [1,1,1,0,0,0,1,0,0,1,0,1,0,0,1,1],  # 6  (0110)
    [1,1,1,1,1,0,0,0,1,0,0,1,0,1,0,0],  # 7  (1110)
    [0,1,1,0,1,0,1,1,0,1,1,1,1,0,0,0],  # 8  (0001)
    [0,0,0,1,1,0,1,0,1,1,0,1,1,1,0,0],  # 9  (1001)
    [0,0,0,0,0,1,1,0,1,0,1,1,0,1,1,1],  # 10 (0101)
    [1,1,0,0,0,0,0,1,1,0,1,0,1,1,0,1],  # 11 (1101)
    [0,1,1,1,0,0,0,0,0,1,1,0,1,0,1,1],  # 12 (0011)
    [1,1,0,1,1,1,0,0,0,0,0,1,1,0,1,0],  # 13 (1011)
    [1,0,1,1,0,1,1,1,0,0,0,0,0,1,1,0],  # 14 (0111)
    [1,0,1,0,1,1,0,1,1,1,0,0,0,0,0,1],  # 15 (1111)
], dtype=np.uint8)

# SFD (Figure 17, bits 0-7 = 1,1,1,0,0,1,0,1, LSB-first -> byte 0xA7) is
# formatted identically across all non-ASK PHYs. Under O-QPSK's per-octet
# bit-to-symbol mapping (6.8.2.2: 4 LSBs of each octet -> one symbol, 4 MSBs
# -> the next), 0xA7's low nibble (bits 0-3 = 1,1,1,0 -> symbol 7) is
# transmitted first, then its high nibble (bits 4-7 = 0,1,0,1 -> symbol 10).
OQPSK_SFD_SYM_LOW = 7
OQPSK_SFD_SYM_HIGH = 10

# Extended 32-row table: original 16 codewords + their bitwise complements,
# so a single correlation pass handles both polarities at once. Correlating
# an inverted buffer against OQPSK_CHIP_TABLE is mathematically identical to
# correlating the non-inverted buffer against OQPSK_CHIP_TABLE's complement
# (Hamming distance is invariant under simultaneous complementation of both
# operands), so this eliminates the need to maintain a separate `1-buf`
# candidate set entirely; argmin index // 16 gives the symbol, and
# whether it's >= 16 gives which polarity matched.
OQPSK_CHIP_TABLE_EXT = np.concatenate([OQPSK_CHIP_TABLE, 1 - OQPSK_CHIP_TABLE], axis=0)

# Bit-packed form of the same 32-row table, used by oqpsk_correlate_all's
# XOR+popcount fast path below: each 16-chip codeword packed into one
# integer (chip k -> bit k), precomputed once since the table is constant.
_OQPSK_BIT_WEIGHTS = (1 << np.arange(16)).astype(np.uint32)
_OQPSK_PACKED_CODEWORDS = (OQPSK_CHIP_TABLE_EXT.astype(np.uint32) * _OQPSK_BIT_WEIGHTS).sum(axis=1)
# 16-bit popcount lookup table (65536 entries, built once at import time).
_POPCOUNT16 = np.array([bin(i).count('1') for i in range(65536)], dtype=np.uint8)


def oqpsk_correlate_all(buf):
    """Nearest-neighbor symbol match at EVERY possible chip offset in `buf`,
    both polarities at once, in a single vectorized pass.

    Returns a uint8 array of shape (len(buf)-15,): symbols[i] is the best-
    matching symbol (0-15) for the 16-chip window starting at buf[i],
    checking both polarities."""
    if len(buf) < 16:
        return np.zeros(0, dtype=np.uint8)
    windows = np.lib.stride_tricks.sliding_window_view(buf, 16)
    packed_windows = (windows.astype(np.uint32) * _OQPSK_BIT_WEIGHTS).sum(axis=1)
    xor_vals = packed_windows[:, None] ^ _OQPSK_PACKED_CODEWORDS[None, :]
    dists = _POPCOUNT16[xor_vals]
    best = np.argmin(dists, axis=1)
    return (best % 16).astype(np.uint8)


def freq_for_channel(channel):
    """IEEE 802.15.4-2006 6.1.2.1, page 0/915MHz band: Fc = 906 + 2*(k-1)."""
    if not (1 <= channel <= 10):
        raise ValueError(f"channel {channel} outside 900MHz band (1-10)")
    return 906e6 + 2e6 * (channel - 1) + FREQ_CAL_OFFSET


def crc16_ccitt(data):
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc


class Candidate:
    """One (phase, polarity) despread/diff-decode/frame-sync lane."""

    SEARCHING, IN_PHR, IN_PSDU = range(3)

    def __init__(self, phase, polarity):
        self.phase = phase
        self.polarity = polarity
        self.en_prev = 0
        self.state = Candidate.SEARCHING
        self.frame_len = None
        # global bit index of the last SFD this candidate has already acted
        # on (whether or not it produced a CRC-valid frame), so repeated
        # rescans of the rolling window never reconsider it
        self.last_sfd_bit = -1

    def process(self, chips_global_start, chips):
        """chips: 1D uint8 array (0/1) covering [chips_global_start, ...).
        Returns a list of (global_bit_index_of_frame_end, psdu_bytes)."""
        results = []

        start = (self.phase - chips_global_start) % 15
        # align first window to this candidate's phase within the buffer
        trimmed = chips[start:]
        n_bits = len(trimmed) // 15
        if n_bits < 16:
            return results
        windows = trimmed[:n_bits * 15].reshape(n_bits, 15)

        d0 = np.count_nonzero(windows != TEMPLATE0, axis=1)
        d1 = np.count_nonzero(windows != TEMPLATE1, axis=1)
        en = (d1 < d0).astype(np.uint8)

        rn = np.empty(n_bits, dtype=np.uint8)
        rn[0] = en[0] ^ self.en_prev
        rn[1:] = en[1:] ^ en[:-1]

        # global bit index of rn[0] is (chips_global_start+start)/15
        base_bit_index = (chips_global_start + start) // 15

        if len(rn) >= 8:
            windows8 = np.lib.stride_tricks.sliding_window_view(rn, 8)
            sfd_hits = np.nonzero(np.all(windows8 == SFD_BITS, axis=1))[0]
            for hit in sfd_hits:
                sfd_bit = base_bit_index + hit
                if sfd_bit <= self.last_sfd_bit:
                    continue

                phr_start = hit + 8
                if phr_start + 8 > len(rn):
                    # not enough data yet to read the PHR; don't mark this
                    # SFD as considered, so we can retry once more chips
                    # arrive; just stop scanning this candidate for now
                    break

                phr_bits = rn[phr_start:phr_start + 7]
                frame_len = int(sum(int(b) << k for k, b in enumerate(phr_bits)))
                if frame_len == 0 or frame_len > MAX_PSDU_BYTES:
                    self.last_sfd_bit = sfd_bit
                    continue

                psdu_start = phr_start + 8
                psdu_end = psdu_start + frame_len * 8
                if psdu_end > len(rn):
                    # frame not fully arrived yet; retry later, don't mark consumed
                    break

                self.last_sfd_bit = sfd_bit

                psdu_bits = rn[psdu_start:psdu_end]
                n_bytes = frame_len
                b = psdu_bits.reshape(n_bytes, 8).astype(np.uint16)
                psdu = bytes((b * BIT_WEIGHTS).sum(axis=1).astype(np.uint8).tolist())

                data, fcs = psdu[:-2], psdu[-2:]
                if len(fcs) == 2 and crc16_ccitt(data) == (fcs[0] | (fcs[1] << 8)):
                    results.append((sfd_bit, psdu))

        if len(en):
            self.en_prev = int(en[-1])

        return results


class OqpskPhaseTrack:
    """Per-phase SFD/PHR/CRC frame-sync state for one of the 16 possible
    chip-alignments. Unlike the original OqpskCandidate, this does NOT do
    its own correlation. Correlation now happens once for the whole buffer
    (all 16 phases and both polarities at once) via oqpsk_correlate_all()
    and this class just scans its own phase's slice of the shared result.
    Unlike BPSK's Candidate, there is no differential decoding step (clause
    6.8.2 has no differential-encoding subclause)."""

    def __init__(self, phase):
        self.phase = phase
        # global symbol index of the last SFD pair this phase has already
        # acted on, so repeated rescans of the rolling window never
        # reconsider it (mirrors Candidate.last_sfd_bit)
        self.last_sfd_sym = -1

    def scan(self, chips_global_start, symbols_all):
        """symbols_all: the FULL per-offset symbol array from
        oqpsk_correlate_all(buf), where buf starts at chips_global_start.
        Returns a list of (global_symbol_index_of_sfd, psdu_bytes)."""
        results = []

        start = (self.phase - chips_global_start) % 16
        symbols = symbols_all[start::16]
        base_sym_index = (chips_global_start + start) // 16

        if len(symbols) >= 2:
            pair_hits = np.nonzero(
                (symbols[:-1] == OQPSK_SFD_SYM_LOW) &
                (symbols[1:] == OQPSK_SFD_SYM_HIGH))[0]
            for hit in pair_hits:
                sfd_sym = base_sym_index + hit
                if sfd_sym <= self.last_sfd_sym:
                    continue

                phr_start = hit + 2
                if phr_start + 2 > len(symbols):
                    break  # PHR not fully arrived; retry later, don't consume

                phr_byte = int(symbols[phr_start]) | (int(symbols[phr_start + 1]) << 4)
                frame_len = phr_byte & 0x7F  # 7-bit length field, 6.3.3
                if frame_len == 0 or frame_len > MAX_PSDU_BYTES:
                    self.last_sfd_sym = sfd_sym
                    continue

                psdu_sym_start = phr_start + 2
                psdu_sym_end = psdu_sym_start + frame_len * 2
                if psdu_sym_end > len(symbols):
                    break  # frame not fully arrived yet, retry later

                self.last_sfd_sym = sfd_sym

                psdu_syms = symbols[psdu_sym_start:psdu_sym_end]
                low = psdu_syms[0::2].astype(np.uint16)
                high = psdu_syms[1::2].astype(np.uint16)
                psdu = bytes((low | (high << 4)).astype(np.uint8).tolist())

                data, fcs = psdu[:-2], psdu[-2:]
                if len(fcs) == 2 and crc16_ccitt(data) == (fcs[0] | (fcs[1] << 8)):
                    results.append((sfd_sym, psdu))

        return results


class ZigbeeLiveDecoder(gr.sync_block):
    def __init__(self, on_frame):
        gr.sync_block.__init__(self, name="zigbee900_live_decoder",
                                in_sig=[np.float32], out_sig=None)
        self.on_frame = on_frame
        self.candidates = [Candidate(phase, pol) for pol in (0, 1) for phase in range(15)]
        self.chip_buffer = np.zeros(0, dtype=np.uint8)
        self.chip_buffer_start = 0     # global chip index of chip_buffer[0]
        self.chips_since_last_process = 0
        # Cross-candidate dedup: the preamble's long run of identical 15-chip
        # windows means many nearby (phase, polarity) candidates can each
        # independently decode the SAME real burst correctly, so per-candidate
        # dedup alone isn't enough; track recently-emitted PSDU content
        # globally too (bounded, insertion-ordered for eviction).
        self.recent_psdus = []
        self.recent_psdus_set = set()
        self.RECENT_PSDU_MAX = 64

    def work(self, input_items, output_items):
        samples = input_items[0]
        chips_normal = (samples > 0).astype(np.uint8)

        self.chip_buffer = np.concatenate([self.chip_buffer, chips_normal])
        self.chips_since_last_process += len(chips_normal)

        if self.chips_since_last_process >= 1500:
            self._process_window()
            self.chips_since_last_process = 0

        return len(samples)

    def _process_window(self):
        buf = self.chip_buffer
        start = self.chip_buffer_start

        for cand in self.candidates:
            chips = buf if cand.polarity == 0 else (1 - buf)
            for sfd_bit, psdu in cand.process(start, chips):
                if not any(psdu):
                    continue   # all-zero PSDU: squelched-silence false positive
                                # (CRC-16 of an all-zero buffer is trivially 0,
                                # so it "validates" against an all-zero FCS)
                if psdu in self.recent_psdus_set:
                    continue   # another candidate already reported this burst
                self.recent_psdus_set.add(psdu)
                self.recent_psdus.append(psdu)
                if len(self.recent_psdus) > self.RECENT_PSDU_MAX:
                    oldest = self.recent_psdus.pop(0)
                    self.recent_psdus_set.discard(oldest)
                self.on_frame(psdu)

        if len(buf) > WINDOW_CHIPS:
            trim = len(buf) - WINDOW_CHIPS
            self.chip_buffer = buf[trim:]
            self.chip_buffer_start += trim


class OqpskLiveDecoder(gr.sync_block):
    """O-QPSK counterpart of ZigbeeLiveDecoder. Input is a real-valued
    already-sliced chip stream (0.0/1.0) at the O-QPSK chip rate, produced
    by the front end's quadrature-demod + chip-clock-recovery + slicer
    chain (see Rx900Live); this block only does the symbol
    correlation/frame-sync/CRC layer, same division of labor as the BPSK
    decoder."""

    def __init__(self, on_frame):
        gr.sync_block.__init__(self, name="oqpsk900_live_decoder",
                                in_sig=[np.float32], out_sig=None)
        self.on_frame = on_frame
        self.tracks = [OqpskPhaseTrack(phase) for phase in range(16)]
        self.chip_buffer = np.zeros(0, dtype=np.uint8)
        self.chip_buffer_start = 0
        # Incremental symbol cache, kept in lockstep with chip_buffer.
        # symbols_cache[j] is the correlator's answer for the 16-chip window
        # starting at global chip position (chip_buffer_start + j). Once
        # computed it never changes, so each new batch of chips only needs
        # correlating against the ~1600 NEW positions plus 15 chips of
        # look-back context, not the entire ~20000-chip rolling buffer from
        # scratch. This was the dominant cost, not the 32-way candidate
        # search: even after batching all 16 phases + both polarities into
        # one correlation call, re-running that over the full buffer every
        # 1600 new chips measured at ~27ms/call against a 1.6ms real-time
        # budget (1Mchip/s / 1600), approx 17x too slow. Incremental caching
        # drops the per-call cost from O(buffer size) to O(new chips).
        self.symbols_cache = np.zeros(0, dtype=np.uint8)
        # accumulate incoming chunks and concatenate once per batch instead
        # of once per work() call
        self._pending_chunks = []
        self._pending_count = 0
        self.recent_psdus = []
        self.recent_psdus_set = set()
        self.RECENT_PSDU_MAX = 64

    def work(self, input_items, output_items):
        samples = input_items[0]
        chips_normal = (samples > 0).astype(np.uint8)

        self._pending_chunks.append(chips_normal)
        self._pending_count += len(chips_normal)

        if self._pending_count >= 1600:
            new_chunk = np.concatenate(self._pending_chunks)
            self._pending_chunks = []
            self._pending_count = 0
            self._process_new_chunk(new_chunk)

        return len(samples)

    def _process_new_chunk(self, new_chunk):
        old_len = len(self.chip_buffer)
        self.chip_buffer = np.concatenate([self.chip_buffer, new_chunk])

        if old_len == 0:
            # first batch ever: no cache, no look-back context needed
            to_correlate = self.chip_buffer
        else:
            # 15 chips of look-back so the earliest new window position
            # (which straddles the old/new boundary) still has full context
            to_correlate = np.concatenate([self.chip_buffer[old_len - 15:old_len], new_chunk])
        new_symbols = oqpsk_correlate_all(to_correlate)
        self.symbols_cache = np.concatenate([self.symbols_cache, new_symbols])

        start = self.chip_buffer_start
        for track in self.tracks:
            for sfd_sym, psdu in track.scan(start, self.symbols_cache):
                if not any(psdu):
                    continue  # all-zero PSDU: same squelched-silence false
                              # positive risk as the BPSK path
                if psdu in self.recent_psdus_set:
                    continue  # another phase already reported this burst
                self.recent_psdus_set.add(psdu)
                self.recent_psdus.append(psdu)
                if len(self.recent_psdus) > self.RECENT_PSDU_MAX:
                    oldest = self.recent_psdus.pop(0)
                    self.recent_psdus_set.discard(oldest)
                self.on_frame(psdu)

        if len(self.chip_buffer) > WINDOW_CHIPS:
            trim = len(self.chip_buffer) - WINDOW_CHIPS
            self.chip_buffer = self.chip_buffer[trim:]
            self.chip_buffer_start += trim
            self.symbols_cache = self.symbols_cache[trim:]


class Rx900Live(gr.top_block):
    def __init__(self, initial_channel, on_frame):
        gr.top_block.__init__(self, "zigbee900_live_rx")

        # explicitly request only the rtl backend.
        self.src = osmosdr.source(args="rtl=0,numchan=1")
        self.src.set_sample_rate(SAMP_RATE)
        self.src.set_center_freq(freq_for_channel(initial_channel))
        self.src.set_freq_corr(0)
        self.src.set_gain_mode(False)
        self.src.set_gain(RTL_GAIN)
        self.src.set_if_gain(20)
        self.src.set_bb_gain(20)
        self.src.set_bandwidth(1.5e6)

        taps = firdes.low_pass(1.0, SAMP_RATE, 700e3, 300e3, fft.window.WIN_HAMMING)
        self.lpf = filter.fir_filter_ccf(1, taps)

        self.squelch = analog.pwr_squelch_cc(-20.0, alpha=0.01, ramp=100, gate=False)
        self.agc = analog.agc_cc(rate=0.0, reference=1.0, gain=1.0, max_gain=4.0)
        self.costas = digital.costas_loop_cc(0.06, 2, False)
        self.sync = digital.symbol_sync_cc(
            digital.TED_MUELLER_AND_MULLER, SPS,
            2 * 3.14159265 * 0.045, 1.0, 1.0, 1.5, 1,
            digital.constellation_bpsk().base(),
        )
        self.c2r = blocks.complex_to_real(1)
        self.decoder = ZigbeeLiveDecoder(on_frame)

        self.connect(self.src, self.lpf, self.squelch, self.agc, self.costas,
                     self.sync, self.c2r, self.decoder)

        # Parallel O-QPSK branch (6.8) - taps self.src directly (before
        # the BPSK-narrow filter above) since O-QPSK's ~1MHz chip rate needs
        # roughly double BPSK's occupied bandwidth. No differential encoding
        # in this PHY (unlike BPSK), and only a 128us preamble to lock onto
        # (vs BPSK's 800us) rules out a Costas-loop coherent approach the
        # same way BPSK uses one. Half-sine-shaped O-QPSK is mathematically
        # equivalent to MSK, so this uses a non-coherent FM-discriminator
        # (quadrature demod) instead, which never needs absolute carrier
        # phase lock at all. UNVERIFIED AGAINST REAL DEVICE: no O-QPSK-capable
        # hardware has been acquired yet, so these front-end DSP parameters
        # (filter width, squelch/AGC thresholds, discriminator gain, clock
        # recovery constants) are theory-derived starting points, not
        # empirically tuned the way BPSK's chain was. The symbol
        # correlator/frame-sync/CRC logic downstream of this (OqpskCandidate)
        # IS rigorously tested, offline, against synthetic known-plaintext
        # chip streams (test_oqpsk_candidate.py, test_oqpsk_full_decoder.py).
        oqpsk_taps = firdes.low_pass(1.0, SAMP_RATE, 1.0e6, 400e3, fft.window.WIN_HAMMING)
        self.oqpsk_lpf = filter.fir_filter_ccf(1, oqpsk_taps)

        self.oqpsk_squelch = analog.pwr_squelch_cc(-20.0, alpha=0.01, ramp=100, gate=False)
        self.oqpsk_agc = analog.agc_cc(rate=0.0, reference=1.0, gain=1.0, max_gain=4.0)

        # Quadrature (FM) demod: for a CPFSK-equivalent signal with
        # modulation index h=0.5, freq deviation = chip_rate/4. Scaling by
        # samp_rate/(2*pi*deviation) puts a full chip-rate deviation at
        # output amplitude ~=1.0, matching the decoder's threshold-at-zero
        # slicing (mirrors ZigbeeLiveDecoder's `samples > 0`).
        oqpsk_freq_deviation = OQPSK_CHIP_RATE / 4
        oqpsk_quad_gain = SAMP_RATE / (2 * 3.14159265 * oqpsk_freq_deviation)
        self.oqpsk_demod = analog.quadrature_demod_cf(oqpsk_quad_gain)

        # Chip-rate (not symbol-rate) clock recovery: gain constants are
        # standard-order values seen in typical GNU Radio GMSK receiver
        # examples, not tuned against this specific signal.
        self.oqpsk_clock = digital.clock_recovery_mm_ff(
            OQPSK_SPS, 0.25 * 0.175 * 0.175, 0.5, 0.175, 0.005)

        self.oqpsk_decoder = OqpskLiveDecoder(on_frame)

        self.connect(self.src, self.oqpsk_lpf, self.oqpsk_squelch, self.oqpsk_agc,
                     self.oqpsk_demod, self.oqpsk_clock, self.oqpsk_decoder)

        self.current_channel = initial_channel

    def retune(self, channel):
        f = freq_for_channel(channel)
        self.src.set_center_freq(f)
        self.current_channel = channel
        # set_center_freq() re-triggers the same fd 1/2 repointing seen on
        # the initial osmosdr.source() call;  reassert every time, not just
        # once at construction.
        restore_stdio_fds()
        print(f"RETUNED channel={channel} freq={f/1e6:.4f}MHz", file=sys.stderr, flush=True)


def stdin_control_loop(tb):
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if parts[0] == "CHANNEL" and len(parts) == 2:
            try:
                tb.retune(int(parts[1]))
            except ValueError as e:
                print(f"ERROR bad channel command: {e}", file=sys.stderr, flush=True)
        elif parts[0] == "QUIT":
            break
        else:
            print(f"ERROR unknown command: {line}", file=sys.stderr, flush=True)


def main():
    initial_channel = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    # optional: self-bounded test runs, e.g. `zigbee900_live_rx.py 1 15` exits
    # after 15s on its own; this avoids needing external timing coordination
    # (stdin EOF from a non-interactive launch would otherwise exit
    # immediately with no data processed at all)
    test_duration = float(sys.argv[2]) if len(sys.argv) > 2 else None

    def on_frame(psdu):
        restore_stdio_fds()
        # Kismet's phy_802154 dissector expects KDLT_IEEE802_15_4_NOFCS framing
        # (MHR+payload only, no trailing FCS); the FCS was already validated
        # against the CRC-16 in Candidate.process(), so it's safe to drop here.
        mpdu = psdu[:-2]
        msg = f"PSDU {main.tb.current_channel} {mpdu.hex()}\n".encode()
        os.write(1, msg)

    tb = Rx900Live(initial_channel, on_frame)
    main.tb = tb

    # osmosdr.source()'s device probing repoints fd 1/2 away from Kismet's
    # pipes (see module-level comment). Force them back now that
    # construction is done, before we rely on stdout/stderr for anything.
    restore_stdio_fds()

    print(f"READY channel={initial_channel}", file=sys.stderr, flush=True)
    tb.start()

    try:
        if test_duration is not None:
            # self-bounded test mode: no stdin dependency at all, so it can't
            # exit early on stdin EOF from a non-interactive launch and no
            # external timing coordination is needed to stop it
            print(f"TEST MODE: running for {test_duration}s then stopping", file=sys.stderr, flush=True)
            time.sleep(test_duration)
        else:
            stdin_control_loop(tb)
    except KeyboardInterrupt:
        pass
    finally:
        tb.stop()
        tb.wait()




if __name__ == "__main__":
    main()
