# SPDX-License-Identifier: Apache-2.0
"""A multi-band lock is ONE channel: ``LTE-B2+66``, ``NR-n41+77``.

A band set (what other tools spell ``bands=2,4,12,71``) sits between the
all-bands and single-band presets. It is spelled as a channel so it is a Lock
target and a Hop
element like any preset, and it reaches the modem through the same guarded
path: settings as found saved first, list then RAT, restored on close.

Driven through the compiled binary against the stateful fake from
``test_cellat_lock`` (its AT+QNWPREFCFG levers are state), so what is
asserted is what a real RM500Q / RM520N-GL would be sent.
"""
from __future__ import annotations

from test_cellat_lock import ORIG, LockableFakeModem, _first_stats, _lock_is, _run


def test_a_band_set_locks_exactly_those_bands_and_the_close_restores(tmp_path):
    state = tmp_path / "s"
    with LockableFakeModem() as modem:
        run = _run(modem, state, configure=[(_first_stats, "LTE-B2+66+71")],
                   close_when=_lock_is("LTE-B2+66+71"), timeout=30)
        assert modem.writes[:2] == [("lte_band", "2:66:71"), ("mode_pref", "LTE")], \
            modem.writes
        # the whole set is the source's channel, not a truncation of it
        assert "LTE-B2+66+71" in run.config_channels, run.config_channels
        assert modem.writes[2:] == [("lte_band", ORIG["lte_band"]),
                                    ("mode_pref", ORIG["mode_pref"])], modem.writes
        assert modem.levers == ORIG, modem.levers
    assert not state.exists()


def test_a_set_with_one_band_the_modem_lacks_writes_nothing(tmp_path):
    with LockableFakeModem() as modem:
        run = _run(modem, tmp_path / "s", stop_when=lambda r: len(r.config_results) >= 1,
                   configure=[(_first_stats, "LTE-B2+13")])
        assert modem.writes == [], modem.writes
    assert any("LTE band 13 is not among" in m for _, m in run.config_results), \
        run.config_results


def test_a_set_too_long_for_one_channel_is_refused_whole(tmp_path):
    """Never truncated: a VALID set cut to fit the in-force buffer would lock
    the modem to the WRONG bands. Every band here is one the modem has, so
    only the length guard stands between this request and a partial lock."""
    bands = ["1", "2", "3", "4", "5", "7", "8", "12", "13", "14", "17", "18",
             "19", "20", "25", "26", "28", "29", "30", "32", "34", "38", "66", "71"]
    too_long = "LTE-B" + "+".join(bands)
    assert len(too_long) >= 64, len(too_long)
    levers = {**ORIG, "lte_band": ":".join(bands)}
    with LockableFakeModem(levers=levers) as modem:
        run = _run(modem, tmp_path / "s", stop_when=lambda r: len(r.config_results) >= 1,
                   configure=[(_first_stats, too_long)], timeout=15)
        assert modem.writes == [], modem.writes
    assert any("too long for one lock channel" in m for _, m in run.config_results), \
        run.config_results


def test_a_set_longer_than_any_preset_name_is_locked_whole(tmp_path):
    """The presets fit 16 bytes; a set need not. 19 characters here: a 16-byte
    in-force buffer would cut it to 'LTE-B12+13+14+6' -- a different, refused
    channel -- so this pins the buffers that carry a requested lock."""
    ch = "LTE-B12+13+14+66+71"
    assert len(ch) > 16
    levers = {**ORIG, "lte_band": "2:4:12:13:14:66:71"}
    with LockableFakeModem(levers=levers) as modem:
        run = _run(modem, tmp_path / "s", configure=[(_first_stats, ch)],
                   close_when=_lock_is(ch), timeout=30)
        assert modem.writes[:2] == [("lte_band", "12:13:14:66:71"), ("mode_pref", "LTE")], \
            modem.writes
        assert ch in run.config_channels, run.config_channels
        assert modem.levers == levers, modem.levers
