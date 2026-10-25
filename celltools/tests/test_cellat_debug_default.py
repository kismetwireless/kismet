# SPDX-License-Identifier: Apache-2.0
"""cellat's debug mode is opt-in, and its transcripts are private.

Debug mode reads the IMSI (``AT+CIMI``) and ICCID (``AT+ICCID`` / ``AT+QCCID``)
and, when no ``transcript=`` path is given, writes an AT transcript to
``/tmp/kismet_cellat_<IMEI>.log``. Neither belongs on the default path of a
published tool: subscriber identifiers would be read on every open, and the
transcript would sit in a shared directory.

So:

* with no ``debug=`` and no ``KISMET_CELLAT_DEBUG``, no identifier read is
  sent and no auto transcript is written;
* ``debug=true`` or ``KISMET_CELLAT_DEBUG=1`` turns it on, and ``debug=false``
  in the definition overrides the environment;
* every transcript file is created with no group or other permission bits.

The opt-in runs double as the premise check for the default run: if the
identifier read were never reachable on this fake modem, its absence on the
default path would prove nothing.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

import cell_binaries
from fake_at_modem import QENG_SERVING, FakeAtModem
from kismet_capture_ipc import CaptureRun

#: A synthetic 15-digit IMEI that this module alone uses, so the fixed
#: auto-transcript path below cannot collide with a sibling module's run.
IMEI = "351234567890125"

AUTO_TRANSCRIPT = Path(f"/tmp/kismet_cellat_{IMEI}.log")
AUTO_LINE = "AT transcript (auto) to"

#: The commands debug mode sends to read subscriber identifiers.
IDENTIFIER_READS = ("AT+CIMI", "AT+ICCID", "AT+QCCID")


class _Run(CaptureRun):
    """One offline cellat run. Empty for the same reason ``_Run`` is elsewhere."""


def _binary_or_skip() -> str:
    found = cell_binaries.discover("cellat")
    if not found.ok:
        pytest.skip(found.skip_reason())
    return str(found.path)


def _env(debug_env: "str | None") -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != "KISMET_CELLAT_DEBUG"}
    if debug_env is not None:
        env["KISMET_CELLAT_DEBUG"] = debug_env
    return env


def _open(options: str = "", debug_env: "str | None" = None):
    """Run cellat until open is over, i.e. until the first serving poll.

    The identifier reads and the transcript open both happen inside
    ``open_callback``, so by the time the first ``AT+QENG`` arrives the modem
    has seen every command the open will send.
    """
    binary = _binary_or_skip()
    try:
        AUTO_TRANSCRIPT.unlink()
    except FileNotFoundError:
        pass
    with FakeAtModem(imei=IMEI, firmware="RM520NGLAAR03A03M4G",
                     manufacturer="Quectel", extra=QENG_SERVING) as modem:

        def opened(_run: CaptureRun) -> bool:
            return any(c.startswith("AT+QENG") for c in modem.commands)

        definition = f"cellat-{IMEI}:atport={modem.port}{options}"
        run = _Run(binary, definition, timeout=25.0, stop_when=opened,
                   env=_env(debug_env)).run()
        commands = list(modem.commands)
    auto_mode = None
    if AUTO_TRANSCRIPT.exists():
        auto_mode = stat.S_IMODE(AUTO_TRANSCRIPT.stat().st_mode)
        AUTO_TRANSCRIPT.unlink()
    return run, commands, auto_mode


def _sent_identifier_read(commands: list[str]) -> bool:
    return any(c in IDENTIFIER_READS for c in commands)


def _reached_poll(commands: list[str]) -> bool:
    return any(c.startswith("AT+QENG") for c in commands)


@pytest.fixture(scope="module")
def default_open():
    return _open()


@pytest.fixture(scope="module")
def debug_open():
    return _open(",debug=true")


def test_the_default_open_reaches_the_first_poll(default_open):
    """Premise guard: the default run must get past open, or nothing below is
    a measurement."""
    _run, commands, _mode = default_open
    assert _reached_poll(commands), f"open never finished; commands={commands!r}"


def test_the_default_open_reads_no_subscriber_identifier(default_open):
    _run, commands, _mode = default_open
    sent = [c for c in commands if c in IDENTIFIER_READS]
    assert not sent, f"the default open read subscriber identifiers: {sent!r}"


def test_the_default_open_writes_no_auto_transcript(default_open):
    run, _commands, mode = default_open
    assert mode is None, f"{AUTO_TRANSCRIPT} was created on the default path"
    assert not any(AUTO_LINE in m for m in run.messages)


def test_debug_true_reads_the_identifiers(debug_open):
    """The positive control: the fake modem does reach the identifier read."""
    _run, commands, _mode = debug_open
    assert _reached_poll(commands)
    assert "AT+CIMI" in commands, f"commands={commands!r}"


def test_the_debug_auto_transcript_is_private(debug_open):
    run, _commands, mode = debug_open
    assert any(AUTO_LINE in m for m in run.messages), run.messages
    assert mode is not None, f"{AUTO_TRANSCRIPT} was not created"
    assert mode & 0o077 == 0, f"auto transcript mode is {oct(mode)}"


def test_the_environment_turns_debug_on():
    _run, commands, _mode = _open(debug_env="1")
    assert _reached_poll(commands)
    assert _sent_identifier_read(commands), f"commands={commands!r}"


def test_the_definition_overrides_the_environment():
    _run, commands, mode = _open(",debug=false", debug_env="1")
    assert _reached_poll(commands)
    assert not _sent_identifier_read(commands), f"commands={commands!r}"
    assert mode is None


def test_an_explicit_transcript_is_private(tmp_path):
    path = tmp_path / "cellat.transcript"
    _run, commands, _mode = _open(f",transcript={path}")
    assert _reached_poll(commands)
    assert path.exists(), "transcript= did not create its file"
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode & 0o077 == 0, f"transcript mode is {oct(mode)}"
