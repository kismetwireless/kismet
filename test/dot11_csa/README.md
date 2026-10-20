# Channel switch alert tests

`csa_pcaps.py` writes test pcaps (DLT 105, no radiotap) for `DOT11CSACH14`, `DOT11CSAFLOOD`
and `DOT11CSASPOOF`: real AP switches, lossy and multi-source captures, cancelled announcements,
an AP restart, an AP with a frozen TSF, and spoofed announcements, including a replica of
`aireplay-ng --csa`.

`run.sh` replays each scenario through a Kismet build, one instance per scenario, and compares
the alerts with the expected ones:

    ./configure && make
    test/dot11_csa/run.sh            # all scenarios, from the build in the source tree
    test/dot11_csa/run.sh . hold     # one scenario

It uses port 2599 on 127.0.0.1, or `CSA_TEST_PORT`, with remote capture off, so it can run
next to a Kismet server.
