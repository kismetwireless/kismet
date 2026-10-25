# BTLE location tracker tests

`decoder_test.cc` tests the tracker decoders in `bluetooth_parsers/btle_tracker.cc` with
synthetic payloads; it needs only a C++ compiler:

    g++ -std=c++17 -Wall -I. test/btle_tracker/decoder_test.cc \
        bluetooth_parsers/btle_tracker.cc -o /tmp/btle_tracker_test && /tmp/btle_tracker_test

`tracker_pcaps.py` writes a test pcap (DLT 256, BTLE_RADIO) with synthetic Samsung SmartTag
advertisements in two states, an FD5A advertisement with another frame id, and a plain
advertiser, all with random addresses.  `run.sh` replays it through a Kismet build, once with
the default settings and once with `btle_ignore_random=true`, and checks the `btle.device.tracker`
fields of each device:

    ./configure && make
    test/btle_tracker/run.sh

It uses port 2598 on 127.0.0.1, or `BTLE_TRACKER_TEST_PORT`, with remote capture and plugins
off, so it can run next to a Kismet server.
