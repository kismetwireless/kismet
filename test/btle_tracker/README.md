# BTLE location tracker tests

`decoder_test.cc` tests the tracker decoders in `bluetooth_parsers/btle_tracker.cc` with
synthetic payloads; it needs only a C++ compiler:

    g++ -std=c++17 -Wall -I. test/btle_tracker/decoder_test.cc \
        bluetooth_parsers/btle_tracker.cc -o /tmp/btle_tracker_test && /tmp/btle_tracker_test

`tracker_pcaps.py` writes a test pcap (DLT 256, BTLE_RADIO) with synthetic advertisements, all
with random addresses: Samsung SmartTags in two states, Apple Find My frames from an AirTag
(separated), AirPods (near owner) and an Apple device that is not a tracker, a Google FMDN tag
in unwanted tracking protection mode, an Eddystone frame, a tracker that only sends the DULT
advertisement, an FMDN tag that sends its FMDN and DULT advertisements in turns, an FD5A
advertisement with another frame id, and a plain advertiser.  `run.sh` replays it through a
Kismet build, once with the default settings and once with `btle_ignore_random=true`, and checks
the `btle.device.tracker` fields of each device:

    ./configure && make
    test/btle_tracker/run.sh

It uses port 2598 on 127.0.0.1, or `BTLE_TRACKER_TEST_PORT`, with remote capture and plugins
off, so it can run next to a Kismet server.
