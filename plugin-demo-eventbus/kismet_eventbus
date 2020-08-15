#!/usr/bin/env python3

# A very basic example of how to create a python-native extension to Kismet
# that interfaces over the external API
#
# This uses the python_tools/KismetExternal python module to integrate with 
# the eventbus and print events to the console.

import argparse
import os
import time
import sys
import threading

# Pretty-print the failure
try:
    import kismetexternal
except ImportError:
    print("ERROR:  Kismet external Python tools require the kismetexternal python ")
    print("        library; you can find it in the kismetexternal git or via pip")
    sys.exit(1)

class KismetProxyTest(object):
    def __init__(self):
        # Try to parse the arguments to find the descriptors we need to give to 
        # the kismet external tool; Kismet calls external helpers with a pre-made
        # set of pipes on --in-fd and --out-fd
        self.parser = argparse.ArgumentParser(description='Kismet External Python Example - Eventbus')

        self.parser.add_argument('--in-fd', action="store", type=int, dest="infd")
        self.parser.add_argument('--out-fd', action="store", type=int, dest="outfd")

        self.results = self.parser.parse_args()

        if self.results.infd is None or self.results.outfd is None:
            print("ERROR:  Kismet external python tools are (typically) launched by ")
            print("        Kismet itself; running it on its own won't do what you want")
            sys.exit(1)

        print("Eventbus loaded KismetExternal {}".format(kismetexternal.__version__))

        # Initialize our external interface
        self.kei = kismetexternal.ExternalInterface(self.results.infd, self.results.outfd)

        # self.kei.debug = True

        # Start the external handler BEFORE we register our handlers, since we need to be
        # connected to send them!
        self.kei.start()

        # Register an event handler for all events
        self.kei.add_event_handler("*", self.handle_event)

        # Start the IO loops running
        self.kei.run()

    def handle_event(self, event, dictionary):
        print("Eventbus got {}".format(event))

        # This is excessively verbose
        # print("Eventbus got {}: {}".format(event, " ".join(f"({key}: {value})" for key, value in dictionary.items())))

    # Loop forever
    def loop(self):
        while self.kei.is_running():
            self.kei.send_ping()
            time.sleep(1)

        self.kei.kill()


if __name__ == "__main__":
    # Make a proxytest and loop forever
    pt = KismetProxyTest()

    # Loop in a detached process
    pt.loop()
