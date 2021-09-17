"""
BTLE geiger counter Kismet data source

Accepts standard options:
    device=BTLE device MAC

"""

from __future__ import print_function

import asyncio
import argparse
from datetime import datetime
import json

import os
import pkgutil
import subprocess
import sys
import threading
import time
import uuid

have_blepy = False

try:
    from bluepy.btle import UUID, Peripheral, DefaultDelegate, BTLEDisconnectError
    have_blepy = True
except:
    pass

from . import kismetexternal

class Geiger(Peripheral):
    def __init__(self, addr):
        self.svcUUID = UUID('db058fb8-776a-45a9-a5b4-cdefbbdfacc3')
        self.cpsUUID = UUID('413fad46-e55e-495c-bb97-4bf18efe911d')
        self.cpmUUID = UUID('6861f015-66e0-4a83-a31f-527a34829341')
        self.usvhUUID = UUID('99f35c9e-b165-432c-942e-d5155a19a2f1')

        connected = False
        for x in range(0, 5):
            try:
                Peripheral.__init__(self, addr)
                connected = True
                break
            except Exception as e:
                continue

        if not connected:
            raise RuntimeError('could not connect to btgeiger device in 5 tries')

        self.service = self.getServiceByUUID(self.svcUUID)
        self.cps = self.service.getCharacteristics(self.cpsUUID)[0]
        self.cpm = self.service.getCharacteristics(self.cpmUUID)[0]
        self.usvh = self.service.getCharacteristics(self.usvhUUID)[0]

    def read(self):
        cps = int.from_bytes(self.cps.read(), "little")
        cpm = int.from_bytes(self.cpm.read(), "little")
        usvh = int.from_bytes(self.usvh.read(), "little")
        usvh = float(usvh) / 1000.0

        return (cps, cpm, usvh)

class KismetBtGeiger(object):
    def __init__(self):
        self.opts = {}

        self.opts['device'] = None
        self.opts['debug'] = None

        self.kismet = None
        self.geiger = None

        # We're usually not remote
        self.proberet = None

        self.message_queue = asyncio.Queue()

        self.driverid = "btgeiger"

        parser = argparse.ArgumentParser(description='BTLE Geiger counter Kismet datasource')
        
        # Append the default args
        parser = kismetexternal.ExternalInterface.common_getopt(parser)
        
        self.config = parser.parse_args()

        if (self.config.infd == None or self.config.outfd == None) and self.config.connect == None:
            print("This tool is launched via Kismet IPC for local capture; see --help and the Kismet documentation to configure it for remote capture.")
            sys.exit(0)

        if not self.config.connect == None and self.config.source == None:
            print("You must specify a source with --source when connecting to a remote Kismet server")
            sys.exit(0)

        if not self.config.source == None:
            (source, options) = kismetexternal.Datasource.parse_definition(self.config.source)

            if source == None:
                print("Could not parse the --source option; this should be a standard Kismet source definition.")
                sys.exit(0)

            self.proberet = self.datasource_probesource(source, options)

            if self.proberet == None:
                print(f"Could not configure local source {config.source}, check your source options and config.")
                sys.exit(0)

            if not "success" in self.proberet:
                print("Could not configure local source {}, check your source options and config.")
                if "message" in self.proberet:
                    print(self.proberet["message"])
                sys.exit(0)

            if not self.proberet["success"]:
                print("Could not configure local source {}, check your source options and config.")
                if "message" in self.proberet:
                    print(self.proberet["message"])
                sys.exit(0)

            print("Connecting to remote server {}".format(self.config.connect))

    def run(self):
        self.kismet = kismetexternal.Datasource(self.config)

        self.kismet.set_configsource_cb(self.datasource_configure)
        self.kismet.set_listinterfaces_cb(self.datasource_listinterfaces)
        self.kismet.set_opensource_cb(self.datasource_opensource)
        self.kismet.set_probesource_cb(self.datasource_probesource)

        t = self.kismet.start()

        # If we're connecting remote, kick a newsource
        if self.proberet:
            print("Registering remote source {} {}".format(self.driverid, self.config.source))
            self.kismet.send_datasource_newsource(self.config.source, self.driverid, self.proberet['uuid'])

        self.kismet.run()

    def is_running(self):
        return self.kismet.is_running()

    def __get_btgeiger_uuid(self, device):
        return kismetexternal.Datasource.make_uuid("kismet_cap_bt_geiger", device)

    def run_btgeiger(self):
        self.kismet.add_task(self.__btgeiger_task)

    def datasource_listinterfaces(self, seqno):
        # No autoprobing of interfaces
        interfaces = []
        self.kismet.send_datasource_interfaces_report(seqno, interfaces)

    def datasource_probesource(self, source, options):
        ret = {}

        if not have_blepy:
            return None

        if not source[:8] == "btgeiger":
            return None

        if not 'device' in options:
            return None

        ret['hardware'] = options['device']
        if ('uuid' in options):
            ret['uuid'] = options['uuid']
        else:
            ret['uuid'] = self.__get_btgeiger_uuid(options['device'])

        ret['channel'] = "0"
        ret['channels'] = ["0"]
        ret['success'] = True

        return ret

    def datasource_opensource(self, source, options):
        ret = {}

        if not have_blepy:
            return ret

        if not source[:8] == "btgeiger":
            ret["success"] = False
            ret["message"] = "Could not parse btgeiger device"
            return ret

        if not 'device' in options:
            ret["success"] = False
            ret["message"] = "no 'device' provided in options; the MAC of the btgeiger device must be provided."
            return ret

        if 'debug' in options:
            if options['debug'] == 'True' or options['debug'] == 'true':
                self.opts['debug'] = True

        ret['hardware'] = options['device']
        if ('uuid' in options):
            ret['uuid'] = options['uuid']
        else:
            ret['uuid'] = self.__get_btgeiger_uuid(options['device'])

        ret['capture_interface'] = f"btgeiger-{options['device']}"

        self.opts['device'] = options['device']

        (ret['success'], ret['message']) = self.open_radio(self.opts['device'])

        if not ret['success']:
            return ret

        self.run_btgeiger()

        return ret

    def datasource_configure(self, seqno, config):
        return {"success": True}

    def handle_json(self, inrec):
        try:
            r = json.dumps(inrec)

            report = kismetexternal.datasource_pb2.SubJson()

            dt = datetime.now()
            report.time_sec = int(time.mktime(dt.timetuple()))
            report.time_usec = int(dt.microsecond)

            report.type = "radiation"
            report.json = r

            self.kismet.send_datasource_data_report(full_json=report)
        except ValueError as e:
            self.kismet.send_datasource_error_report(message = "Could handle JSON output")
            return False
        except Exception as e:
            self.kismet.send_datasource_error_report(message = "Could not handle output")
            return False

        return True

    def __async_radio_thread(self):
        # This function blocks forever until cancelled
        try:
            while True:
                (cps, cpm, usvh) = self.geiger.read()
                self.kismet.add_task(self.message_queue.put, [{"cps": cps, "cpm": cpm, "usvh": usvh}])
                time.sleep(0.5)
        except Exception as e:
            self.kismet.send_datasource_error_report(message = f"Error reading from BT geiger: {e}")

        # Always make sure we die
        self.kismet.spindown()

    def open_radio(self, device):
        try:
            self.geiger = Geiger(device)
        except Exception as e:
            return [False, f"Error opening BT Geiger device: {e.args[0]}"]

        self.geiger_thread = threading.Thread(target=self.__async_radio_thread)
        self.geiger_thread.daemon = True
        self.geiger_thread.start()

        return [True, ""]

    async def __btgeiger_task(self):
        print_stderr = False

        if self.opts['debug'] is not None and self.opts['debug']:
            print_stderr = True

        try:
            while not self.kismet.kill_ioloop:
                msg = await self.message_queue.get()

                if not msg:
                    break

                if print_stderr:
                    print(msg, file=sys.stderr)

                if not self.handle_json(msg):
                    raise RuntimeError('could not send btgeiger data')

        except Exception as e:
            traceback.print_exc(file=sys.stderr)
            print("An error occurred reading from the geiger bt device", file=sys.stderr);

            self.kismet.send_datasource_error_report(message = "Error handling btgeiger: {}".format(e))

        finally:
            self.kismet.spindown()
            return


