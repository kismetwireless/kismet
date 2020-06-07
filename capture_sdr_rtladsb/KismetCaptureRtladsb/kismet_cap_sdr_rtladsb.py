import asyncio
import sys
import time
import KismetCaptureRtladsb

def main():
    # sys.tracebacklimit = 0

    rtl = KismetCaptureRtladsb.KismetRtladsb()

    rtl.run()

