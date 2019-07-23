import sys
import time
import KismetCaptureRtladsb

def main():
    sys.tracebacklimit = 0

    rtl = KismetCaptureRtladsb.KismetRtladsb()

    # Go into sleep mode
    while rtl.is_running():
        time.sleep(1)

