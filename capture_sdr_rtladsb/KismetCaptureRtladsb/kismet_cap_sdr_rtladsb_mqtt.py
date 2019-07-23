import sys
import time
import KismetCaptureRtladsb

def main():
    sys.tracebacklimit = 0

    rtl = KismetCaptureRtladsb.KismetRtladsb(mqtt=True)

    # Go into sleep mode
    while rtl.is_running():
        time.sleep(1)

