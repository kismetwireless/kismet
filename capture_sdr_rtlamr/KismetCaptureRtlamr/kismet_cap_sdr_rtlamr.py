import sys
import time
import KismetCaptureRtlamr

def main():
    sys.tracebacklimit = 0

    rtl = KismetCaptureRtlamr.KismetRtlamr()

    # Go into sleep mode
    while rtl.is_running():
        time.sleep(1)

