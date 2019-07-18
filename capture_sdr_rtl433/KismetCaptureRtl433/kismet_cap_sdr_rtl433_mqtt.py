import sys
import time
import KismetCaptureRtl433

def main():
    sys.tracebacklimit = 0

    rtl = KismetCaptureRtl433.KismetRtl433(mqtt=True)

    # Go into sleep mode
    while rtl.is_running():
        time.sleep(1)

