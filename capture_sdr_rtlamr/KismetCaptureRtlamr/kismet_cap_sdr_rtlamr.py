import sys
import time
import KismetCaptureRtlamr

def main():
    # sys.tracebacklimit = 0

    rtl = KismetCaptureRtlamr.KismetRtlamr()
    rtl.run()
