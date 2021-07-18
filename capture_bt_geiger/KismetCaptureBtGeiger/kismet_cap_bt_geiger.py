import sys
import time
import KismetCaptureBtGeiger

def main():
    # sys.tracebacklimit = 0

    g = KismetCaptureBtGeiger.KismetBtGeiger()
    g.run()
