import sys
import time
import KismetCaptureFreaklabsZigbee

def main():
    sys.tracebacklimit = 0

    zig = KismetCaptureFreaklabsZigbee.KismetFreaklabsZigbee()

    zig.run()
