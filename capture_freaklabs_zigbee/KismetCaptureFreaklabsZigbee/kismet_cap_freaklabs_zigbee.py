import sys
import time
import KismetCaptureFreaklabsZigbee

def main():
    sys.tracebacklimit = 0

    zig = KismetCaptureFreaklabsZigbee.KismetFreaklabsZigbee()

    # Go into sleep mode
    while zig.is_running():
        time.sleep(1)

