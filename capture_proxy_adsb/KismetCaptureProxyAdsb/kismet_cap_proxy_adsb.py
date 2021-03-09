import asyncio
import sys
import time
import KismetCaptureProxyadsb

def main():
    rtl = KismetCaptureProxyadsb.KismetProxyadsb()
    rtl.run()
