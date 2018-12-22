#!/usr/bin/env python2

from setuptools import setup

setup(name='KismetCaptureRtladsb',
      version='2018.0.0',
      description='Kismet rtladsb datasource',
      author='Russ Handorf / @dntlookbehindu',
      author_email='russell@handorf.com',
      url='https://www.handorf.com/',
      install_requires=['protobuf', 'KismetExternal'],
      packages=['KismetCaptureRtladsb'],
      scripts=['kismet_cap_sdr_rtladsb', 'kismet_cap_sdr_rtladsb_mqtt'],
     )


