#!/usr/bin/env python2

from setuptools import setup, find_packages

setup(name='KismetCaptureRtladsb',
      version='2018.5.1',
      description='Kismet rtladsb datasource',
      author='Russ Handorf / @dntlookbehindu',
      author_email='russell@handorf.com',
      url='https://www.handorf.com/',
      install_requires=['numpy', 'protobuf'],
      packages=find_packages(),
      scripts=['kismet_cap_sdr_rtladsb', 'kismet_cap_sdr_rtladsb_mqtt'],
      # data_files=[('share/kismet_rtladsb', ['data/aircraft_db.csv'])]
      package_data={'KismetCaptureRtladsb': ['data/aircraft_db.csv']},
     )


