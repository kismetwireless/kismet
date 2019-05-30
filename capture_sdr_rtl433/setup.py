#!/usr/bin/env python2

from setuptools import setup, find_packages

setup(name='KismetCaptureRtl433',
      version='2018.0.0',
      description='Kismet rtl_433 datasource',
      author='Mike Kershaw / Dragorn',
      author_email='dragorn@kismetwireless.net',
      url='https://www.kismetwireless.net/',
      install_requires=['protobuf'],
      packages=find_packages(),
      scripts=['kismet_cap_sdr_rtl433', 'kismet_cap_sdr_rtl433_mqtt'],
     )


