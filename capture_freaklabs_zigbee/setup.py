#!/usr/bin/env python3

from setuptools import setup

setup(name='KismetCaptureFreaklabsZigbee',
      version='2018.0.0',
      description='Kismet Freaklabs Zigbee datasource',
      author='Mike Kershaw / Dragorn',
      author_email='dragorn@kismetwireless.net',
      url='https://www.kismetwireless.net/',
      install_requires=['protobuf', 'KismetExternal', 'pyserial'],
      packages=['KismetCaptureFreaklabsZigbee'],
      scripts=['kismet_cap_freaklabs_zigbee'],
     )


