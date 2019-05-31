#!/usr/bin/env python2

from setuptools import setup, find_packages

setup(name='KismetCaptureFreaklabsZigbee',
      version='2018.0.0',
      description='Kismet Freaklabs Zigbee datasource',
      author='Mike Kershaw / Dragorn',
      author_email='dragorn@kismetwireless.net',
      url='https://www.kismetwireless.net/',
      install_requires=['protobuf', 'pyserial'],
      packages=find_packages(),
      scripts=['kismet_cap_freaklabs_zigbee'],
     )


