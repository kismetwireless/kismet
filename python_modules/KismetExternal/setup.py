#!/usr/bin/env python2

from setuptools import setup

setup(name='KismetExternal',
      version='2018.0.0',
      description='Kismet External Helper Library',
      author='Mike Kershaw / Dragorn',
      author_email='dragorn@kismetwireless.net',
      url='https://www.kismetwireless.net/',
      install_requires=['protobuf'],
      packages=['KismetExternal'],
     )


