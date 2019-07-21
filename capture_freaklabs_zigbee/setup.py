from setuptools import setup, find_packages

setup(name='KismetCaptureFreaklabsZigbee',
      version='2018.7.0',
      description='Kismet Freaklabs Zigbee datasource',
      author='Mike Kershaw / Dragorn',
      author_email='dragorn@kismetwireless.net',
      url='https://www.kismetwireless.net/',
      install_requires=['protobuf', 'pyserial'],
      packages=find_packages(),
      entry_points={
          'console_scripts': [
              'kismet_cap_freaklabs_zigbee = KismetCaptureFreaklabsZigbee.kismet_cap_freaklabs_zigbee:main',
              ],
          },
     )


