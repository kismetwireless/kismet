from setuptools import setup, find_packages

setup(name='KismetCaptureProxyAdsb',
      version='2021.02.1',
      description='Kismet ADSB proxy datasource',
      author='Mike Kershaw / @kismetwireless',
      author_email='dragorn@kismetwireless.net',
      url='https://www.kismetwireless.net/',
      install_requires=['protobuf', 'websockets'],
      python_requires='>=3.2',
      packages=find_packages(),
      entry_points={
          'console_scripts': [
              'kismet_cap_proxy_adsb = KismetCaptureProxyAdsb.kismet_cap_proxy_adsb:main',
              ],
          },
     )

