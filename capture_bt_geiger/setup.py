from setuptools import setup, find_packages

setup(name='KismetCaptureBtGeiger',
      version='2021.07.1',
      description='Kismet BTLE geiger datasource',
      author='Mike Kershaw / @kismetwireless',
      author_email='dragorn@kismetwireless.net',
      url='https://www.kismetwireless.net/',
      install_requires=['protobuf', 'websockets', 'bluepy'],
      python_requires='>=3.2',
      packages=find_packages(),
      entry_points={
          'console_scripts': [
              'kismet_cap_bt_geiger = KismetCaptureBtGeiger.kismet_cap_bt_geiger:main',
              ],
          },
     )


