from setuptools import setup, find_packages

setup(name='KismetCaptureRtladsb',
      version='2018.7.1',
      description='Kismet rtladsb datasource',
      author='Russ Handorf / @dntlookbehindu',
      author_email='russell@handorf.com',
      url='https://www.handorf.com/',
      install_requires=['numpy', 'protobuf'],
      python_requires='>=3.2',
      packages=find_packages(),
      entry_points={
          'console_scripts': [
              'kismet_cap_sdr_rtladsb = KismetCaptureRtladsb.kismet_cap_sdr_rtladsb:main',
              ],
          },
      package_data={'KismetCaptureRtladsb': ['data/aircraft_db.csv']},
     )


