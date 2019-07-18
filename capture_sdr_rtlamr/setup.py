from setuptools import setup, find_packages

setup(name='KismetCaptureRtlamr',
      version='2018.07.0',
      description='Kismet rtlamr datasource',
      author='Russ Handorf / @dntlookbehindu',
      author_email='russell@handorf.com',
      url='https://www.handorf.com/',
      install_requires=['protobuf'],
      packages=find_packages(),
      entry_points={
          'console_scripts': [
              'kismet_cap_sdr_rtlamr = KismetCaptureRtlamr.kismet_cap_sdr_rtlamr:main',
              'kismet_cap_sdr_rtlamr_mqtt = KismetCaptureRtlamr.kismet_cap_sdr_rtlamr_mqtt:main',
              ],
          },
     )


