from setuptools import setup, find_packages

setup(name='KismetCaptureRtlamr',
      version='2020.10.1',
      description='Kismet rtlamr datasource',
      author='Russ Handorf / @dntlookbehindu, Mike Kershaw / @kismetwireless',
      author_email='russell@handorf.com, dragorn@kismetwireless.net',
      url='https://www.handorf.com/',
      install_requires=['protobuf', 'numpy', 'websockets'],
      python_requires='>=3.2',
      packages=find_packages(),
      entry_points={
          'console_scripts': [
              'kismet_cap_sdr_rtlamr = KismetCaptureRtlamr.kismet_cap_sdr_rtlamr:main',
              ],
          },
     )


