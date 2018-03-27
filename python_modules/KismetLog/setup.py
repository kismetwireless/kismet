try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

config = {
    'description': 'Python API for the Kismet Log interface',
    'author': 'Mike Kershaw / Dragorn',
    'url': 'https://www.kismetwireless.net',
    'download_url': 'https://www.kismetwireless.net',
    'author_email': 'dragorn@kismetwireless.net',
    'version': '2018.0.0',
    'packages': ['KismetLog'],
    'scripts': [],
    'name': 'kismetlog'
}

setup(**config)
