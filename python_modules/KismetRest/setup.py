try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

config = {
    'description': 'Simplified Python API for the Kismet REST interface',
    'author': 'Mike Kershaw / Dragorn',
    'url': 'https://www.kismetwireless.net',
    'download_url': 'https://www.kismetwireless.net',
    'author_email': 'dragorn@kismetwireless.net',
    'version': '1.0',
    'install_requires': [ 'requests' ],
    'packages': ['KismetRest'],
    'scripts': [],
    'name': 'kismetrest'
}

setup(**config)
