from distutils.core import setup, Extension

cModule = Extension('cinepy',
    sources = ['cinepy.c'],
    libraries = ['crypto'])

setup(name = 'cinepy',
    version = '0.1',
    description = 'Functions for digital cinema',
    author = 'Arts Alliance Media',
    author_email = 'dev@artsalliancemedia.com',
    url = 'http://github.com/mjohnsullivan/cinepy',
    packages = ['cinepy'],
    ext_modules = [cModule])
