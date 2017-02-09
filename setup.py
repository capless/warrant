import os

from setuptools import find_packages, setup

README = open(os.path.join(os.path.dirname(__file__), 'README.md')).read()

packages = find_packages(exclude=['tests*'])

setup(
    name='cognito',
    version='0.1',
    packages=packages,
    include_package_data=True,
    description='Cognito integration using boto3.',
    long_description=README,
    author='MetaMetrics, Inc.',
    author_email='engineering@lexile.com',
    url='http://www.metametricsinc.com/',
    license='GPLv3',
    install_requires=[
        'boto3>=1.4,<1.5',
    ],
    extras_require={
        'django': [
            'Django>=1.8,<1.11',
            'mock==2.0.0'
        ],
    }
)
