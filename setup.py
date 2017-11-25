import os

from setuptools import setup, find_packages
from pip.req import parse_requirements

install_reqs = parse_requirements('requirements.txt', session=False)
test_reqs = parse_requirements('requirements_test.txt', session=False)

version = '0.6.0'

README="""Python class to integrate Boto3's Cognito client so it is easy to login users. With SRP support."""

setup(
    name='warrant',
    version=version,
    description=README,
    long_description=README,
    classifiers=[
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.6",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Environment :: Web Environment",
    ],
    keywords='aws,cognito,api,gateway,capless',
    author='Capless.io',
    author_email='opensource@capless.io',
    maintainer='Brian Jinwright',
    packages=find_packages(),
    url='https://github.com/capless/warrant',
    license='Apache License 2.0',
    install_requires=[str(ir.req) for ir in install_reqs],
    extras_require={
        'test': [str(ir.req) for ir in test_reqs]
    },
    include_package_data=True,
    zip_safe=True,

)
