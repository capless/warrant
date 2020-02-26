import os

from setuptools import setup, find_packages

try:
    from pip._internal.req import parse_requirements
except ImportError:
    from pip.req import parse_requirements

install_reqs = parse_requirements("requirements.txt", session=False)
test_reqs = parse_requirements("requirements_test.txt", session=False)

version = "0.6.1"

README = """Python class to integrate Boto3's Cognito client so it is easy to login users. With SRP support."""

setup(
    name="pycognito",
    version=version,
    description=README,
    long_description=README,
    classifiers=[
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Environment :: Web Environment",
    ],
    download_url="https://github.com/pvizeli/pycognito/tarball/" + VERSION,
    keywords="aws,cognito,api,gateway,serverless",
    author="Pascal Vizeli",
    author_email="pvizeli@syshack.ch",
    packages=find_packages(),
    url="https://github.com/pvizeli/pycognito",
    license="Apache License 2.0",
    install_requires=[str(ir.req) for ir in install_reqs],
    extras_require={"test": [str(ir.req) for ir in test_reqs]},
    include_package_data=True,
    zip_safe=True,
)
