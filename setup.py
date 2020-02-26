from pathlib import Path

from setuptools import setup, find_packages

VERSION = "0.1.0"

setup(
    name="pycognito",
    version=VERSION,
    description="Python class to integrate Boto3's Cognito client so it is easy to login users. With SRP support.",
    long_description=Path("README.md").read_text(),
    long_description_content_type="text/markdown",
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
    install_requires=[
        "boto3>=1.10.49",
        "envs>=1.3",
        "python-jose[cryptography]>=3.1.0",
        "requests>=2.22.0",
    ],
    include_package_data=True,
    zip_safe=True,
)
