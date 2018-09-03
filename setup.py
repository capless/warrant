from setuptools import setup, find_packages

install_reqs = [
    "boto3>=1.4.3",
    "envs>=0.3.0",
    "python-jose>=3.0.0",
    "requests>=2.13.0"
]

test_reqs = [
    "mock>=2.0.0",
    "nose",
    "coverage"
]

version = '0.6.2'

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
    install_requires=install_reqs,
    extras_require={
        'test': test_reqs
    },
    include_package_data=True,
    zip_safe=True,

)
