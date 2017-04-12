import os

from setuptools import setup, find_packages
from pip.req import parse_requirements

install_reqs = parse_requirements('requirements.txt', session=False)
django_install_reqs = parse_requirements('django-requirements.txt', session=False)

version = '0.1.0'

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    README = readme.read()

setup(
    name='warrant',
    version=version,
    description="""Python class to integrate Boto3's Cognito client so it is easy to login users. With SRP support.""",
    long_description=README,
    classifiers=[
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Environment :: Web Environment",
    ],
    keywords='aws,cognito,api,gateway,django,capless',
    author='MetaMetrics Inc and Capless.io',
    author_email='opensource@capless.io',
    maintainer='Brian Jinwright',
    packages=find_packages(),
    url='https://github.com/capless/warrant',
    license='GNU GPL V3',
    install_requires=[str(ir.req) for ir in install_reqs],
    include_package_data=True,
    zip_safe=False,
    extras_require={
        'django':[str(ir.req) for ir in django_install_reqs] ,
    }
)
