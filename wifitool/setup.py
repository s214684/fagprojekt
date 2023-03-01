#!/usr/bin/env python

from setuptools import find_packages, setup



setup(
    name='wifitool',
    version='1.0',
    packages=find_packages('.'),
    entry_points={
                'console_scripts': [
            'my_start=my_package.start:main',
        ]
    }
)
