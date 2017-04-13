#!/usr/bin/python

from setuptools import setup

setup(name='barbican_keymaster',
      version='0.0.1',
      author='OpenStack',
      packages=['barbican_keymaster'],
      entry_points={
          'paste.filter_factory': [
              'barbican_keymaster=barbican_keymaster:filter_factory',
          ],
      })
