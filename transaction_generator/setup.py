# Copyright 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

from __future__ import print_function

import os
from setuptools import setup, find_packages

data_files = [('config',['config/config_schema.json'])]


setup(name='private-txn-generator',
      version=1.0,
      description='Sawtooth Transaction Generator',
      author='Intel Corporation',
      packages=find_packages(),
      install_requires=[
          "cbor",
          "colorlog",
          "sawtooth-sdk",
          "sawtooth-signing"
      ],
      data_files=data_files,
      entry_points={
          'console_scripts': [
             'private-txn-generator = client_cli.cli:main_wrapper'
          ]
      })
