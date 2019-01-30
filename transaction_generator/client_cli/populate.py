#!/usr/bin/python
#
# Copyright 2016 Intel Corporation
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

import argparse
import logging


from client_cli.exceptions import CliException
from config.config_loader import get_namespace, get_signer_key_file, get_txns, get_encoding

LOGGER = logging.getLogger(__name__)


def gen_signer_key(key_file):
    from sawtooth_signing import create_context
    from sawtooth_signing import CryptoFactory
    from sawtooth_signing.secp256k1 import Secp256k1PrivateKey
    from sawtooth_signing import ParseError

    context = create_context('secp256k1')
    crypto_factory = CryptoFactory(context=context)
    if key_file is not None:
        try:
            with open(key_file, 'r') as infile:
                signing_key = infile.read().strip()
            private_key = Secp256k1PrivateKey.from_hex(signing_key)
        except ParseError as pe:
            raise CliException(str(pe))
        except IOError as ioe:
            raise CliException(str(ioe))
    else:
        private_key = context.new_random_private_key()
    return crypto_factory.new_signer(private_key)


def do_populate(args, batches):
    from client_cli.create_batch import create_transaction
    from client_cli.create_batch import create_batch
    from client_cli.create_batch import PrivatePayload

    signer = gen_signer_key(get_signer_key_file())

    payloads = get_txns()
    encoding = get_encoding()
    total_txn_count = 0
    txns = []

    for payload in payloads:
        txn = create_transaction(
            payload=PrivatePayload(payload, encoding, signer.get_public_key().as_hex()),
            addr= get_namespace(),#TODO get input and output from json file
            signer=signer)
        total_txn_count += 1
        txns.append(txn)

    batch = create_batch(
        transactions=txns,
        signer=signer)

    batches.append(batch)
