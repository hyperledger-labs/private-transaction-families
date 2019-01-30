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
import hashlib
import json
import cbor
import logging
import time
import ctypes
import base64

import sawtooth_sdk.protobuf.batch_pb2 as batch_pb2
import sawtooth_sdk.protobuf.transaction_pb2 as transaction_pb2

from config.config_loader import read_config_file, get_family_name, get_family_version
from client_cli.populate import do_populate
from ctypes import cdll

openssl_lib = cdll.LoadLibrary('../src/CryptoLib/openssl/lib/libcrypto_so.so')
crypto_lib = ctypes.cdll.LoadLibrary('../src/lib/debug/libstl_crypto_so_u.so')

LOGGER = logging.getLogger(__name__)


class PrivatePayload(object):
    def __init__(self, json_obj, encoding, signer_pub_key):
        self._json_obj = json_obj
        self._encoding = encoding
        self._signer_pub_key = signer_pub_key
        self._encoded = None
        self._sha512 = None
        self._encrypted = None

    def to_hash(self):
        return self._json_obj

    def get_encoded(self):
        if self._encoded is None:
            if  self._encoding == 'cbor':
                self._encoded = cbor.dumps(self.to_hash(), sort_keys=True)
            elif self._encoding == 'json':
                self._encoded = json.dumps(self.to_hash(), sort_keys=True)
        return self._encoded

    def sha512(self):
        if self._sha512 is None:
            self._sha512 = hashlib.sha512(self.get_encrypted()).hexdigest()
        return self._sha512

    def get_encrypted(self):
        if self._encrypted is None:
            self._encrypted = encrypt_payload(self.get_encoded().encode('utf-8'), self._signer_pub_key)
        return self._encrypted


def create_transaction(payload, addr, signer):
    header = transaction_pb2.TransactionHeader(
        signer_public_key=signer.get_public_key().as_hex(),
        family_name=get_family_name(),
        family_version=get_family_version(),
        inputs=[addr],
        outputs=[addr],
        dependencies=[],
        payload_sha512= payload.sha512(),
        batcher_public_key=signer.get_public_key().as_hex(),
        nonce=time.time().hex().encode())

    header_bytes = header.SerializeToString()

    signature = signer.sign(header_bytes)

    transaction = transaction_pb2.Transaction(
        header=header_bytes,
        payload=payload.get_encrypted(),
        header_signature=signature)

    return transaction


def read_buffer(res_buf):
  
    size_to_read = 0
    while res_buf[size_to_read] != 0:
        size_to_read = size_to_read + 1
           
    size_to_read = size_to_read + 1

    byteArr = bytearray(size_to_read)
    for i in range(0, size_to_read):
       byteArr[i] = res_buf[i]
        
   
    return byteArr




def encrypt_payload(payload, pub_key, keys_path = None):
    encrypt_transaction = crypto_lib.encrypt_data
    encrypt_transaction.argtypes = [ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_short, ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
    encrypt_transaction.restype = ctypes.c_bool
    
    transaction_payload = ctypes.create_string_buffer(bytes(payload), len(payload))   
    size = ctypes.c_ulonglong(len(transaction_payload))  
    res_buf = ctypes.POINTER(ctypes.c_ubyte) () 
    
    path_to_keys = ctypes.c_char_p(keys_path)
    client_pub_key = ctypes.c_char_p(pub_key.encode('utf-8'))
    svn = ctypes.c_short(0)
    res = encrypt_transaction(transaction_payload, size, svn, ctypes.byref(res_buf), client_pub_key, path_to_keys)
    if(res):
        # copy to local array before freeing memeory allocated by C library
        size_to_read = 0
        while res_buf[size_to_read] != 0:
           size_to_read = size_to_read + 1
           
        size_to_read = size_to_read + 1

        byteArr = bytearray(size_to_read)
        for i in range(0, size_to_read):
           byteArr[i] = res_buf[i]
        
        # free memory allocated by C lib
        free_mem = crypto_lib.free_mem_request
        free_mem.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))] 
        free_mem.restype = ctypes.c_bool

        res = free_mem(ctypes.byref(res_buf))
    
    else:
        LOGGER.error("Error: Encrypt data failed")
        return

    return bytes(byteArr)




def create_batch(transactions, signer):
    transaction_signatures = [t.header_signature for t in transactions]

    header = batch_pb2.BatchHeader(
        signer_public_key=signer.get_public_key().as_hex(),
        transaction_ids=transaction_signatures)

    header_bytes = header.SerializeToString()

    signature = signer.sign(header_bytes)

    batch = batch_pb2.Batch(
        header=header_bytes,
        transactions=transactions,
        header_signature=signature)

    return batch


def write_batch_file(args, batches):
    batch_list = batch_pb2.BatchList(batches=batches)
    print("Writing to {}...".format(args.output))
    with open(args.output, "wb") as fd:
        fd.write(batch_list.SerializeToString())


def do_create_batch(args):
    batches = []
    # validate json file
    read_config_file(args.config)
    do_populate(args, batches)
    write_batch_file(args, batches)


def add_create_batch_parser(subparsers, parent_parser):
    parser = subparsers.add_parser(
        'create_batch',
        parents=[parent_parser],
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument(
        '-o', '--output',
        type=str,
        help='name of output file, default is batches.generator',
        default='batches.generator')

    parser.add_argument(
        '-B', '--max-batch-size',
        type=int,
        help='max transactions per batch, default is 10',
        default=10)

    parser.add_argument(
        '-f', '--config',
        type=str,
        required=True,
        help='full path to file containing transactions configuration, must match config_schema.json')
