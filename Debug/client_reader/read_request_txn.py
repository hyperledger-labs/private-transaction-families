#!/usr/bin/env python3

import requests
import base64
import argparse
import ctypes
import struct

openssl_lib = ctypes.cdll.LoadLibrary('../../src/CryptoLib/openssl/lib/libcrypto_so.so')
crypto_lib = ctypes.cdll.LoadLibrary('../../src/lib/debug/libstl_crypto_so_u.so')


def get_arg():
    parser = argparse.ArgumentParser("read_request_txn.py")
    parser.add_argument('-T' , '--txn', required=True, help="<Required> valid transaction id", type=str)
    parser.add_argument('-U', '--url', type=str, help='url for the REST API, default is http://localhost:8008', default='http://localhost:8008')
    parser.add_argument('-K', '--client_keys_path', type=str, help='path to folder containing client_public_key.hexstr and client_private_key.hexstr', default='~/.stl_keys')
    args = parser.parse_args()

    url = args.url
    txn = args.txn
    client_keys_folder = args.client_keys_path
    return txn , url, client_keys_folder


def read_from_rest(url, txn):
    # send request to sawtooth rest api
    r = requests.get(u"{}/{}".format(url+ '/transactions', txn))
    if (r.status_code != 200):
        print ('status code is {}, details: {}'.format(r.status_code, r.text))
        return False, ""
    elif (len(r.json()['data']) == 0):
        print ('ERROR: returned data size is 0')
        return False, ""
    else:
        return True, base64.b64decode(r.json()['data']['payload'])


def encrypt_request(data, client_keys_folder, keys_path = None):
    # declare args for call of encrypt addresses data API from crypto DLL
    encrypt_addresses_txn = crypto_lib.encrypt_addresses_data
    encrypt_addresses_txn.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_ulonglong, ctypes.c_short, ctypes.POINTER(ctypes.c_ulonglong), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]
    encrypt_addresses_txn.restype = ctypes.c_bool

    # fill in arguments needed for calling the encrypt API
    res_buf = ctypes.POINTER(ctypes.c_ubyte) () 
    svn = ctypes.c_short(0)
    nonce = ctypes.c_ulonglong()
    secret_array = (ctypes.c_ubyte*32) ()
    # data_ptr = ctypes.cast(data, (ctypes.POINTER(ctypes.c_ubyte)))
    secret = ctypes.cast(secret_array, (ctypes.POINTER(ctypes.c_ubyte)))
    path_to_keys = ctypes.c_char_p(keys_path)
    import os
    from os.path import expanduser
    with open(os.path.join(expanduser(client_keys_folder), 'client_public_key.hexstr'), 'r') as pubKeyFile:
        client_pub_key = ctypes.c_char_p(pubKeyFile.read().encode())
    with open(os.path.join(expanduser(client_keys_folder), 'client_private_key.hexstr'), 'r') as privKeyFile:
        client_priv_key = ctypes.c_char_p(privKeyFile.read().encode()) 

    # call API
    res = encrypt_addresses_txn(ctypes.c_char_p(data), len(data), svn ,ctypes.byref(nonce), secret, ctypes.byref(res_buf), client_pub_key, client_priv_key, path_to_keys)
    
    if res:
        size_to_read = 1
        while res_buf[size_to_read] != 0:
           size_to_read = size_to_read + 1
        # copy data
        byteArr = bytearray(size_to_read)
        for i in range(0, size_to_read):
           byteArr[i] = res_buf[i]
        # free data allocated by DLL
        ctypes.CDLL(ctypes.util.find_library('c')).free(res_buf)
    else:
        print ("Error: Encrypt address request failed")
        exit(17)

    return bytes(byteArr), nonce, secret


def dec_data(data, nonce, secret, keys_path = None):
   
    class secure_data(ctypes.Structure):
        _fields_ = [('nonce', ctypes.c_ulonglong),
                    ('address', ctypes.c_char * 71),
                    ('data', ctypes.c_char * (10*1024*1024))] # allocate the max of 10MB

    decrypt_data = crypto_lib.decrypt_data
    decrypt_data.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.c_short, ctypes.c_ulonglong, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.POINTER(secure_data)), ctypes.POINTER(ctypes.c_ulonglong), ctypes.POINTER(ctypes.c_char)]
    decrypt_data.restype = ctypes.c_char_p

    requested_data = ctypes.c_char_p(data)
    svn = ctypes.c_short(0)
    size = ctypes.c_ulonglong(0)
    secure_data_s = secure_data()
    secure_data_p = ctypes.pointer(secure_data_s)
    path_to_keys = ctypes.c_char_p(keys_path)
     
    res = decrypt_data(requested_data, svn, nonce, secret, ctypes.byref(secure_data_p),ctypes.byref(size),path_to_keys )

    if size.value is not 0:
        content = (secure_data_p.contents)
        print ('decoded payload is:\n{}'.format(content.data.decode('ascii')))
        ctypes.CDLL(ctypes.util.find_library('c')).free(secure_data_p)



def main():
    txn_id, url, client_keys_folder = get_arg()
    print ('reqeusted read from {} at transactions {}'.format(url, txn_id))
    status, data = read_from_rest(url, txn_id)
    if not status:
        return
    # add first byte 0 to mark as txn read request and remove null terminator byte from data
    data = (0).to_bytes(1, byteorder='big') +  data[:-1]
    # encrypt request
    enc_req, nonce, secret = encrypt_request(data, client_keys_folder)
    enc_req_url_safe = base64.urlsafe_b64encode(base64.b64decode(enc_req)).decode('ascii')
    # send private read request to sawtooth rest api
    r = requests.get(u"{}/{}".format(url + '/private_state', enc_req_url_safe))
    if (r.status_code != 200):
        print ('status code is {}, details: {}'.format(r.status_code, r.text))
        return
    if (len(r.json()['data']) == 0):
        print ('ERROR: returned data size is 0')
        return
    #decrypt respond and print it
    dec_data(r.json()['data'].encode('ascii'), nonce, secret)

if __name__ == "__main__":
    main()
