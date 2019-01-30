'''
transaction processor general config file
'''
import hashlib
import json
import os
import sys

import jsonschema

# _family_name = ""
# _encoding = ""
# _family_version = ""
# _namespace = ""
# _signer_key = ""
# _txns_payload = ""
# _set_config = False



def read_config_file(config_file) :
    config_schema_file = 'config_schema.json'
    config_dir = os.path.join(os.path.dirname(__file__))

    with open(config_file) as json_data_file:
        config_data = json.load(json_data_file)

    with open(os.path.join(config_dir, config_schema_file)) as json_schema_file:
        config_schema = json.load(json_schema_file)
    try:
        jsonschema.validate(config_data, config_schema)
    except jsonschema.exceptions.ValidationError as err:
        print('config.json error: {}'.format(err))
        sys.exit(1)
    global _family_name, _encoding, _family_version, _namespace, _signer_key, _txns_payload, _set_config

    _family_name = config_data.get('family_name')
    _encoding = config_data.get('payload_encoding')
    _family_version = str(config_data.get('family_version'))
    _namespace = hashlib.sha512(config_data.get('family_name').encode('utf-8')).hexdigest()[0:6]
    _signer_key = config_data.get('signer_priv_key')
    _txns_payload = config_data.get('txn_payload')
    _set_config = True;


#TODO assert if equals None
def get_family_name():
    return _family_name


def get_encoding():
    return _encoding


def get_family_version():
    return _family_version


def get_namespace():
    return _namespace


def get_signer_key_file():
    return _signer_key


def get_txns():
    return _txns_payload
