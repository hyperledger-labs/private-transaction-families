#/bin/bash -e
if [ ! -d "sawtooth_rest_api/protobuf" ]; then
    mkdir sawtooth_rest_api/protobuf 
    cp sawtooth_rest_api/__init__.py sawtooth_rest_api/protobuf/
fi
protoc --proto_path=../protos/ --python_out=sawtooth_rest_api/protobuf ../protos/*.proto
# replace all 'import' of proto files to start with 'from . import'
sed -i 's/^import \([^ ]*\)_pb2 as \([^ ]*\)$/from . import \1_pb2 as \2/' sawtooth_rest_api/protobuf/*_pb2.py
