#!/bin/bash

#get consensus
if [[ $1 = "poet" || $2 = "poet" ]] ; then
  echo 1
  consensus="poet-engine"
elif [[ $1 = "raft" || $2 = "raft" ]] ; then
  echo 2
  consensus="raft-engine"
else
  echo 3
  consensus="devmode-engine-rust"
fi

#get verbosity level
if [[ $1 = "-v"* ]]; then
  verb="$1"
elif [[ $2 = "-v"* ]]; then
  verb="$2"
else
  verb=""
fi

sudo -u sawtooth ./clear_sawtooth.sh
echo '------------------------------------'
echo 'set keys and genesis batch (dev)'
echo '------------------------------------'
sawtooth keygen --force
sawset genesis
sudo -u sawtooth sawadm genesis config-genesis.batch
sudo sawadm keygen --force
echo '------------------------------------'
echo 'start sawtooth components'
echo '------------------------------------'
gnome-terminal \
--tab -e "bash -c \"sudo -u sawtooth sawtooth-validator $verb; exec bash\"" \
--tab -e "bash -c \"sudo -u sawtooth settings-tp $verb; exec bash\"" \
--tab -e "bash -c \"sudo sawtooth-rest-api $verb; exec bash\"" \
--tab -e "bash -c \"sudo -u sawtooth $consensus -C tcp://127.0.0.1:5050 $verb; exec bash\"";

