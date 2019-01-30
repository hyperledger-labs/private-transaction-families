#!/bin/bash
echo '------------------------------------'
echo 'clear /var/lib/sawtooth'
echo '------------------------------------'
rm -rf /var/lib/sawtooth/* 
rm -rf /var/log/sawtooth/*
exit
