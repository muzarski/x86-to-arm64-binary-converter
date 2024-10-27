#!/bin/bash

echo "Installing capstone library and cmake..."
apt-get install -y libcapstone-dev > /dev/null
apt-get install -y cmake > /dev/null

echo "Cloning keystone-engine repo..."
git clone https://github.com/keystone-engine/keystone 2> /dev/null

echo "Building keystone library..."
cd keystone
mkdir build 2> /dev/null
cd build
../make-share.sh

echo "Installing keystone library..."
make install

