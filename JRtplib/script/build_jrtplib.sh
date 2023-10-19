#!/bin/bash

if [ -d "./build" ]; then
  rm -rf build
  else
    echo "do nothing"
fi
mkdir build && cd build
cmake .. 
make -j 6
#echo 123456 | sudo -S make install
sudo make install

