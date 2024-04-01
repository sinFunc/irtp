#!/bin/bash
if [ ! -d "./cmake-build-debug" ]; then
   echo "There is not build directory.please build the project first and run this shell again."
   exit
fi


cd cmake-build-debug
./IRtp localip=172.22.1.100 localport=60000 remoteip=172.22.1.202 remoteport=60000 option=2