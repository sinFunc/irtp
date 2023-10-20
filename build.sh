#!/bin/bash
if [ -d "./build" ]; then
  rm -rf build
fi

gcc_version=$(gcc --version | head -n 1)
gcc_major_version=$(echo "$gcc_version" | awk '{print $3}' | cut -d'.' -f1)
gcc_minor_version=$(echo "$gcc_version" | awk '{print $3}' | cut -d'.' -f2)
#gcc_patch_version=$(echo "$gcc_version" | awk -F '[.-]' '{print $5}')
#echo ${gcc_major_version} ${gcc_minor_version} ${gcc_patch_version}

gcc_target_major=8
gcc_target_minor=3

function print_gcc_info() {
    echo "please update your gcc(${gcc_version})>=8.3.1.you can run command as follow."
    echo "sudo yum install centos-release-scl"
    echo "sudo yum install devtoolset-8-gcc"
    echo "scl enable devtoolset-8 bash"
    echo "try to run scl enable devtoolset-8 bash.please check your gcc version and run this shell again"
    scl enable devtoolset-8 bash
    exit
}

if [ "$gcc_target_major" -gt "$gcc_major_version" ]; then
  print_gcc_info
  elif [ "$gcc_target_major" -lt "$gcc_major_version" ]; then
     echo ${gcc_version}
  else
    if [ "$gcc_target_minor" -gt "$gcc_minor_version" ]; then
      print_gcc_info
    fi
fi

mkdir build && cd build
cmake ..
make -j 6
