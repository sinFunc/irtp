#!/bin/bash
if [ -d "./build" ]; then
  rm -rf build
fi

gcc_version=$(gcc --version | head -n 1)
#echo ${gcc_version}
gcc_major_version=$(echo "$gcc_version" | awk '{print $3}' | cut -d'.' -f1)
gcc_minor_version=$(echo "$gcc_version" | awk '{print $3}' | cut -d'.' -f2)
#gcc_patch_version=$(echo "$gcc_version" | awk -F '[.-]' '{print $5}')
#echo ${gcc_major_version} ${gcc_minor_version} ${gcc_patch_version}

gcc_target_major=8
gcc_target_minor=3


if [ "$gcc_target_major" -gt "$gcc_major_version" ]; then
  scl enable devtoolset-8 bash
  elif [ "$gcc_target_major" -lt "$gcc_major_version" ]; then
     echo "do nothing"
  else
    if [ "$gcc_target_minor" -gt "$gcc_minor_version" ]; then
      scl enable devtoolset-8 bash
    fi
fi


gcc_new_version=$(gcc --version | head -n 1)
echo ${gcc_new_version}


mkdir build && cd build
cmake .. 
make -j 6
