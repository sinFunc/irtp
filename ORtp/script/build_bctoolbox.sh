#cd ORtp/3rdParty/bctoolbox-5.2.64
#rm -rf ibuild/
#mkdir ibuild
#cd ibuild
if [ -d "./ibuild" ]; then
  rm -rf ibuild
  else
    echo "do nothing"
fi
mkdir ibuild && cd ibuild
cmake .. -DENABLE_SHARED=OFF -DENABLE_STRICT=OFF -DENABLE_TESTS_COMPONENT=OFF -DENABLE_TESTS=OFF
make -j 5
echo 123456 | sudo -S make install