#cd ORtp/3rdParty/mbedtls-2.28.3
#rm -rf ibuild/
#mkdir ibuild
#cd ibuild
if [ -d "./ibuild" ]; then
  rm -rf ibuild
  else
    echo "do nothing"
fi
mkdir ibuild && cd ibuild
cmake .. -DBUILD_SHARED_LIBS=OFF
make -j 5
echo 123456 | sudo -S make install



