#cd ORtp/3rdParty/bcunit-5.2.62
#rm -rf ibuild/
#mkdir ibuild
#cd ibuild
if [ -d "./ibuild" ]; then
  rm -rf ibuild
fi
mkdir ibuild && cd ibuild
cmake .. -DENABLE_SHARED=NO
make -j 5
#echo 123456 | sudo -S make install
sudo make install