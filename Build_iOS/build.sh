if [ ! -e "OpenSSL-for-iPhone" ]
then
git clone --depth=1 https://github.com/x2on/OpenSSL-for-iPhone.git
pushd OpenSSL-for-iPhone
./build-libssl.sh
popd
fi

if [ ! -e "openssl" ]
then
mkdir -p openssl/lib
cp -r OpenSSL-for-iPhone/bin/iPhoneOS9.3-armv7.sdk/include openssl
cp OpenSSL-for-iPhone/include/LICENSE openssl
lipo -create -output openssl/lib/libssl.a OpenSSL-for-iPhone/bin/iPhone*/lib/libssl.a
lipo -create -output openssl/lib/libcrypto.a OpenSSL-for-iPhone/bin/iPhone*/lib/libcrypto.a
fi

if [ ! -e "boostoniphone" ]
then
git clone https://gist.github.com/c629ae4c7168216a9856.git boostoniphone
pushd boostoniphone
git apply ../fix_boost_building_script.patch
cp ../boost.sh .
chmod +x boost.sh
./boost.sh
pushd ios/framework/boost.framework/Versions/A
mkdir Headers2
mv Headers Headers2/boost
mv Headers2 Headers
popd
popd
mv boostoniphone/ios/framework/boost.framework .
fi

if [ ! -e "ios-cmake" ]
then
git clone https://github.com/cristeab/ios-cmake.git
pushd ios-cmake
git apply ../fix_ios_cmake_compiler.patch
popd
fi

mkdir build.debug
pushd build.debug
cmake .. -DCMAKE_BUILD_TYPE=Debug
make
popd

