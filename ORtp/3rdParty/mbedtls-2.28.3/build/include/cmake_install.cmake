# Install script for directory: /home/sean/installBySrc/mbedtls-2.28.3/include

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/mbedtls" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/aes.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/aesni.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/arc4.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/aria.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/asn1.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/asn1write.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/base64.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/bignum.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/blowfish.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/bn_mul.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/camellia.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/ccm.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/certs.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/chacha20.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/chachapoly.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/check_config.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/cipher.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/cipher_internal.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/cmac.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/compat-1.3.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/config.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/config_psa.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/constant_time.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/ctr_drbg.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/debug.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/des.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/dhm.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/ecdh.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/ecdsa.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/ecjpake.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/ecp.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/ecp_internal.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/entropy.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/entropy_poll.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/error.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/gcm.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/havege.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/hkdf.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/hmac_drbg.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/md.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/md2.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/md4.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/md5.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/md_internal.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/memory_buffer_alloc.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/net.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/net_sockets.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/nist_kw.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/oid.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/padlock.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/pem.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/pk.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/pk_internal.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/pkcs11.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/pkcs12.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/pkcs5.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/platform.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/platform_time.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/platform_util.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/poly1305.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/psa_util.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/ripemd160.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/rsa.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/rsa_internal.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/sha1.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/sha256.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/sha512.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/ssl.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/ssl_cache.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/ssl_ciphersuites.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/ssl_cookie.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/ssl_internal.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/ssl_ticket.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/threading.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/timing.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/version.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/x509.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/x509_crl.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/x509_crt.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/x509_csr.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/mbedtls/xtea.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/psa" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "/home/sean/installBySrc/mbedtls-2.28.3/include/psa/crypto.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/psa/crypto_builtin_composites.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/psa/crypto_builtin_primitives.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/psa/crypto_compat.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/psa/crypto_config.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/psa/crypto_driver_common.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/psa/crypto_driver_contexts_composites.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/psa/crypto_driver_contexts_primitives.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/psa/crypto_extra.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/psa/crypto_platform.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/psa/crypto_se_driver.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/psa/crypto_sizes.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/psa/crypto_struct.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/psa/crypto_types.h"
    "/home/sean/installBySrc/mbedtls-2.28.3/include/psa/crypto_values.h"
    )
endif()

