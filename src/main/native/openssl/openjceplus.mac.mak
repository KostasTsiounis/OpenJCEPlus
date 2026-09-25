###############################################################################
#
# Copyright IBM Corp. 2026
#
# This code is free software; you can redistribute it and/or modify it
# under the terms provided by IBM in the LICENSE file that accompanied
# this code, including the "Classpath" Exception described therein.
###############################################################################

HOSTOUT = ${BUILDTOP}/ojp-${PLATFORM}
NATIVE_DIR = ${NATIVE_TOPDIR}/openssl
NATIVE_LIB_HOME = ${OPENSSL_HOME}
JNI_CLASS = ${TOPDIR}/src/main/java/com/ibm/crypto/plus/provider/openssl/NativeOpenSSLImplementation.java
JNI_HEADER = com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation.h

ifndef OPENSSL_LIB_LOCATION
	OPENSSL_LIB_LOCATION = ${OPENSSL_HOME}/lib
endif

ifndef OPENSSL_LIB
	OPENSSL_LIB = crypto
endif

TARGET_LIBS := -L ${OPENSSL_LIB_LOCATION} -l ${OPENSSL_LIB}
$(shell cp -f ${OPENSSL_LIB_LOCATION}/libcrypto.3.dylib ${OPENSSL_LIB_LOCATION}/lib${OPENSSL_LIB}.dylib \
	&& install_name_tool -id "@rpath/lib${OPENSSL_LIB}.dylib" ${OPENSSL_LIB_LOCATION}/lib${OPENSSL_LIB}.dylib)
$(info Contents of OPENSSL_LIB_LOCATION=${OPENSSL_LIB_LOCATION}: $(shell ls -la ${OPENSSL_LIB_LOCATION}/libcrypto*))

OBJS = \
	${HOSTOUT}/BuildDate.o \
	${HOSTOUT}/Digest.o \
	${HOSTOUT}/StaticStub.o \
	${HOSTOUT}/Utils.o

TARGET = ${HOSTOUT}/libopenjceplus.dylib

include ../share/common.mac.mak
