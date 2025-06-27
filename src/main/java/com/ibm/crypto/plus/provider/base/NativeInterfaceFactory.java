/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.ock.NativeOCKAdapterFIPS;
import com.ibm.crypto.plus.provider.ock.NativeOCKAdapterNonFIPS;
import com.ibm.crypto.plus.provider.ossl.NativeOSSLAdapterNonFIPS;

public class NativeInterfaceFactory {
    public static NativeAdapter getImpl(boolean isFIPS) {
        return isFIPS ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
    }

    public static NativeAdapter getDigestImpl(boolean isFIPS) {
        return isFIPS ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
    }
}
