/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ossl;

public class NativeOSSLAdapterNonFIPS extends NativeOSSLAdapter {
    private static NativeOSSLAdapterNonFIPS instance = null;

    private NativeOSSLAdapterNonFIPS() {
        super(false);
    }

    public static NativeOSSLAdapterNonFIPS getInstance() {
        if (instance == null) {
            instance = new NativeOSSLAdapterNonFIPS();
        }

        return instance;
    }

}
