/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ossl;

public class NativeOSSLAdapterFIPS extends NativeOSSLAdapter {
    private static NativeOSSLAdapterFIPS instance = null;

    private NativeOSSLAdapterFIPS() {
        super(true);
    }

    public static NativeOSSLAdapterFIPS getInstance() {
        if (instance == null) {
            instance = new NativeOSSLAdapterFIPS();
        }

        return instance;
    }
}
