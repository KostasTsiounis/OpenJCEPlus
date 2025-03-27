/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

public class NativeOCKAdapterFIPS extends NativeOCKAdapter {
    private static NativeOCKAdapterFIPS instance = null;

    private NativeOCKAdapterFIPS() {
        super(true);
    }

    public static NativeOCKAdapterFIPS getInstance() {
        if (instance == null) {
            instance = new NativeOCKAdapterFIPS();
        }

        return instance;
    }

}