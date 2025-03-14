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