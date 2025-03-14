package com.ibm.crypto.plus.provider.ock;

public class NativeOCKAdapterNonFIPS extends NativeOCKAdapter {
    private static NativeOCKAdapterNonFIPS instance = null;

    private NativeOCKAdapterNonFIPS() {
        super(false);
    }

    public static NativeOCKAdapterNonFIPS getInstance() {
        if (instance == null) {
            instance = new NativeOCKAdapterNonFIPS();
        }

        return instance;
    }

}
