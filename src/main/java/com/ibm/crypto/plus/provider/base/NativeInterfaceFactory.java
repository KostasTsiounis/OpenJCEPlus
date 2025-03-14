package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.ock.NativeOCKAdapterFIPS;
import com.ibm.crypto.plus.provider.ock.NativeOCKAdapterNonFIPS;

public class NativeInterfaceFactory {
    public static NativeInterface getImpl(boolean isFIPS) {
        return isFIPS ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
    }
}
