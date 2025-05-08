/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import com.ibm.crypto.plus.provider.base.NativeException;

public final class OCKException extends NativeException {

    /**
     * 
     */
    private static final long serialVersionUID = -3104732494450550839L;

    public OCKException(String s) {
        super(s);
    }

    public OCKException(int code) {
        super(code);
    }
}
