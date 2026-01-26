/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

public final class RSAPadding {

    public static final int RSAPAD_NONE = 0;
    public static final int RSAPAD_PKCS1 = 1;
    public static final int RSAPAD_OAEP = 2;
    //private static final int RSA_SSLV23_PADDING // Unused?
    //private static final int RSA_X931_PADDING // Unused?
    //private static final int RSA_PKCS1_PSS_PADDING // Unused?

    public static final int NONE = 0;
    public static final int SHA1 = 1;
    public static final int SHA224 = 2;
    public static final int SHA256 = 3;
    public static final int SHA384 = 4;
    public static final int SHA512 = 5;

    public static final RSAPadding NoPadding = new RSAPadding(RSAPAD_NONE, NONE, "NoPadding");
    public static final RSAPadding PKCS1Padding = new RSAPadding(RSAPAD_PKCS1, NONE, "PKCS1Padding");
    public static final RSAPadding OAEPPadding = new RSAPadding(RSAPAD_OAEP, SHA1, "OAEPPadding");
    public static final RSAPadding OAEPPaddingSHA224 = new RSAPadding(RSAPAD_OAEP, SHA224, "OAEPPadding");
    public static final RSAPadding OAEPPaddingSHA256 = new RSAPadding(RSAPAD_OAEP, SHA256, "OAEPPadding");
    public static final RSAPadding OAEPPaddingSHA384 = new RSAPadding(RSAPAD_OAEP, SHA384, "OAEPPadding");
    public static final RSAPadding OAEPPaddingSHA512 = new RSAPadding(RSAPAD_OAEP, SHA512, "OAEPPadding");

    private int id;
    private int md;
    private String description;

    private RSAPadding(int id, int md, String description) {
        this.id = id;
        this.md = md;
        this.description = description;
    }

    public int getId() {
        return id;
    }

    public boolean isPadding(int paddingId) {
        return id == paddingId;
    }

    public int getMessageDigest() {
        return md;
    }

    public String toString() {
        return description;
    }
}
