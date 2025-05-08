/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ossl;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.ByteBuffer;
import java.security.ProviderException;

import com.ibm.crypto.plus.provider.base.NativeAdapter;

import sun.security.util.Debug;

public abstract class NativeOSSLAdapter extends NativeAdapter {
    // These code values must match those defined in Context.h.
    //
    private static final int VALUE_ID_FIPS_APPROVED_MODE = 0;
    private static final int VALUE_OSSL_INSTALL_PATH = 1;
    private static final int VALUE_OSSL_VERSION = 2;

    // User enabled debugging
    private static Debug debug = Debug.getInstance("jceplus");

    static final String unobtainedValue = new String();

    // whether to validate OSSL was loaded from JRE location
    private static final boolean validateOSSLLocation = true;

    // whether to validate OSSL version of load library matches version in ICCSIG.txt
    private static final boolean validateOSSLVersion = false;

    private boolean osslInitialized = false;
    private boolean useFIPSMode;

    private String osslVersion = unobtainedValue;
    private String osslInstallPath = unobtainedValue;

    // The following is a special String instance to indicate that a
    // value has not yet been obtained.  We do this because some values
    // may be null and we only want to query the value one time.
    //
    private static String libraryBuildDate = unobtainedValue;

    NativeOSSLAdapter(boolean useFIPSMode) {
        this.useFIPSMode = useFIPSMode;
        initializeContext();
    }
    // Initialize OSSL context(s)
    //
    private synchronized void initializeContext() {
        // Leave this duplicate check in here. If two threads are both trying
        // to instantiate an OpenJCEPlus provider at the same time, we need to
        // ensure that the initialization only happens one time. We have
        // made the method synchronizaed to ensure only one thread can execute
        // the method at a time.
        //
        if (osslInitialized) {
            return;
        }

        try {
            if (validateOSSLLocation) {
                validateLibraryLocation();
            }

            if (validateOSSLVersion) {
                validateLibraryVersion();
            }

            this.osslInitialized = true;
        } catch (Throwable t) {
            ProviderException exceptionToThrow = providerException(
                    "Failed to initialize OpenJCEPlus provider", t);

            if (exceptionToThrow.getCause() == null) {
                // We are not including the full stack trace back to the point
                // of origin.
                // Try and obtain the message for the underlying cause of the
                // exception
                //
                // If an ExceptionInInitializerError or NoClassDefFoundError is
                // thrown, we want to get the message from the cause of that
                // exception.
                //
                if ((t instanceof java.lang.ExceptionInInitializerError)
                        || (t instanceof java.lang.NoClassDefFoundError)) {
                    Throwable cause = t.getCause();
                    if (cause != null) {
                        t = cause;
                    }
                }

                // In the case that the JNI library could not be loaded.
                //
                String message = t.getMessage();
                if ((message != null) && (message.length() > 0)) {
                    // We want to see the message for the underlying cause even
                    // if not showing the stack trace all the way back to the
                    // point of origin.
                    //
                    exceptionToThrow.initCause(new ProviderException(t.getMessage()));
                }
            }

            if (debug != null) {
                exceptionToThrow.printStackTrace(System.out);
            }

            throw exceptionToThrow;
        }
    }

    @Override
    public String getLibraryVersion() {
        if (osslVersion == unobtainedValue) {
            obtainOSSLVersion();
        }
        return osslVersion;
    }

    @Override
    public String getLibraryInstallPath() {
        if (osslInstallPath == unobtainedValue) {
            obtainOSSLInstallPath();
        }
        return osslInstallPath;
    }


    private synchronized void obtainOSSLVersion() {
        // Leave this duplicate check in here. If two threads are both trying
        // to get the value at the same time, we only want to call the native
        // code one time.
        //
        if (osslVersion == unobtainedValue) {
            osslVersion = CTX_getValue(VALUE_OSSL_VERSION);
        }
    }

    private synchronized void obtainOSSLInstallPath() {
        // Leave this duplicate check in here. If two threads are both trying
        // to get the value at the same time, we only want to call the native
        // code one time.
        //
        if (osslInstallPath == unobtainedValue) {
            osslInstallPath = CTX_getValue(VALUE_OSSL_INSTALL_PATH);
        }
    }

    @Override
    public void validateLibraryLocation() throws ProviderException {
        if (NativeOSSLImplementation.requirePreloadOSSL == false) {
            // If we are not requiring OSSL to be pre-loaded, then it does not need to be
            // loaded from the JRE location
            //
            return;
        }

        try {
            // Check to make sure that the OSSL install path is within the JRE
            //
            String ockLoadPath = new File(NativeOSSLImplementation.getOSSLLoadPath()).getCanonicalPath();
            String ockInstallPath = new File(getLibraryInstallPath()).getCanonicalPath();

            if (debug != null) {
                debug.println("dependent library load path : " + ockLoadPath);
                debug.println("dependent library install path : " + ockInstallPath);
            }

            if (ockInstallPath.startsWith(ockLoadPath) == false) {
                String exceptionMessage = "Dependent library was loaded from an external location";

                if (debug != null) {
                    exceptionMessage = "Dependent library was loaded from " + ockInstallPath;
                }

                throw new ProviderException(exceptionMessage);
            }
        } catch (java.io.IOException e) {
            throw new ProviderException("Failed to validate dependent library", e);
        }
    }

    @Override
    public void validateLibraryVersion() throws ProviderException {
        if (NativeOSSLImplementation.requirePreloadOSSL == false) {
            // If we are not requiring OSSL to be pre-loaded, then it does not need to be
            // a specific version
            //
            return;
        }

        String expectedVersion = getExpectedLibraryVersion();
        String actualVersion = getLibraryVersion();

        if (expectedVersion == null) {
            throw new ProviderException(
                    "Could not not determine expected version of dependent library");
        } else if (expectedVersion.equals(actualVersion) == false) {
            throw new ProviderException("Expected depdendent library version " + expectedVersion
                    + ", got " + actualVersion);
        }
    }

    private String getExpectedLibraryVersion() {
        String ockLoadPath = NativeOSSLImplementation.getOSSLLoadPath();
        String ockSigFileName;
        if (this.useFIPSMode) {
            ockSigFileName = ockLoadPath + File.separator + "C" + File.separator + "icc"
                    + File.separator + "icclib" + File.separator + "ICCSIG.txt";
        } else {
            ockSigFileName = ockLoadPath + File.separator + "N" + File.separator + "icc"
                    + File.separator + "icclib" + File.separator + "ICCSIG.txt";
        }
        BufferedReader br = null;
        try {
            String line;
            String versionMarker = "# ICC Version ";
            br = new BufferedReader(new FileReader(ockSigFileName));
            while ((line = br.readLine()) != null) {
                if (line.startsWith(versionMarker)) {
                    String version = line.substring(versionMarker.length()).trim();
                    return version;
                }
            }
        } catch (Exception e) {
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (Exception e) {
                }
            }
        }

        return null;
    }

    @Override
    public String getLibraryBuildDate() {
        if (libraryBuildDate == unobtainedValue) {
            libraryBuildDate = NativeOSSLImplementation.getLibraryBuildDate();;
        }
        return libraryBuildDate;
    }

    @Override
    public long initializeOCK(boolean isFIPS) {
        return NativeOSSLImplementation.initializeOSSL(isFIPS);
    }

    @Override
    public String CTX_getValue(int valueId) {
        return NativeOSSLImplementation.CTX_getValue(valueId);
    }

    @Override
    public long getByteBufferPointer(ByteBuffer b) {
        return NativeOSSLImplementation.getByteBufferPointer(b);
    }

    @Override
    public void RAND_nextBytes(byte[] buffer) {
        NativeOSSLImplementation.RAND_nextBytes(buffer);
    }

    @Override
    public void RAND_setSeed(byte[] seed) {
        NativeOSSLImplementation.RAND_setSeed(seed);
    }

    @Override
    public void RAND_generateSeed(byte[] seed) {
        NativeOSSLImplementation.RAND_generateSeed(seed);
    }

    @Override
    public long EXTRAND_create(String algName) {
        return NativeOSSLImplementation.EXTRAND_create(algName);
    }

    @Override
    public void EXTRAND_nextBytes(long ockPRNGContextId, byte[] buffer) {
        NativeOSSLImplementation.EXTRAND_nextBytes(ockPRNGContextId, buffer);
    }

    @Override
    public void EXTRAND_setSeed(long ockPRNGContextId, byte[] seed) {
        NativeOSSLImplementation.EXTRAND_setSeed(ockPRNGContextId, seed);
    }

    @Override
    public void EXTRAND_delete(long ockPRNGContextId) {
        NativeOSSLImplementation.EXTRAND_delete(ockPRNGContextId);
    }

    @Override
    public long CIPHER_create(String cipher) {
        return NativeOSSLImplementation.CIPHER_create(cipher);
    }

    @Override
    public void CIPHER_init(long ockCipherId, int isEncrypt, int paddingId, byte[] key, byte[] iv) {
        NativeOSSLImplementation.CIPHER_init(ockCipherId, isEncrypt, paddingId, key, iv);
    }

    @Override
    public void CIPHER_clean(long ockCipherId) {
        NativeOSSLImplementation.CIPHER_clean(ockCipherId);
    }

    @Override
    public void CIPHER_setPadding(long ockCipherId, int paddingId) {
        NativeOSSLImplementation.CIPHER_setPadding(ockCipherId, paddingId);
    }

    @Override
    public int CIPHER_getBlockSize(long ockCipherId) {
        return NativeOSSLImplementation.CIPHER_getBlockSize(ockCipherId);
    }

    @Override
    public int CIPHER_getKeyLength(long ockCipherId) {
        return NativeOSSLImplementation.CIPHER_getKeyLength(ockCipherId);
    }

    @Override
    public int CIPHER_getIVLength(long ockCipherId) {
        return NativeOSSLImplementation.CIPHER_getIVLength(ockCipherId);
    }

    @Override
    public int CIPHER_getOID(long ockCipherId) {
        return NativeOSSLImplementation.CIPHER_getOID(ockCipherId);
    }

    @Override
    public int CIPHER_encryptUpdate(long ockCipherId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset, boolean needsReinit) {
        return NativeOSSLImplementation.CIPHER_encryptUpdate(ockCipherId,
            plaintext, plaintextOffset, plaintextLen, ciphertext, ciphertextOffset, needsReinit);
    }

    @Override
    public int CIPHER_decryptUpdate(long ockCipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, boolean needsReinit) {
        return NativeOSSLImplementation.CIPHER_decryptUpdate(ockCipherId,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, needsReinit);
    }

    @Override
    public int CIPHER_encryptFinal(long ockCipherId, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset, boolean needsReinit) {
        return NativeOSSLImplementation.CIPHER_encryptFinal(ockCipherId,
            input, inOffset, inLen, ciphertext, ciphertextOffset, needsReinit);
    }

    @Override
    public int CIPHER_decryptFinal(long ockCipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, boolean needsReinit) {
        return NativeOSSLImplementation.CIPHER_decryptFinal(ockCipherId,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, needsReinit);
    }

    @Override
    public long checkHardwareSupport() {
        return NativeOSSLImplementation.checkHardwareSupport();
    }

    @Override
    public void CIPHER_delete(long ockCipherId) {
        NativeOSSLImplementation.CIPHER_delete(ockCipherId);
    }

    @Override
    public int z_kmc_native(byte[] input, int inputOffset, byte[] output, int outputOffset, long paramPointer,
            int inputLength, int mode) {
        return NativeOSSLImplementation.z_kmc_native(input, inputOffset, output, outputOffset, paramPointer, inputLength, mode);
    }

    @Override
    public long POLY1305CIPHER_create(String cipher) {
        return NativeOSSLImplementation.POLY1305CIPHER_create(cipher);
    }

    @Override
    public void POLY1305CIPHER_init(long ockCipherId, int isEncrypt, byte[] key, byte[] iv) {
        NativeOSSLImplementation.POLY1305CIPHER_init(ockCipherId, isEncrypt, key, iv);
    }

    @Override
    public void POLY1305CIPHER_clean(long ockCipherId) {
        NativeOSSLImplementation.POLY1305CIPHER_clean(ockCipherId);
    }

    @Override
    public void POLY1305CIPHER_setPadding(long ockCipherId, int paddingId) {
        NativeOSSLImplementation.POLY1305CIPHER_setPadding(ockCipherId, paddingId);
    }

    @Override
    public int POLY1305CIPHER_getBlockSize(long ockCipherId) {
        return NativeOSSLImplementation.POLY1305CIPHER_getBlockSize(ockCipherId);
    }

    @Override
    public int POLY1305CIPHER_getKeyLength(long ockCipherId) {
        return NativeOSSLImplementation.POLY1305CIPHER_getKeyLength(ockCipherId);
    }

    @Override
    public int POLY1305CIPHER_getIVLength(long ockCipherId) {
        return NativeOSSLImplementation.POLY1305CIPHER_getIVLength(ockCipherId);
    }

    @Override
    public int POLY1305CIPHER_getOID(long ockCipherId) {
        return NativeOSSLImplementation.POLY1305CIPHER_getOID(ockCipherId);
    }

    @Override
    public int POLY1305CIPHER_encryptUpdate(long ockCipherId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset) {
        return NativeOSSLImplementation.POLY1305CIPHER_encryptUpdate(ockCipherId,
            plaintext, plaintextOffset, plaintextLen, ciphertext, ciphertextOffset);
    }

    @Override
    public int POLY1305CIPHER_decryptUpdate(long ockCipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset) {
        return NativeOSSLImplementation.POLY1305CIPHER_decryptUpdate(ockCipherId,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset);
    }

    @Override
    public int POLY1305CIPHER_encryptFinal(long ockCipherId, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset, byte[] tag) {
        return NativeOSSLImplementation.POLY1305CIPHER_encryptFinal(ockCipherId,
            input, inOffset, inLen, ciphertext, ciphertextOffset, tag);
    }

    @Override
    public int POLY1305CIPHER_decryptFinal(long ockCipherId, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, byte[] tag) {
        return NativeOSSLImplementation.POLY1305CIPHER_decryptFinal(ockCipherId,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, tag);
    }

    @Override
    public void POLY1305CIPHER_delete(long ockCipherId) {
        NativeOSSLImplementation.POLY1305CIPHER_delete(ockCipherId);
    }

    @Override
    public long do_GCM_checkHardwareGCMSupport() {
        return NativeOSSLImplementation.do_GCM_checkHardwareGCMSupport();
    }

    @Override
    public int do_GCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) {
        return NativeOSSLImplementation.do_GCM_encryptFastJNI_WithHardwareSupport(keyLen, ivLen,
            inOffset, inLen, ciphertextOffset, aadLen, tagLen, parameterBuffer,
            input, inputOffset, output, outputOffset);
    }

    @Override
    public int do_GCM_encryptFastJNI(long gcmCtx, int keyLen, int ivLen, int inOffset, int inLen, int ciphertextOffset,
            int aadLen, int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer) {
        return NativeOSSLImplementation.do_GCM_encryptFastJNI(gcmCtx, keyLen, ivLen, inOffset, inLen,
            ciphertextOffset, aadLen, tagLen, parameterBuffer, inputBuffer, outputBuffer);
    }

    @Override
    public int do_GCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) {
        return NativeOSSLImplementation.do_GCM_decryptFastJNI_WithHardwareSupport(keyLen, ivLen, inOffset, inLen,
            ciphertextOffset, aadLen, tagLen, parameterBuffer, input, inputOffset, output, outputOffset);
    }

    @Override
    public int do_GCM_decryptFastJNI(long gcmCtx, int keyLen, int ivLen, int ciphertextOffset, int ciphertextLen,
            int plainOffset, int aadLen, int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer) {
        return NativeOSSLImplementation.do_GCM_decryptFastJNI(gcmCtx, keyLen, ivLen,
            ciphertextOffset, ciphertextLen, plainOffset, aadLen, tagLen, parameterBuffer, inputBuffer, outputBuffer);
    }

    @Override
    public int do_GCM_encrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input, int inOffset,
            int inLen, byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen) {
        return NativeOSSLImplementation.do_GCM_encrypt(gcmCtx, key, keyLen, iv, ivLen,
            input, inOffset, inLen, ciphertext, ciphertextOffset, aad, aadLen, tag, tagLen);
    }

    @Override
    public int do_GCM_decrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] ciphertext,
            int cipherOffset, int cipherLen, byte[] plaintext, int plaintextOffset, byte[] aad, int aadLen, int tagLen) {
        return NativeOSSLImplementation.do_GCM_decrypt(gcmCtx, key, keyLen, iv, ivLen,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, aad, aadLen, tagLen);
    }

    @Override
    public int do_GCM_FinalForUpdateEncrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input,
            int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag,
            int tagLen) {
        return NativeOSSLImplementation.do_GCM_FinalForUpdateEncrypt(gcmCtx, key, keyLen, iv, ivLen,
            input, inOffset, inLen, ciphertext, ciphertextOffset, aad, aadLen, tag, tagLen);
    }

    @Override
    public int do_GCM_FinalForUpdateDecrypt(long gcmCtx, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, int plaintextlen, byte[] aad, int aadLen, int tagLen) {
        return NativeOSSLImplementation.do_GCM_FinalForUpdateDecrypt(gcmCtx,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset, plaintextlen, aad, aadLen, tagLen);
    }

    @Override
    public int do_GCM_UpdForUpdateEncrypt(long gcmCtx, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset) {
        return NativeOSSLImplementation.do_GCM_UpdForUpdateEncrypt(gcmCtx,
            input, inOffset, inLen, ciphertext, ciphertextOffset);
    }

    @Override
    public int do_GCM_UpdForUpdateDecrypt(long gcmCtx, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset) {
        return NativeOSSLImplementation.do_GCM_UpdForUpdateDecrypt(gcmCtx,
            ciphertext, cipherOffset, cipherLen, plaintext, plaintextOffset);
    }

    @Override
    public int do_GCM_InitForUpdateEncrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] aad,
            int aadLen) {
        return NativeOSSLImplementation.do_GCM_InitForUpdateEncrypt(gcmCtx,
            key, keyLen, iv, ivLen, aad, aadLen);
    }

    @Override
    public int do_GCM_InitForUpdateDecrypt(long gcmCtx, byte[] key, int keyLen, byte[] iv, int ivLen, byte[] aad,
            int aadLen) {
        return NativeOSSLImplementation.do_GCM_InitForUpdateDecrypt(gcmCtx,
            key, keyLen, iv, ivLen, aad, aadLen);
    }

    @Override
    public void do_GCM_delete() {
        NativeOSSLImplementation.do_GCM_delete();
    }

    @Override
    public void free_GCM_ctx(long gcmContextId) {
        NativeOSSLImplementation.free_GCM_ctx(gcmContextId);
    }

    @Override
    public long create_GCM_context() {
        return NativeOSSLImplementation.create_GCM_context();
    }

    @Override
    public long do_CCM_checkHardwareCCMSupport() {
        return NativeOSSLImplementation.do_CCM_checkHardwareCCMSupport();
    }

    @Override
    public int do_CCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) {
        return NativeOSSLImplementation.do_CCM_encryptFastJNI_WithHardwareSupport(keyLen, ivLen, inOffset, inLen,
            ciphertextOffset, aadLen, tagLen, parameterBuffer, input, inputOffset, output, outputOffset);
    }

    @Override
    public int do_CCM_encryptFastJNI(int keyLen, int ivLen, int inLen, int ciphertextLen, int aadLen, int tagLen,
            long parameterBuffer, long inputBuffer, long outputBuffer) {
        return NativeOSSLImplementation.do_CCM_encryptFastJNI(keyLen, ivLen, inLen,
            ciphertextLen, aadLen, tagLen, parameterBuffer, inputBuffer, outputBuffer);
    }

    @Override
    public int do_CCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen, int inOffset, int inLen,
            int ciphertextOffset, int aadLen, int tagLen, long parameterBuffer, byte[] input, int inputOffset,
            byte[] output, int outputOffset) {
        return NativeOSSLImplementation.do_CCM_decryptFastJNI_WithHardwareSupport(keyLen, ivLen, inOffset, inLen,
            ciphertextOffset, aadLen, tagLen, parameterBuffer, input, inputOffset, output, outputOffset);
    }

    @Override
    public int do_CCM_decryptFastJNI(int keyLen, int ivLen, int ciphertextLen, int plaintextLen, int aadLen, int tagLen,
            long parameterBuffer, long inputBuffer, long outputBuffer) {
        return NativeOSSLImplementation.do_CCM_decryptFastJNI(keyLen, ivLen, ciphertextLen,
            plaintextLen, aadLen, tagLen, parameterBuffer, inputBuffer, outputBuffer);
    }

    @Override
    public int do_CCM_encrypt(byte[] iv, int ivLen, byte[] key, int keyLen, byte[] aad, int aadLen, byte[] input,
            int inLen, byte[] ciphertext, int ciphertextLen, int tagLen) {
        return NativeOSSLImplementation.do_CCM_encrypt(iv, ivLen, key, keyLen,
            aad, aadLen, input, inLen, ciphertext, ciphertextLen, tagLen);
    }

    @Override
    public int do_CCM_decrypt(byte[] iv, int ivLen, byte[] key, int keyLen, byte[] aad, int aadLen, byte[] ciphertext,
            int ciphertextLength, byte[] plaintext, int plaintextLength, int tagLen) {
        return NativeOSSLImplementation.do_CCM_decrypt(iv, ivLen, key, keyLen,
            aad, aadLen, ciphertext, ciphertextLength, plaintext, plaintextLength, tagLen);
    }

    @Override
    public void do_CCM_delete() {
        NativeOSSLImplementation.do_CCM_delete();
    }

    @Override
    public int RSACIPHER_public_encrypt(long rsaKeyId, int rsaPaddingId, byte[] plaintext, int plaintextOffset,
            int plaintextLen, byte[] ciphertext, int ciphertextOffset) {
        return NativeOSSLImplementation.RSACIPHER_public_encrypt(rsaKeyId, rsaPaddingId,
            plaintext, plaintextOffset, plaintextLen, ciphertext, ciphertextOffset);
    }

    @Override
    public int RSACIPHER_private_encrypt(long rsaKeyId, int rsaPaddingId, byte[] plaintext, int plaintextOffset,
            int plaintextLen, byte[] ciphertext, int ciphertextOffset, boolean convertKey) {
        return NativeOSSLImplementation.RSACIPHER_private_encrypt(rsaKeyId, rsaPaddingId,
            plaintext, plaintextOffset, plaintextLen, ciphertext, ciphertextOffset, convertKey);
    }

    @Override
    public int RSACIPHER_public_decrypt(long rsaKeyId, int rsaPaddingId, byte[] ciphertext, int ciphertextOffset,
            int ciphertextLen, byte[] plaintext, int plaintextOffset) {
        return NativeOSSLImplementation.RSACIPHER_public_decrypt(rsaKeyId, rsaPaddingId,
            ciphertext, ciphertextOffset, ciphertextLen, plaintext, plaintextOffset);
    }

    @Override
    public int RSACIPHER_private_decrypt(long rsaKeyId, int rsaPaddingId, byte[] ciphertext, int ciphertextOffset,
            int ciphertextLen, byte[] plaintext, int plaintextOffset, boolean convertKey) {
        return NativeOSSLImplementation.RSACIPHER_private_decrypt(rsaKeyId, rsaPaddingId,
            ciphertext, ciphertextOffset, ciphertextLen, plaintext, plaintextOffset, convertKey);
    }

    @Override
    public long DHKEY_generate(int numBits) {
        return NativeOSSLImplementation.DHKEY_generate(numBits);
    }

    @Override
    public byte[] DHKEY_generateParameters(int numBits) {
        return NativeOSSLImplementation.DHKEY_generateParameters(numBits);
    }

    @Override
    public long DHKEY_generate(byte[] dhParameters) {
        return NativeOSSLImplementation.DHKEY_generate(dhParameters);
    }

    @Override
    public long DHKEY_createPrivateKey(byte[] privateKeyBytes) {
        return NativeOSSLImplementation.DHKEY_createPrivateKey(privateKeyBytes);
    }

    @Override
    public long DHKEY_createPublicKey(byte[] publicKeyBytes) {
        return NativeOSSLImplementation.DHKEY_createPublicKey(publicKeyBytes);
    }

    @Override
    public byte[] DHKEY_getParameters(long dhKeyId) {
        return NativeOSSLImplementation.DHKEY_getParameters(dhKeyId);
    }

    @Override
    public byte[] DHKEY_getPrivateKeyBytes(long dhKeyId) {
        return NativeOSSLImplementation.DHKEY_getPrivateKeyBytes(dhKeyId);
    }

    @Override
    public byte[] DHKEY_getPublicKeyBytes(long dhKeyId) {
        return NativeOSSLImplementation.DHKEY_getPublicKeyBytes(dhKeyId);
    }

    @Override
    public long DHKEY_createPKey(long dhKeyId) {
        return NativeOSSLImplementation.DHKEY_createPKey(dhKeyId);
    }

    @Override
    public byte[] DHKEY_computeDHSecret(long pubKeyId, long privKeyId) {
        return NativeOSSLImplementation.DHKEY_computeDHSecret(pubKeyId, privKeyId);
    }

    @Override
    public void DHKEY_delete(long dhKeyId) {
        NativeOSSLImplementation.DHKEY_delete(dhKeyId);
    }

    @Override
    public long RSAKEY_generate(int numBits, long e) {
        return NativeOSSLImplementation.RSAKEY_generate(numBits, e);
    }

    @Override
    public long RSAKEY_createPrivateKey(byte[] privateKeyBytes) {
        return NativeOSSLImplementation.RSAKEY_createPrivateKey(privateKeyBytes);
    }

    @Override
    public long RSAKEY_createPublicKey(byte[] publicKeyBytes) {
        return NativeOSSLImplementation.RSAKEY_createPublicKey(publicKeyBytes);
    }

    @Override
    public byte[] RSAKEY_getPrivateKeyBytes(long rsaKeyId) {
        return NativeOSSLImplementation.RSAKEY_getPrivateKeyBytes(rsaKeyId);
    }

    @Override
    public byte[] RSAKEY_getPublicKeyBytes(long rsaKeyId) {
        return NativeOSSLImplementation.RSAKEY_getPublicKeyBytes(rsaKeyId);
    }

    @Override
    public long RSAKEY_createPKey(long rsaKeyId) {
        return NativeOSSLImplementation.RSAKEY_createPKey(rsaKeyId);
    }

    @Override
    public int RSAKEY_size(long rsaKeyId) {
        return NativeOSSLImplementation.RSAKEY_size(rsaKeyId);
    }

    @Override
    public void RSAKEY_delete(long rsaKeyId) {
        NativeOSSLImplementation.RSAKEY_delete(rsaKeyId);
    }

    @Override
    public long DSAKEY_generate(int numBits) {
        return NativeOSSLImplementation.DSAKEY_generate(numBits);
    }

    @Override
    public byte[] DSAKEY_generateParameters(int numBits) {
        return NativeOSSLImplementation.DSAKEY_generateParameters(numBits);
    }

    @Override
    public long DSAKEY_generate(byte[] dsaParameters) {
        return NativeOSSLImplementation.DSAKEY_generate(dsaParameters);
    }

    @Override
    public long DSAKEY_createPrivateKey(byte[] privateKeyBytes) {
        return NativeOSSLImplementation.DSAKEY_createPrivateKey(privateKeyBytes);
    }

    @Override
    public long DSAKEY_createPublicKey(byte[] publicKeyBytes) {
        return NativeOSSLImplementation.DSAKEY_createPublicKey(publicKeyBytes);
    }

    @Override
    public byte[] DSAKEY_getParameters(long dsaKeyId) {
        return NativeOSSLImplementation.DSAKEY_getParameters(dsaKeyId);
    }

    @Override
    public byte[] DSAKEY_getPrivateKeyBytes(long dsaKeyId) {
        return NativeOSSLImplementation.DSAKEY_getPrivateKeyBytes(dsaKeyId);
    }

    @Override
    public byte[] DSAKEY_getPublicKeyBytes(long dsaKeyId) {
        return NativeOSSLImplementation.DSAKEY_getPublicKeyBytes(dsaKeyId);
    }

    @Override
    public long DSAKEY_createPKey(long dsaKeyId) {
        return NativeOSSLImplementation.DSAKEY_createPKey(dsaKeyId);
    }

    @Override
    public void DSAKEY_delete(long dsaKeyId) {
        NativeOSSLImplementation.DSAKEY_delete(dsaKeyId);
    }

    @Override
    public void PKEY_delete(long pkeyId) {
        NativeOSSLImplementation.PKEY_delete(pkeyId);
    }

    @Override
    public long DIGEST_create(String digestAlgo) {
        return NativeOSSLImplementation.DIGEST_create(digestAlgo);
    }

    @Override
    public long DIGEST_copy(long digestId) {
        return NativeOSSLImplementation.DIGEST_copy(digestId);
    }

    @Override
    public int DIGEST_update(long digestId, byte[] input, int offset, int length) {
        return NativeOSSLImplementation.DIGEST_update(digestId, input, offset, length);
    }

    @Override
    public void DIGEST_updateFastJNI(long digestId, long inputBuffer, int length) {
        NativeOSSLImplementation.DIGEST_updateFastJNI(digestId, inputBuffer, length);
    }

    @Override
    public byte[] DIGEST_digest(long digestId) {
        return NativeOSSLImplementation.DIGEST_digest(digestId);
    }

    @Override
    public void DIGEST_digest_and_reset(long digestId, long outputBuffer, int length) {
        NativeOSSLImplementation.DIGEST_digest_and_reset(digestId, outputBuffer, length);
    }

    @Override
    public int DIGEST_digest_and_reset(long digestId, byte[] output) {
        return NativeOSSLImplementation.DIGEST_digest_and_reset(digestId, output);
    }

    @Override
    public int DIGEST_size(long digestId) {
        return NativeOSSLImplementation.DIGEST_size(digestId);
    }

    @Override
    public void DIGEST_reset(long digestId) {
        NativeOSSLImplementation.DIGEST_reset(digestId);
    }

    @Override
    public void DIGEST_delete(long digestId) {
        NativeOSSLImplementation.DIGEST_delete(digestId);
    }

    @Override
    public byte[] SIGNATURE_sign(long digestId, long pkeyId, boolean convert) {
        return NativeOSSLImplementation.SIGNATURE_sign(digestId, pkeyId, convert);
    }

    @Override
    public boolean SIGNATURE_verify(long digestId, long pkeyId, byte[] sigBytes) {
        return NativeOSSLImplementation.SIGNATURE_verify(digestId, pkeyId, sigBytes);
    }

    @Override
    public byte[] SIGNATUREEdDSA_signOneShot(long pkeyId, byte[] bytes) {
        return NativeOSSLImplementation.SIGNATUREEdDSA_signOneShot(pkeyId, bytes);
    }

    @Override
    public boolean SIGNATUREEdDSA_verifyOneShot(long pkeyId, byte[] sigBytes, byte[] oneShot) {
        return NativeOSSLImplementation.SIGNATUREEdDSA_verifyOneShot(pkeyId, sigBytes, oneShot);
    }

    @Override
    public int RSAPSS_signInit(long rsaPssId, long pkeyId, int saltlen, boolean convert) {
        return NativeOSSLImplementation.RSAPSS_signInit(rsaPssId, pkeyId, saltlen, convert);
    }

    @Override
    public int RSAPSS_verifyInit(long rsaPssId, long pkeyId, int saltlen) {
        return NativeOSSLImplementation.RSAPSS_verifyInit(rsaPssId, pkeyId, saltlen);
    }

    @Override
    public int RSAPSS_getSigLen(long rsaPssId) {
        return NativeOSSLImplementation.RSAPSS_getSigLen(rsaPssId);
    }

    @Override
    public void RSAPSS_signFinal(long rsaPssId, byte[] signature, int length) {
        NativeOSSLImplementation.RSAPSS_signFinal(rsaPssId, signature, length);
    }

    @Override
    public boolean RSAPSS_verifyFinal(long rsaPssId, byte[] sigBytes, int length) {
        return NativeOSSLImplementation.RSAPSS_verifyFinal(rsaPssId, sigBytes, length);
    }

    @Override
    public long RSAPSS_createContext(String digestAlgo, String mgf1SpecAlgo) {
        return NativeOSSLImplementation.RSAPSS_createContext(digestAlgo, mgf1SpecAlgo);
    }

    @Override
    public void RSAPSS_releaseContext(long rsaPssId) {
        NativeOSSLImplementation.RSAPSS_releaseContext(rsaPssId);
    }

    @Override
    public void RSAPSS_digestUpdate(long rsaPssId, byte[] input, int offset, int length) {
        NativeOSSLImplementation.RSAPSS_digestUpdate(rsaPssId, input, offset, length);
    }

    @Override
    public void RSAPSS_reset(long digestId) {
        NativeOSSLImplementation.RSAPSS_reset(digestId);
    }

    @Override
    public void RSAPSS_resetDigest(long rsaPssId) {
        NativeOSSLImplementation.RSAPSS_resetDigest(rsaPssId);
    }

    @Override
    public byte[] DSANONE_SIGNATURE_sign(byte[] digest, long dsaKeyId) {
        return NativeOSSLImplementation.DSANONE_SIGNATURE_sign(digest, dsaKeyId);
    }

    @Override
    public boolean DSANONE_SIGNATURE_verify(byte[] digest, long dsaKeyId, byte[] sigBytes) {
        return NativeOSSLImplementation.DSANONE_SIGNATURE_verify(digest, dsaKeyId, sigBytes);
    }

    @Override
    public byte[] RSASSL_SIGNATURE_sign(byte[] digest, long rsaKeyId) {
        return NativeOSSLImplementation.RSASSL_SIGNATURE_sign(digest, rsaKeyId);
    }

    @Override
    public boolean RSASSL_SIGNATURE_verify(byte[] digest, long rsaKeyId, byte[] sigBytes, boolean convert) {
        return NativeOSSLImplementation.RSASSL_SIGNATURE_verify(digest, rsaKeyId, sigBytes, convert);
    }

    @Override
    public long HMAC_create(String digestAlgo) {
        return NativeOSSLImplementation.HMAC_create(digestAlgo);
    }

    @Override
    public int HMAC_update(long hmacId, byte[] key, int keyLength, byte[] input, int inputOffset, int inputLength,
            boolean needInit) {
        return NativeOSSLImplementation.HMAC_update(hmacId, key, keyLength,
            input, inputOffset, inputLength, needInit);
    }

    @Override
    public int HMAC_doFinal(long hmacId, byte[] key, int keyLength, byte[] hmac, boolean needInit) {
        return NativeOSSLImplementation.HMAC_doFinal(hmacId, key, keyLength, hmac, needInit);
    }

    @Override
    public int HMAC_size(long hmacId) {
        return NativeOSSLImplementation.HMAC_size(hmacId);
    }

    @Override
    public void HMAC_delete(long hmacId) {
        NativeOSSLImplementation.HMAC_delete(hmacId);
    }

    @Override
    public long ECKEY_generate(int numBits) {
        return NativeOSSLImplementation.ECKEY_generate(numBits);
    }

    @Override
    public long ECKEY_generate(String curveOid) {
        return NativeOSSLImplementation.ECKEY_generate(curveOid);
    }

    @Override
    public long XECKEY_generate(int option, long bufferPtr) {
        return NativeOSSLImplementation.XECKEY_generate(option, bufferPtr);
    }

    @Override
    public byte[] ECKEY_generateParameters(int numBits) {
        return NativeOSSLImplementation.ECKEY_generateParameters(numBits);
    }

    @Override
    public byte[] ECKEY_generateParameters(String curveOid) {
        return NativeOSSLImplementation.ECKEY_generateParameters(curveOid);
    }

    @Override
    public long ECKEY_generate(byte[] ecParameters) {
        return NativeOSSLImplementation.ECKEY_generate(ecParameters);
    }

    @Override
    public long ECKEY_createPrivateKey(byte[] privateKeyBytes) {
        return NativeOSSLImplementation.ECKEY_createPrivateKey(privateKeyBytes);
    }

    @Override
    public long XECKEY_createPrivateKey(byte[] privateKeyBytes, long bufferPtr) {
        return NativeOSSLImplementation.XECKEY_createPrivateKey(privateKeyBytes, bufferPtr);
    }

    @Override
    public long ECKEY_createPublicKey(byte[] publicKeyBytes, byte[] parameterBytes) {
        return NativeOSSLImplementation.ECKEY_createPublicKey(publicKeyBytes, parameterBytes);
    }

    @Override
    public long XECKEY_createPublicKey(byte[] publicKeyBytes) {
        return NativeOSSLImplementation.XECKEY_createPublicKey(publicKeyBytes);
    }

    @Override
    public byte[] ECKEY_getParameters(long ecKeyId) {
        return NativeOSSLImplementation.ECKEY_getParameters(ecKeyId);
    }

    @Override
    public byte[] ECKEY_getPrivateKeyBytes(long ecKeyId) {
        return NativeOSSLImplementation.ECKEY_getPrivateKeyBytes(ecKeyId);
    }

    @Override
    public byte[] XECKEY_getPrivateKeyBytes(long xecKeyId) {
        return NativeOSSLImplementation.XECKEY_getPrivateKeyBytes(xecKeyId);
    }

    @Override
    public byte[] ECKEY_getPublicKeyBytes(long ecKeyId) {
        return NativeOSSLImplementation.ECKEY_getPublicKeyBytes(ecKeyId);
    }

    @Override
    public byte[] XECKEY_getPublicKeyBytes(long xecKeyId) {
        return NativeOSSLImplementation.XECKEY_getPublicKeyBytes(xecKeyId);
    }

    @Override
    public long ECKEY_createPKey(long ecKeyId) {
        return NativeOSSLImplementation.ECKEY_createPKey(ecKeyId);
    }

    @Override
    public void ECKEY_delete(long ecKeyId) {
        NativeOSSLImplementation.ECKEY_delete(ecKeyId);
    }

    @Override
    public void XECKEY_delete(long xecKeyId) {
        NativeOSSLImplementation.XECKEY_delete(xecKeyId);
    }

    @Override
    public long XDHKeyAgreement_init(long privId) {
        return NativeOSSLImplementation.XDHKeyAgreement_init(privId);
    }

    @Override
    public void XDHKeyAgreement_setPeer(long genCtx, long pubId) {
        NativeOSSLImplementation.XDHKeyAgreement_setPeer(genCtx, pubId);
    }

    @Override
    public byte[] ECKEY_computeECDHSecret(long pubEcKeyId, long privEcKeyId) {
        return NativeOSSLImplementation.ECKEY_computeECDHSecret(pubEcKeyId, privEcKeyId);
    }

    @Override
    public byte[] XECKEY_computeECDHSecret(long genCtx, long pubEcKeyId, long privEcKeyId, int secrectBufferSize) {
        return NativeOSSLImplementation.XECKEY_computeECDHSecret(genCtx, pubEcKeyId, privEcKeyId, secrectBufferSize);
    }

    @Override
    public byte[] ECKEY_signDatawithECDSA(byte[] digestBytes, int digestBytesLen, long ecPrivateKeyId) {
        return NativeOSSLImplementation.ECKEY_signDatawithECDSA(digestBytes, digestBytesLen, ecPrivateKeyId);
    }

    @Override
    public boolean ECKEY_verifyDatawithECDSA(byte[] digestBytes, int digestBytesLen, byte[] sigBytes, int sigBytesLen,
            long ecPublicKeyId) {
        return NativeOSSLImplementation.ECKEY_verifyDatawithECDSA(digestBytes, digestBytesLen,
            sigBytes, sigBytesLen, ecPublicKeyId);
    }

    @Override
    public long HKDF_create(String digestAlgo) {
        return NativeOSSLImplementation.HKDF_create(digestAlgo);
    }

    @Override
    public byte[] HKDF_extract(long hkdfId, byte[] saltBytes, long saltLen, byte[] inKey, long inKeyLen) {
        return NativeOSSLImplementation.HKDF_extract(hkdfId, saltBytes, saltLen, inKey, inKeyLen);
    }

    @Override
    public byte[] HKDF_expand(long hkdfId, byte[] prkBytes, long prkBytesLen, byte[] info, long infoLen, long okmLen) {
        return NativeOSSLImplementation.HKDF_expand(hkdfId, prkBytes, prkBytesLen, info, infoLen, okmLen);
    }

    @Override
    public byte[] HKDF_derive(long hkdfId, byte[] saltBytes, long saltLen, byte[] inKey, long inKeyLen, byte[] info,
            long infoLen, long okmLen) {
        return NativeOSSLImplementation.HKDF_derive(hkdfId,
            saltBytes, saltLen, inKey, inKeyLen, info, infoLen, okmLen);
    }

    @Override
    public void HKDF_delete(long hkdfId) {
        NativeOSSLImplementation.HKDF_delete(hkdfId);
    }

    @Override
    public int HKDF_size(long hkdfId) {
        return NativeOSSLImplementation.HKDF_size(hkdfId);
    }

    @Override
    public byte[] PBKDF2_derive(String hashAlgorithm, byte[] password, byte[] salt, int iterations, int keyLength) {
        return NativeOSSLImplementation.PBKDF2_derive(hashAlgorithm, password, salt, iterations, keyLength);
    }
}
