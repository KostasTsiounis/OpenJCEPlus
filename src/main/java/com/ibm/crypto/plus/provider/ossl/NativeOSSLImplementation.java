/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ossl;

import java.io.File;
import java.nio.ByteBuffer;
import java.security.ProviderException;
import sun.security.util.Debug;

final class NativeOSSLImplementation {

    // User enabled debugging
    private static Debug debug = Debug.getInstance("jceplus");

    // Whether OSSL is dynamically loaded. If OSSL is dynamically loaded,
    // we want to pre-load OSSL to help ensure we are getting the expected
    // version.
    //
    private static final boolean osslDynamicallyLoaded = true;

    // If OSSL is dynamically loaded, whether to require that OSSL be
    // pre-loaded.
    //
    static boolean requirePreloadOSSL = true;

    // Default ock core library name
    //
    private static final String OSSL_CORE_LIBRARY_NAME = "crypto";
    private static final String JGSKIT_CORE_LIBRARY_NAME = "ossl";
    private static String osName = null;
    private static String osArch = null;
    private static String JVMFIPSmode = null;

    static {
        if (osslDynamicallyLoaded) {
            // Preload OSSL library. We want to pre-load OSSL to help
            // ensure we are picking up the expected version within
            // the JRE.
            //
            preloadOSSL();
        }
        // Load native code for java-gskit
        //
        preloadJGskit();
    }

    public static String getOsName() {
        return osName;
    }

    public static String getOsArch() {
        return osArch;

    }

    static String getOSSLLoadPath() {
        String ockOverridePath = System.getProperty("ossl.library.path");
        if (ockOverridePath != null) {
            if (debug != null) {
                debug.println("Loading ock library using value in property ock.library.path: "
                    + ockOverridePath);
            }
            return ockOverridePath;
        }
        if (debug != null) {
            debug.println("Library path not found for ock, use java home directory.");
        }

        String javaHome = System.getProperty("java.home");
        osName = System.getProperty("os.name");
        String ockPath;

        if (osName.startsWith("Windows")) {
            ockPath = javaHome + File.separator + "bin";
        } else {
            ockPath = javaHome + File.separator + "lib";
        }

        if (debug != null) {
            debug.println("Loading ock library using value: " + ockPath);
        }
        return ockPath;
    }

    static String getJGskitLoadPath() {
        String jgskitOverridePath = System.getProperty("ossllib.library.path");
        if (jgskitOverridePath != null) {
            if (debug != null) {
                debug.println("Loading jgskit library using value in property jgskit.library.path: " + jgskitOverridePath);
            }
            return jgskitOverridePath;
        }
        if (debug != null) {
            debug.println("Libpath not found for jgskit, use java home directory.");
        }

        String javaHome = System.getProperty("java.home");
        osName = System.getProperty("os.name");
        String jgskitPath;

        if (osName.startsWith("Windows")) {
            jgskitPath = javaHome + File.separator + "bin";
        } else {
            jgskitPath = javaHome + File.separator + "lib";
        }

        if (debug != null) {
            debug.println("Loading jgskit library using value: " + jgskitPath);
        }
        return jgskitPath;
    }

    static void preloadJGskit() {
        osName = System.getProperty("os.name");
        osArch = System.getProperty("os.arch");
        String jgskitPath = getJGskitLoadPath();
        File loadFile = null;
        if (osName.startsWith("Windows") && osArch.equals("amd64")) {
            loadFile = new File(jgskitPath, "lib" + JGSKIT_CORE_LIBRARY_NAME + "_64.dll");
        } else if (osName.equals("Mac OS X")) {
            loadFile = new File(jgskitPath, "lib" + JGSKIT_CORE_LIBRARY_NAME + ".dylib");
        } else {
            loadFile = new File(jgskitPath, "lib" + JGSKIT_CORE_LIBRARY_NAME + ".so");
        }

        boolean jgskitLibraryPreloaded = loadIfExists(loadFile);
        if (jgskitLibraryPreloaded == false) {
            throw new ProviderException("Could not load dependent " + JGSKIT_CORE_LIBRARY_NAME + " library for os.name=" + osName
                        + ", os.arch=" + osArch);
        }
    }

    static void preloadOSSL() {
        osName = System.getProperty("os.name");
        osArch = System.getProperty("os.arch");
        String ockPath = getOSSLLoadPath();
        File loadFile = null;

        // --------------------------------------------------------------
        // Determine the OSSL library to load for a given OS and architecture.
        //
        // AIX: lib<OSSL_CORE_LIBRARY_NAME>_64.so
        // Linux aarch64: lib<OSSL_CORE_LIBRARY_NAME>.dylib
        // Linux ppc64le: lib<OSSL_CORE_LIBRARY_NAME>_64.so
        // Linux s390x: lib<OSSL_CORE_LIBRARY_NAME>_64.so
        // Linux x86_64: lib<OSSL_CORE_LIBRARY_NAME>_64.so
        // Mac OS X: lib<OSSL_CORE_LIBRARY_NAME>_64.so
        // Windows* amd64: <OSSL_CORE_LIBRARY_NAME>_64.dll
        // --------------------------------------------------------------
        if (osName.equals("Mac OS X")) {
            loadFile = new File(ockPath, "lib" + OSSL_CORE_LIBRARY_NAME + ".dylib");
        } else if (osName.startsWith("Windows") && osArch.equals("amd64")) {
            loadFile = new File(ockPath, OSSL_CORE_LIBRARY_NAME + "_64.dll");
        } else {
            loadFile = new File(ockPath, "lib" + OSSL_CORE_LIBRARY_NAME + "_64.so");
        }

        boolean ockLibraryPreloaded = loadIfExists(loadFile);
        if ((ockLibraryPreloaded == false) && requirePreloadOSSL) {
            throw new ProviderException("Could not load dependent ossl library for os.name=" + osName
                        + ", os.arch=" + osArch);
        }
    }

    private static boolean loadIfExists(File libraryFile) {
        String libraryName = libraryFile.getAbsolutePath();

        if (libraryFile.exists()) {
            // Need a try/catch block in case the library has already been
            // loaded by another ClassLoader
            //
            try {
                System.load(libraryName);
                if (debug != null) {
                    debug.println("Loaded : " + libraryName);
                }
                return true;
            } catch (Throwable t) {
                if (debug != null) {
                    debug.println("Failed to load : " + libraryName);
                }
            }
        } else {
            if (debug != null) {
                debug.println("Skipping load of " + libraryName);
            }
        }
        return false;
    }

    // =========================================================================
    // General functions
    // =========================================================================

    static public native String getLibraryBuildDate();

    // =========================================================================
    // Static stub functions
    // =========================================================================

    static public native long initializeOSSL(boolean isFIPS);

    static public native String CTX_getValue(int valueId);

    static native long getByteBufferPointer(ByteBuffer b);

    // =========================================================================
    // Basic random number generator functions
    // =========================================================================

    static public native void RAND_nextBytes(byte[] buffer);

    static public native void RAND_setSeed(byte[] seed);

    static public native void RAND_generateSeed(byte[] seed);

    // =========================================================================
    // Extended random number generator functions
    // =========================================================================

    static public native long EXTRAND_create(String algName);

    static public native void EXTRAND_nextBytes(long ockPRNGContextId,
            byte[] buffer);

    static public native void EXTRAND_setSeed(long ockPRNGContextId, byte[] seed)
           ;

    static public native void EXTRAND_delete(long ockPRNGContextId)
           ;

    // =========================================================================
    // Cipher functions
    // =========================================================================

    static public native long CIPHER_create(String cipher);

    static public native void CIPHER_init(long ockCipherId, int isEncrypt,
            int paddingId, byte[] key, byte[] iv);

    static public native void CIPHER_clean(long ockCipherId);

    static public native void CIPHER_setPadding(long ockCipherId, int paddingId)
           ;

    static public native int CIPHER_getBlockSize(long ockCipherId);

    static public native int CIPHER_getKeyLength(long ockCipherId);

    static public native int CIPHER_getIVLength(long ockCipherId);

    static public native int CIPHER_getOID(long ockCipherId);

    static public native int CIPHER_encryptUpdate(long ockCipherId,
            byte[] plaintext, int plaintextOffset, int plaintextLen, byte[] ciphertext,
            int ciphertextOffset, boolean needsReinit);

    static public native int CIPHER_decryptUpdate(long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, boolean needsReinit);

    static public native int CIPHER_encryptFinal(long ockCipherId, byte[] input,
            int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset, boolean needsReinit)
           ;

    static public native int CIPHER_decryptFinal(long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, boolean needsReinit);

    static public native long checkHardwareSupport();

    static public native void CIPHER_delete(long ockCipherId)
           ;

    static public native int z_kmc_native(byte[] input, int inputOffset, byte[] output,
            int outputOffset, long paramPointer, int inputLength, int mode);

    // =========================================================================
    // Poly1305 Cipher functions
    // =========================================================================

    static public native long POLY1305CIPHER_create(String cipher)
           ;

    static public native void POLY1305CIPHER_init(long ockCipherId,
            int isEncrypt, byte[] key, byte[] iv);

    static public native void POLY1305CIPHER_clean(long ockCipherId)
           ;

    static public native void POLY1305CIPHER_setPadding(long ockCipherId,
            int paddingId);

    static public native int POLY1305CIPHER_getBlockSize(long ockCipherId);

    static public native int POLY1305CIPHER_getKeyLength(long ockCipherId);

    static public native int POLY1305CIPHER_getIVLength(long ockCipherId);

    static public native int POLY1305CIPHER_getOID(long ockCipherId);

    static public native int POLY1305CIPHER_encryptUpdate(long ockCipherId,
            byte[] plaintext, int plaintextOffset, int plaintextLen, byte[] ciphertext,
            int ciphertextOffset);

    static public native int POLY1305CIPHER_decryptUpdate(long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset);

    static public native int POLY1305CIPHER_encryptFinal(long ockCipherId,
            byte[] input, int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset,
            byte[] tag);

    static public native int POLY1305CIPHER_decryptFinal(long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, byte[] tag);

    static public native void POLY1305CIPHER_delete(long ockCipherId)
           ;

    // =========================================================================
    // GCM Cipher functions
    // =========================================================================

    static public native long do_GCM_checkHardwareGCMSupport();

    static public native int do_GCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
           ;

    static public native int do_GCM_encryptFastJNI(long gcmCtx, int keyLen,
            int ivLen, int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, long inputBuffer, long outputBuffer);

    static public native int do_GCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
           ;

    static public native int do_GCM_decryptFastJNI(long gcmCtx, int keyLen,
            int ivLen, int ciphertextOffset, int ciphertextLen, int plainOffset, int aadLen,
            int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer)
           ;

    static public native int do_GCM_encrypt(long gcmCtx, byte[] key, int keyLen,
            byte[] iv, int ivLen, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen)
           ;

    static public native int do_GCM_decrypt(long gcmCtx, byte[] key, int keyLen,
            byte[] iv, int ivLen, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, byte[] aad, int aadLen, int tagLen)
           ;

    static public native int do_GCM_FinalForUpdateEncrypt(long gcmCtx,
            byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input, int inOffset, int inLen,
            byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen)
           ;

    static public native int do_GCM_FinalForUpdateDecrypt(long gcmCtx,
            /* byte[] key, int keyLen,
             byte[] iv, int ivLen,*/
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, int plaintextlen, byte[] aad, int aadLen, int tagLen)
           ;

    static public native int do_GCM_UpdForUpdateEncrypt(long gcmCtx,
            byte[] input, int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset)
           ;

    static public native int do_GCM_UpdForUpdateDecrypt(long gcmCtx,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset);

    static public native int do_GCM_InitForUpdateEncrypt(long gcmCtx, byte[] key,
            int keyLen, byte[] iv, int ivLen, byte[] aad, int aadLen);

    static public native int do_GCM_InitForUpdateDecrypt(long gcmCtx, byte[] key,
            int keyLen, byte[] iv, int ivLen, byte[] aad, int aadLen);


    static public native void do_GCM_delete();

    static public native void free_GCM_ctx(long gcmContextId)
           ;

    //static public native int get_GCM_TLSEnabled();

    static public native long create_GCM_context();

    // =========================================================================
    // CCM Cipher functions
    // =========================================================================

    static public native long do_CCM_checkHardwareCCMSupport();

    static public native int do_CCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
           ;

    static public native int do_CCM_encryptFastJNI(int keyLen, int ivLen,
            int inLen, int ciphertextLen, int aadLen, int tagLen, long parameterBuffer,
            long inputBuffer, long outputBuffer);

    static public native int do_CCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
           ;

    static public native int do_CCM_decryptFastJNI(int keyLen, int ivLen,
            int ciphertextLen, int plaintextLen, int aadLen, int tagLen, long parameterBuffer,
            long inputBuffer, long outputBuffer);

    static public native int do_CCM_encrypt(byte[] iv, int ivLen, byte[] key,
            int keyLen, byte[] aad, int aadLen, byte[] input, int inLen, byte[] ciphertext,
            int ciphertextLen, int tagLen);

    static public native int do_CCM_decrypt(byte[] iv, int ivLen, byte[] key,
            int keyLen, byte[] aad, int aadLen, byte[] ciphertext, int ciphertextLength,
            byte[] plaintext, int plaintextLength, int tagLen);

    static public native void do_CCM_delete();

    // =========================================================================
    // RSA cipher functions
    // =========================================================================

    static public native int RSACIPHER_public_encrypt(long rsaKeyId,
            int rsaPaddingId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset);

    static public native int RSACIPHER_private_encrypt(long rsaKeyId,
            int rsaPaddingId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset, boolean convertKey);

    static public native int RSACIPHER_public_decrypt(long rsaKeyId,
            int rsaPaddingId, byte[] ciphertext, int ciphertextOffset, int ciphertextLen,
            byte[] plaintext, int plaintextOffset);

    static public native int RSACIPHER_private_decrypt(long rsaKeyId,
            int rsaPaddingId, byte[] ciphertext, int ciphertextOffset, int ciphertextLen,
            byte[] plaintext, int plaintextOffset, boolean convertKey);

    // =========================================================================
    // DH key functions
    // =========================================================================

    static public native long DHKEY_generate(int numBits);

    static public native byte[] DHKEY_generateParameters(int numBits);

    static public native long DHKEY_generate(byte[] dhParameters)
           ;

    static public native long DHKEY_createPrivateKey(byte[] privateKeyBytes)
           ;

    static public native long DHKEY_createPublicKey(byte[] publicKeyBytes)
           ;

    static public native byte[] DHKEY_getParameters(long dhKeyId);

    static public native byte[] DHKEY_getPrivateKeyBytes(long dhKeyId)
           ;

    static public native byte[] DHKEY_getPublicKeyBytes(long dhKeyId)
           ;

    static public native long DHKEY_createPKey(long dhKeyId);

    static public native byte[] DHKEY_computeDHSecret(long pubKeyId,
            long privKeyId);

    static public native void DHKEY_delete(long dhKeyId);

    // =========================================================================
    // RSA key functions
    // =========================================================================

    static public native long RSAKEY_generate(int numBits, long e)
           ;

    static public native long RSAKEY_createPrivateKey(byte[] privateKeyBytes)
           ;

    static public native long RSAKEY_createPublicKey(byte[] publicKeyBytes)
           ;

    static public native byte[] RSAKEY_getPrivateKeyBytes(long rsaKeyId)
           ;

    static public native byte[] RSAKEY_getPublicKeyBytes(long rsaKeyId)
           ;

    static public native long RSAKEY_createPKey(long rsaKeyId)
           ;

    static public native int RSAKEY_size(long rsaKeyId);

    static public native void RSAKEY_delete(long rsaKeyId);

    // =========================================================================
    // DSA key functions
    // =========================================================================

    static public native long DSAKEY_generate(int numBits);

    static public native byte[] DSAKEY_generateParameters(int numBits);

    static public native long DSAKEY_generate(byte[] dsaParameters)
           ;

    static public native long DSAKEY_createPrivateKey(byte[] privateKeyBytes)
           ;

    static public native long DSAKEY_createPublicKey(byte[] publicKeyBytes)
           ;

    static public native byte[] DSAKEY_getParameters(long dsaKeyId);

    static public native byte[] DSAKEY_getPrivateKeyBytes(long dsaKeyId)
           ;

    static public native byte[] DSAKEY_getPublicKeyBytes(long dsaKeyId)
           ;

    static public native long DSAKEY_createPKey(long dsaKeyId)
           ;

    static public native void DSAKEY_delete(long dsaKeyId);

    // =========================================================================
    // PKey functions
    // =========================================================================

    static public native void PKEY_delete(long pkeyId);

    // =========================================================================
    // Digest functions
    // =========================================================================

    static public native long DIGEST_create(String digestAlgo)
           ;

    static public native long DIGEST_copy(long digestId)
           ;

    static public native int DIGEST_update(long digestId, byte[] input,
            int offset, int length);

    static public native void DIGEST_updateFastJNI(long digestId,
            long inputBuffer, int length);

    static public native byte[] DIGEST_digest(long digestId);

    static public native void DIGEST_digest_and_reset(long digestId,
            long outputBuffer, int length);

    static public native int DIGEST_digest_and_reset(long digestId,
            byte[] output);

    static public native int DIGEST_size(long digestId);

    static public native void DIGEST_reset(long digestId);

    static public native void DIGEST_delete(long digestId);

    // =========================================================================
    // Signature functions (with digest)
    // =========================================================================

    static public native byte[] SIGNATURE_sign(long digestId, long pkeyId,
            boolean convert);

    static public native boolean SIGNATURE_verify(long digestId, long pkeyId,
            byte[] sigBytes);

    static public native byte[] SIGNATUREEdDSA_signOneShot(long pkeyId,
            byte[] bytes);

    static public native boolean SIGNATUREEdDSA_verifyOneShot(long pkeyId,
            byte[] sigBytes, byte[] oneShot);

    // =========================================================================
    // RSAPSSSignature functions
    // =========================================================================

    static public native int RSAPSS_signInit(long rsaPssId, long pkeyId,
            int saltlen, boolean convert);

    static public native int RSAPSS_verifyInit(long rsaPssId, long pkeyId,
            int saltlen);

    static public native int RSAPSS_getSigLen(long rsaPssId);

    static public native void RSAPSS_signFinal(long rsaPssId, byte[] signature,
            int length);

    static public native boolean RSAPSS_verifyFinal(long rsaPssId,
            byte[] sigBytes, int length);

    static public native long RSAPSS_createContext(String digestAlgo,
            String mgf1SpecAlgo);

    static public native void RSAPSS_releaseContext(long rsaPssId)
           ;

    static public native void RSAPSS_digestUpdate(long rsaPssId, byte[] input,
            int offset, int length);

    static public native void RSAPSS_reset(long digestId);

    static public native void RSAPSS_resetDigest(long rsaPssId)
           ;

    // =========================================================================
    // DSA Signature functions (pre-hashed data)
    // =========================================================================

    static public native byte[] DSANONE_SIGNATURE_sign(byte[] digest,
            long dsaKeyId);

    static public native boolean DSANONE_SIGNATURE_verify(byte[] digest,
            long dsaKeyId, byte[] sigBytes);

    // =========================================================================
    // RSASSL Signature functions (pre-hashed data)
    // =========================================================================

    static public native byte[] RSASSL_SIGNATURE_sign(byte[] digest,
            long rsaKeyId);

    static public native boolean RSASSL_SIGNATURE_verify(byte[] digest,
            long rsaKeyId, byte[] sigBytes, boolean convert);

    // =========================================================================
    // HMAC functions
    // =========================================================================

    static public native long HMAC_create(String digestAlgo);

    static public native int HMAC_update(long hmacId, byte[] key, int keyLength,
            byte[] input, int inputOffset, int inputLength, boolean needInit);

    static public native int HMAC_doFinal(long hmacId, byte[] key, int keyLength,
            byte[] hmac, boolean needInit);

    static public native int HMAC_size(long hmacId);

    static public native void HMAC_delete(long hmacId);

    // =========================================================================
    // EC key functions
    // =========================================================================

    static public native long ECKEY_generate(int numBits);

    static public native long ECKEY_generate(String curveOid)
           ;

    static public native long XECKEY_generate(int option, long bufferPtr)
           ;

    static public native byte[] ECKEY_generateParameters(int numBits)
           ;

    static public native byte[] ECKEY_generateParameters(String curveOid)
           ;

    static public native long ECKEY_generate(byte[] ecParameters)
           ;

    static public native long ECKEY_createPrivateKey(byte[] privateKeyBytes)
           ;

    static public native long XECKEY_createPrivateKey(byte[] privateKeyBytes,
            long bufferPtr);

    static public native long ECKEY_createPublicKey(byte[] publicKeyBytes,
            byte[] parameterBytes);

    static public native long XECKEY_createPublicKey(byte[] publicKeyBytes)
           ;

    static public native byte[] ECKEY_getParameters(long ecKeyId);

    static public native byte[] ECKEY_getPrivateKeyBytes(long ecKeyId)
           ;

    static public native byte[] XECKEY_getPrivateKeyBytes(long xecKeyId)
           ;

    static public native byte[] ECKEY_getPublicKeyBytes(long ecKeyId)
           ;

    static public native byte[] XECKEY_getPublicKeyBytes(long xecKeyId)
           ;

    static public native long ECKEY_createPKey(long ecKeyId);

    static public native void ECKEY_delete(long ecKeyId);

    static public native void XECKEY_delete(long xecKeyId);

    static public native long XDHKeyAgreement_init(long privId);

    static public native void XDHKeyAgreement_setPeer(long genCtx, long pubId);

    static public native byte[] ECKEY_computeECDHSecret(long pubEcKeyId,
            long privEcKeyId);

    static public native byte[] XECKEY_computeECDHSecret(long genCtx,
            long pubEcKeyId, long privEcKeyId, int secrectBufferSize);


    static public native byte[] ECKEY_signDatawithECDSA(byte[] digestBytes,
            int digestBytesLen, long ecPrivateKeyId);

    static public native boolean ECKEY_verifyDatawithECDSA(byte[] digestBytes,
            int digestBytesLen, byte[] sigBytes, int sigBytesLen, long ecPublicKeyId)
           ;


    // =========================================================================
    // HKDF functions
    // =========================================================================

    static public native long HKDF_create(String digestAlgo);

    static public native byte[] HKDF_extract(long hkdfId, byte[] saltBytes,
            long saltLen, byte[] inKey, long inKeyLen);

    static public native byte[] HKDF_expand(long hkdfId, byte[] prkBytes,
            long prkBytesLen, byte[] info, long infoLen, long okmLen);

    static public native byte[] HKDF_derive(long hkdfId, byte[] saltBytes,
            long saltLen, byte[] inKey, long inKeyLen, byte[] info, long infoLen, long okmLen)
           ;

    static public native void HKDF_delete(long hkdfId);

    static public native int HKDF_size(long hkdfId);

    // =========================================================================
    // Password based key derivation functions ( PBKDF )
    // =========================================================================

    static public native byte[] PBKDF2_derive(String hashAlgorithm, byte[] password, byte[] salt,
            int iterations, int keyLength);
}
