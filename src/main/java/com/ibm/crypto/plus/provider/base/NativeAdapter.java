/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import java.nio.ByteBuffer;
import java.security.ProviderException;
import sun.security.util.Debug;

public abstract class NativeAdapter {
    // User enabled debugging
    private static Debug debug = Debug.getInstance("jceplus");

    static public ProviderException providerException(String message, Throwable osslException) {
        ProviderException providerException = new ProviderException(message, osslException);
        setExceptionCause(providerException, osslException);
        return providerException;
    }
        
    static public void setExceptionCause(Exception exception, Throwable osslException) {
        if (debug != null) {
            exception.initCause(osslException);
        }
    }
    abstract public String getLibraryVersion() throws NativeException;

    abstract public String getLibraryInstallPath() throws NativeException;

    abstract public void validateLibraryLocation() throws ProviderException, NativeException;

    abstract public void validateLibraryVersion() throws ProviderException, NativeException;

    // =========================================================================
    // General functions
    // =========================================================================

    abstract public String getLibraryBuildDate();

    // =========================================================================
    // Static stub functions
    // =========================================================================

    abstract public long initializeOCK(boolean isFIPS) throws NativeException;

    abstract public String CTX_getValue(int valueId) throws NativeException;

    abstract public long getByteBufferPointer(ByteBuffer b);

    // =========================================================================
    // Basic random number generator functions
    // =========================================================================

    abstract public void RAND_nextBytes(byte[] buffer) throws NativeException;

    abstract public void RAND_setSeed(byte[] seed) throws NativeException;

    abstract public void RAND_generateSeed(byte[] seed) throws NativeException;

    // =========================================================================
    // Extended random number generator functions
    // =========================================================================

    abstract public long EXTRAND_create(String algName) throws NativeException;

    abstract public void EXTRAND_nextBytes(long ockPRNGContextId,
            byte[] buffer) throws NativeException;

    abstract public void EXTRAND_setSeed(long ockPRNGContextId, byte[] seed)
            throws NativeException;

    abstract public void EXTRAND_delete(long ockPRNGContextId)
            throws NativeException;

    // =========================================================================
    // Cipher functions
    // =========================================================================

    abstract public long CIPHER_create(String cipher) throws NativeException;

    abstract public void CIPHER_init(long ockCipherId, int isEncrypt,
            int paddingId, byte[] key, byte[] iv) throws NativeException;

    abstract public void CIPHER_clean(long ockCipherId) throws NativeException;

    abstract public void CIPHER_setPadding(long ockCipherId, int paddingId)
            throws NativeException;

    abstract public int CIPHER_getBlockSize(long ockCipherId);

    abstract public int CIPHER_getKeyLength(long ockCipherId);

    abstract public int CIPHER_getIVLength(long ockCipherId);

    abstract public int CIPHER_getOID(long ockCipherId);

    abstract public int CIPHER_encryptUpdate(long ockCipherId,
            byte[] plaintext, int plaintextOffset, int plaintextLen, byte[] ciphertext,
            int ciphertextOffset, boolean needsReinit) throws NativeException;

    abstract public int CIPHER_decryptUpdate(long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, boolean needsReinit) throws NativeException;

    abstract public int CIPHER_encryptFinal(long ockCipherId, byte[] input,
            int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset, boolean needsReinit)
            throws NativeException;

    abstract public int CIPHER_decryptFinal(long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, boolean needsReinit) throws NativeException;

    abstract public long checkHardwareSupport();

    abstract public void CIPHER_delete(long ockCipherId)
            throws NativeException;

    abstract public int z_kmc_native(byte[] input, int inputOffset, byte[] output,
            int outputOffset, long paramPointer, int inputLength, int mode);

    // =========================================================================
    // Poly1305 Cipher functions
    // =========================================================================

    abstract public long POLY1305CIPHER_create(String cipher)
            throws NativeException;

    abstract public void POLY1305CIPHER_init(long ockCipherId,
            int isEncrypt, byte[] key, byte[] iv) throws NativeException;

    abstract public void POLY1305CIPHER_clean(long ockCipherId)
            throws NativeException;

    abstract public void POLY1305CIPHER_setPadding(long ockCipherId,
            int paddingId) throws NativeException;

    abstract public int POLY1305CIPHER_getBlockSize(long ockCipherId);

    abstract public int POLY1305CIPHER_getKeyLength(long ockCipherId);

    abstract public int POLY1305CIPHER_getIVLength(long ockCipherId);

    abstract public int POLY1305CIPHER_getOID(long ockCipherId);

    abstract public int POLY1305CIPHER_encryptUpdate(long ockCipherId,
            byte[] plaintext, int plaintextOffset, int plaintextLen, byte[] ciphertext,
            int ciphertextOffset) throws NativeException;

    abstract public int POLY1305CIPHER_decryptUpdate(long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset) throws NativeException;

    abstract public int POLY1305CIPHER_encryptFinal(long ockCipherId,
            byte[] input, int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset,
            byte[] tag) throws NativeException;

    abstract public int POLY1305CIPHER_decryptFinal(long ockCipherId,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, byte[] tag) throws NativeException;

    abstract public void POLY1305CIPHER_delete(long ockCipherId)
            throws NativeException;

    // =========================================================================
    // GCM Cipher functions
    // =========================================================================

    abstract public long do_GCM_checkHardwareGCMSupport();

    abstract public int do_GCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws NativeException;

    abstract public int do_GCM_encryptFastJNI(long gcmCtx, int keyLen,
            int ivLen, int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, long inputBuffer, long outputBuffer) throws NativeException;

    abstract public int do_GCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws NativeException;

    abstract public int do_GCM_decryptFastJNI(long gcmCtx, int keyLen,
            int ivLen, int ciphertextOffset, int ciphertextLen, int plainOffset, int aadLen,
            int tagLen, long parameterBuffer, long inputBuffer, long outputBuffer)
            throws NativeException;

    abstract public int do_GCM_encrypt(long gcmCtx, byte[] key, int keyLen,
            byte[] iv, int ivLen, byte[] input, int inOffset, int inLen, byte[] ciphertext,
            int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen)
            throws NativeException;

    abstract public int do_GCM_decrypt(long gcmCtx, byte[] key, int keyLen,
            byte[] iv, int ivLen, byte[] ciphertext, int cipherOffset, int cipherLen,
            byte[] plaintext, int plaintextOffset, byte[] aad, int aadLen, int tagLen)
            throws NativeException;

    abstract public int do_GCM_FinalForUpdateEncrypt(long gcmCtx,
            byte[] key, int keyLen, byte[] iv, int ivLen, byte[] input, int inOffset, int inLen,
            byte[] ciphertext, int ciphertextOffset, byte[] aad, int aadLen, byte[] tag, int tagLen)
            throws NativeException;

    abstract public int do_GCM_FinalForUpdateDecrypt(long gcmCtx,
            /* byte[] key, int keyLen,
             byte[] iv, int ivLen,*/
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset, int plaintextlen, byte[] aad, int aadLen, int tagLen)
            throws NativeException;

    abstract public int do_GCM_UpdForUpdateEncrypt(long gcmCtx,
            byte[] input, int inOffset, int inLen, byte[] ciphertext, int ciphertextOffset)
            throws NativeException;

    abstract public int do_GCM_UpdForUpdateDecrypt(long gcmCtx,
            byte[] ciphertext, int cipherOffset, int cipherLen, byte[] plaintext,
            int plaintextOffset) throws NativeException;

    abstract public int do_GCM_InitForUpdateEncrypt(long gcmCtx, byte[] key,
            int keyLen, byte[] iv, int ivLen, byte[] aad, int aadLen) throws NativeException;

    abstract public int do_GCM_InitForUpdateDecrypt(long gcmCtx, byte[] key,
            int keyLen, byte[] iv, int ivLen, byte[] aad, int aadLen) throws NativeException;


    abstract public void do_GCM_delete() throws NativeException;

    abstract public void free_GCM_ctx(long gcmContextId)
            throws NativeException;

    //abstract public int get_GCM_TLSEnabled() throws NativeException;

    abstract public long create_GCM_context() throws NativeException;

    // =========================================================================
    // CCM Cipher functions
    // =========================================================================

    abstract public long do_CCM_checkHardwareCCMSupport();

    abstract public int do_CCM_encryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws NativeException;

    abstract public int do_CCM_encryptFastJNI(int keyLen, int ivLen,
            int inLen, int ciphertextLen, int aadLen, int tagLen, long parameterBuffer,
            long inputBuffer, long outputBuffer) throws NativeException;

    abstract public int do_CCM_decryptFastJNI_WithHardwareSupport(int keyLen, int ivLen,
            int inOffset, int inLen, int ciphertextOffset, int aadLen, int tagLen,
            long parameterBuffer, byte[] input, int inputOffset, byte[] output, int outputOffset)
            throws NativeException;

    abstract public int do_CCM_decryptFastJNI(int keyLen, int ivLen,
            int ciphertextLen, int plaintextLen, int aadLen, int tagLen, long parameterBuffer,
            long inputBuffer, long outputBuffer) throws NativeException;

    abstract public int do_CCM_encrypt(byte[] iv, int ivLen, byte[] key,
            int keyLen, byte[] aad, int aadLen, byte[] input, int inLen, byte[] ciphertext,
            int ciphertextLen, int tagLen) throws NativeException;

    abstract public int do_CCM_decrypt(byte[] iv, int ivLen, byte[] key,
            int keyLen, byte[] aad, int aadLen, byte[] ciphertext, int ciphertextLength,
            byte[] plaintext, int plaintextLength, int tagLen) throws NativeException;

    abstract public void do_CCM_delete() throws NativeException;

    // =========================================================================
    // RSA cipher functions
    // =========================================================================

    abstract public int RSACIPHER_public_encrypt(long rsaKeyId,
            int rsaPaddingId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset) throws NativeException;

    abstract public int RSACIPHER_private_encrypt(long rsaKeyId,
            int rsaPaddingId, byte[] plaintext, int plaintextOffset, int plaintextLen,
            byte[] ciphertext, int ciphertextOffset, boolean convertKey) throws NativeException;

    abstract public int RSACIPHER_public_decrypt(long rsaKeyId,
            int rsaPaddingId, byte[] ciphertext, int ciphertextOffset, int ciphertextLen,
            byte[] plaintext, int plaintextOffset) throws NativeException;

    abstract public int RSACIPHER_private_decrypt(long rsaKeyId,
            int rsaPaddingId, byte[] ciphertext, int ciphertextOffset, int ciphertextLen,
            byte[] plaintext, int plaintextOffset, boolean convertKey) throws NativeException;

    // =========================================================================
    // DH key functions
    // =========================================================================

    abstract public long DHKEY_generate(int numBits) throws NativeException;

    abstract public byte[] DHKEY_generateParameters(int numBits);

    abstract public long DHKEY_generate(byte[] dhParameters)
            throws NativeException;

    abstract public long DHKEY_createPrivateKey(byte[] privateKeyBytes)
            throws NativeException;

    abstract public long DHKEY_createPublicKey(byte[] publicKeyBytes)
            throws NativeException;

    abstract public byte[] DHKEY_getParameters(long dhKeyId);

    abstract public byte[] DHKEY_getPrivateKeyBytes(long dhKeyId)
            throws NativeException;

    abstract public byte[] DHKEY_getPublicKeyBytes(long dhKeyId)
            throws NativeException;

    abstract public long DHKEY_createPKey(long dhKeyId) throws NativeException;

    abstract public byte[] DHKEY_computeDHSecret(long pubKeyId,
            long privKeyId) throws NativeException;

    abstract public void DHKEY_delete(long dhKeyId) throws NativeException;

    // =========================================================================
    // RSA key functions
    // =========================================================================

    abstract public long RSAKEY_generate(int numBits, long e)
            throws NativeException;

    abstract public long RSAKEY_createPrivateKey(byte[] privateKeyBytes)
            throws NativeException;

    abstract public long RSAKEY_createPublicKey(byte[] publicKeyBytes)
            throws NativeException;

    abstract public byte[] RSAKEY_getPrivateKeyBytes(long rsaKeyId)
            throws NativeException;

    abstract public byte[] RSAKEY_getPublicKeyBytes(long rsaKeyId)
            throws NativeException;

    abstract public long RSAKEY_createPKey(long rsaKeyId)
            throws NativeException;

    abstract public int RSAKEY_size(long rsaKeyId);

    abstract public void RSAKEY_delete(long rsaKeyId);

    // =========================================================================
    // DSA key functions
    // =========================================================================

    abstract public long DSAKEY_generate(int numBits) throws NativeException;

    abstract public byte[] DSAKEY_generateParameters(int numBits);

    abstract public long DSAKEY_generate(byte[] dsaParameters)
            throws NativeException;

    abstract public long DSAKEY_createPrivateKey(byte[] privateKeyBytes)
            throws NativeException;

    abstract public long DSAKEY_createPublicKey(byte[] publicKeyBytes)
            throws NativeException;

    abstract public byte[] DSAKEY_getParameters(long dsaKeyId);

    abstract public byte[] DSAKEY_getPrivateKeyBytes(long dsaKeyId)
            throws NativeException;

    abstract public byte[] DSAKEY_getPublicKeyBytes(long dsaKeyId)
            throws NativeException;

    abstract public long DSAKEY_createPKey(long dsaKeyId)
            throws NativeException;

    abstract public void DSAKEY_delete(long dsaKeyId) throws NativeException;

    // =========================================================================
    // PKey functions
    // =========================================================================

    abstract public void PKEY_delete(long pkeyId) throws NativeException;

    // =========================================================================
    // Digest functions
    // =========================================================================

    abstract public long DIGEST_create(String digestAlgo)
            throws NativeException;

    abstract public long DIGEST_copy(long digestId)
            throws NativeException;

    abstract public int DIGEST_update(long digestId, byte[] input,
            int offset, int length) throws NativeException;

    abstract public void DIGEST_updateFastJNI(long digestId,
            long inputBuffer, int length) throws NativeException;

    abstract public byte[] DIGEST_digest(long digestId) throws NativeException;

    abstract public void DIGEST_digest_and_reset(long digestId,
            long outputBuffer, int length) throws NativeException;

    abstract public int DIGEST_digest_and_reset(long digestId,
            byte[] output) throws NativeException;

    abstract public int DIGEST_size(long digestId) throws NativeException;

    abstract public void DIGEST_reset(long digestId) throws NativeException;

    abstract public void DIGEST_delete(long digestId) throws NativeException;

    // =========================================================================
    // Signature functions (with digest)
    // =========================================================================

    abstract public byte[] SIGNATURE_sign(long digestId, long pkeyId,
            boolean convert) throws NativeException;

    abstract public boolean SIGNATURE_verify(long digestId, long pkeyId,
            byte[] sigBytes) throws NativeException;

    abstract public byte[] SIGNATUREEdDSA_signOneShot(long pkeyId,
            byte[] bytes) throws NativeException;

    abstract public boolean SIGNATUREEdDSA_verifyOneShot(long pkeyId,
            byte[] sigBytes, byte[] oneShot) throws NativeException;

    // =========================================================================
    // RSAPSSSignature functions
    // =========================================================================

    abstract public int RSAPSS_signInit(long rsaPssId, long pkeyId,
            int saltlen, boolean convert) throws NativeException;

    abstract public int RSAPSS_verifyInit(long rsaPssId, long pkeyId,
            int saltlen) throws NativeException;

    abstract public int RSAPSS_getSigLen(long rsaPssId);

    abstract public void RSAPSS_signFinal(long rsaPssId, byte[] signature,
            int length) throws NativeException;

    abstract public boolean RSAPSS_verifyFinal(long rsaPssId,
            byte[] sigBytes, int length) throws NativeException;

    abstract public long RSAPSS_createContext(String digestAlgo,
            String mgf1SpecAlgo) throws NativeException;

    abstract public void RSAPSS_releaseContext(long rsaPssId)
            throws NativeException;

    abstract public void RSAPSS_digestUpdate(long rsaPssId, byte[] input,
            int offset, int length) throws NativeException;

    abstract public void RSAPSS_reset(long digestId) throws NativeException;

    abstract public void RSAPSS_resetDigest(long rsaPssId)
            throws NativeException;

    // =========================================================================
    // DSA Signature functions (pre-hashed data)
    // =========================================================================

    abstract public byte[] DSANONE_SIGNATURE_sign(byte[] digest,
            long dsaKeyId) throws NativeException;

    abstract public boolean DSANONE_SIGNATURE_verify(byte[] digest,
            long dsaKeyId, byte[] sigBytes) throws NativeException;

    // =========================================================================
    // RSASSL Signature functions (pre-hashed data)
    // =========================================================================

    abstract public byte[] RSASSL_SIGNATURE_sign(byte[] digest,
            long rsaKeyId) throws NativeException;

    abstract public boolean RSASSL_SIGNATURE_verify(byte[] digest,
            long rsaKeyId, byte[] sigBytes, boolean convert) throws NativeException;

    // =========================================================================
    // HMAC functions
    // =========================================================================

    abstract public long HMAC_create(String digestAlgo) throws NativeException;

    abstract public int HMAC_update(long hmacId, byte[] key, int keyLength,
            byte[] input, int inputOffset, int inputLength, boolean needInit) throws NativeException;

    abstract public int HMAC_doFinal(long hmacId, byte[] key, int keyLength,
            byte[] hmac, boolean needInit) throws NativeException;

    abstract public int HMAC_size(long hmacId) throws NativeException;

    abstract public void HMAC_delete(long hmacId) throws NativeException;

    // =========================================================================
    // EC key functions
    // =========================================================================

    abstract public long ECKEY_generate(int numBits) throws NativeException;

    abstract public long ECKEY_generate(String curveOid)
            throws NativeException;

    abstract public long XECKEY_generate(int option, long bufferPtr)
            throws NativeException;

    abstract public byte[] ECKEY_generateParameters(int numBits)
            throws NativeException;

    abstract public byte[] ECKEY_generateParameters(String curveOid)
            throws NativeException;

    abstract public long ECKEY_generate(byte[] ecParameters)
            throws NativeException;

    abstract public long ECKEY_createPrivateKey(byte[] privateKeyBytes)
            throws NativeException;

    abstract public long XECKEY_createPrivateKey(byte[] privateKeyBytes,
            long bufferPtr) throws NativeException;

    abstract public long ECKEY_createPublicKey(byte[]  publicKeyBytes,
            byte[] parameterBytes) throws NativeException;

    abstract public long XECKEY_createPublicKey(byte[] publicKeyBytes)
            throws NativeException;

    abstract public byte[] ECKEY_getParameters(long ecKeyId);

    abstract public byte[] ECKEY_getPrivateKeyBytes(long ecKeyId)
            throws NativeException;

    abstract public byte[] XECKEY_getPrivateKeyBytes(long xecKeyId)
            throws NativeException;

    abstract public byte[] ECKEY_getPublicKeyBytes(long ecKeyId)
            throws NativeException;

    abstract public byte[] XECKEY_getPublicKeyBytes(long xecKeyId)
            throws NativeException;

    abstract public long ECKEY_createPKey(long ecKeyId) throws NativeException;

    abstract public void ECKEY_delete(long ecKeyId) throws NativeException;

    abstract public void XECKEY_delete(long xecKeyId) throws NativeException;

    abstract public long XDHKeyAgreement_init(long privId);

    abstract public void XDHKeyAgreement_setPeer(long genCtx, long pubId);

    abstract public byte[] ECKEY_computeECDHSecret(long pubEcKeyId,
            long privEcKeyId) throws NativeException;

    abstract public byte[] XECKEY_computeECDHSecret(long genCtx,
            long pubEcKeyId, long privEcKeyId, int secrectBufferSize) throws NativeException;


    abstract public byte[] ECKEY_signDatawithECDSA(byte[] digestBytes,
            int digestBytesLen, long ecPrivateKeyId) throws NativeException;

    abstract public boolean ECKEY_verifyDatawithECDSA(byte[] digestBytes,
            int digestBytesLen, byte[] sigBytes, int sigBytesLen, long ecPublicKeyId)
            throws NativeException;


    // =========================================================================
    // HKDF functions
    // =========================================================================

    abstract public long HKDF_create(String digestAlgo) throws NativeException;

    abstract public byte[] HKDF_extract(long hkdfId, byte[] saltBytes,
            long saltLen, byte[] inKey, long inKeyLen) throws NativeException;

    abstract public byte[] HKDF_expand(long hkdfId, byte[] prkBytes,
            long prkBytesLen, byte[] info, long infoLen, long okmLen) throws NativeException;

    abstract public byte[] HKDF_derive(long hkdfId, byte[] saltBytes,
            long saltLen, byte[] inKey, long inKeyLen, byte[] info, long infoLen, long okmLen)
            throws NativeException;

    abstract public void HKDF_delete(long hkdfId) throws NativeException;

    abstract public int HKDF_size(long hkdfId) throws NativeException;

    // =========================================================================
    // Password based key derivation functions ( PBKDF )
    // =========================================================================

    abstract public byte[] PBKDF2_derive(String hashAlgorithm, byte[] password, byte[] salt,
            int iterations, int keyLength) throws NativeException;
}
