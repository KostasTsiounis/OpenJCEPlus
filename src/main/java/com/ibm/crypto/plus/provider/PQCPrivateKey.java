/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.PQCKey;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;

/*
 * A PQC private key for the NIST FIPS 203, 204, 205 Algorithm.
 */
@SuppressWarnings("restriction")
final class PQCPrivateKey extends PKCS8Key {

    private static final long serialVersionUID = -3168962080315231494L;

    private OpenJCEPlusProvider provider = null;
    private String familyName;      // algorithm family name returned by getAlgorithm()
    private String paramSetName; // specific parameter-set name (e.g. "ML-DSA-65")

    private transient PQCKey pqcKey;

    private transient boolean destroyed = false;

    /**
     * Create a PQC private key from the key data and the algorithm name.
     *
     * @param keyBytes  the private key bytes
     * @param algName   the name of the algorithm used
     */
    PQCPrivateKey(OpenJCEPlusProvider provider, byte[] keyBytes, String algName)
            throws InvalidKeyException {
        this.algid = new AlgorithmId(PQCAlgorithmId.getOID(algName));
        this.paramSetName = PQCKnownOIDs.findMatch(this.algid.getName()).stdName();
        this.familyName = familyName(this.paramSetName);
        this.provider = provider;
        try {
            this.privKeyMaterial = normaliseKeyMaterial(keyBytes, this.paramSetName);
            this.pqcKey = PQCKey.createPrivateKey(
                    this.paramSetName, this.privKeyMaterial, provider, "KeyFactory");
        } catch (Exception e) {
            throw new InvalidKeyException("Invalid key " + e.getMessage(), e);
        }
    }

    /**
     * Create a PQC private key from an existing PQCKey.
     *
     * @param pqcKey the PQCKey to be used to create the private key
     */
    PQCPrivateKey(OpenJCEPlusProvider provider, PQCKey pqcKey) throws InvalidKeyException {
        try {
            this.provider = provider;
            this.pqcKey = pqcKey;
            this.paramSetName = PQCKnownOIDs.findMatch(pqcKey.getAlgorithm()).stdName();
            this.familyName = familyName(this.paramSetName);
            this.algid = new AlgorithmId(PQCAlgorithmId.getOID(this.paramSetName));
            this.privKeyMaterial = normaliseKeyMaterial(pqcKey.getPrivateKeyBytes(), this.paramSetName);
        } catch (Exception exception) {
            throw provider.providerException("Failure in PQCPrivateKey" + exception.getMessage(), exception);
        }
    }

    /**
     * Create a private key from it's DER encoding (PKCS#8).
     *
     * @param encoded   the encoded PKCS#8 key
     */
    PQCPrivateKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        super(encoded);
        this.provider = provider;
        this.paramSetName = PQCKnownOIDs.findMatch(this.algid.getName()).stdName();
        this.familyName = familyName(this.paramSetName);
        try {
            this.privKeyMaterial = normaliseKeyMaterial(this.privKeyMaterial, this.paramSetName);
            this.pqcKey = PQCKey.createPrivateKey(
                    this.paramSetName, this.privKeyMaterial, provider, "KeyFactory");
        } catch (Exception e) {
            throw new InvalidKeyException("Invalid key " + e.getMessage(), e);
        }
    }

    @Override
    public String getAlgorithm() {
        checkDestroyed();
        return familyName;
    }

    @Override
    public byte[] getEncoded() {
        checkDestroyed();
        /*Different JVM levels are resulting in different encodings. So do the encoding here instead.
        *     OneAsymmetricKey ::= SEQUENCE {
        *        version                   Version,
        *        privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
        *        privateKey                PrivateKey,
        *        attributes            [0] Attributes OPTIONAL,
        *        ...,
        *        [[2: publicKey        [1] PublicKey OPTIONAL ]],
        *        ...
        *      }
        */
        byte[] encodedKey = null;
        try {
            int V1 = 0;
            DerOutputStream tmp = new DerOutputStream();
            tmp.putInteger(V1);
            DerOutputStream bytes = new DerOutputStream();
            bytes.putOID(algid.getOID());
            tmp.write(DerValue.tag_Sequence, bytes);
            tmp.putOctetString(this.privKeyMaterial);
            DerValue out = DerValue.wrap(DerValue.tag_Sequence, tmp);
            encodedKey = out.toByteArray();
            tmp.close();
            bytes.close();
        } catch (IOException ex) {
            //System.out.println("Exception creating encoding - "+ex.getMessage());
            return encodedKey;
        }
        
        return encodedKey;
    }

    /**
     * Returns the specific parameter-set name (e.g. "ML-DSA-65") for this key.
     */
    String getParamSetName() {
        return paramSetName;
    }

    PQCKey getPQCKey() {
        return this.pqcKey;
    }

    @java.io.Serial
    protected Object writeReplace() throws java.io.ObjectStreamException {
        checkDestroyed();
        return new JCEPlusKeyRep(JCEPlusKeyRep.Type.PRIVATE, getAlgorithm(), getFormat(), getEncoded(), provider.getName());
    } 

    /**
     * Destroys this key. A call to any of its other methods after this will
     * cause an IllegalStateException to be thrown.
     *
     * @throws DestroyFailedException
     *                                if some error occurs while destroying this
     *                                key.
     */
    @Override
    public void destroy() throws DestroyFailedException {
        if (!destroyed) {
            destroyed = true;
            Arrays.fill(this.privKeyMaterial, 0, this.privKeyMaterial.length, (byte) 0x00);
            this.privKeyMaterial = null;
            this.encodedKey = null;
            this.pqcKey = null;
        }
    }

    /** Determines if this key has been destroyed. */
    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    private void checkDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("This key is no longer valid");
        }
    }

    /**
     * Returns the family name for a known PQC algorithm.
     * <ul>
     *   <li>ML-DSA-44/65/87 all map to "ML-DSA"</li>
     *   <li>ML-KEM-512/768/1024 all map to "ML-KEM"</li>
     * </ul>
     * This matches the behaviour of the SUN provider, where {@code getAlgorithm()}
     * on a {@code NamedPKCS8Key} always returns the family name (the {@code fname}
     * field set from the constructor of {@code NamedKeyPairGenerator} /
     * {@code NamedKeyFactory}).
     */
    private static String familyName(String paramSetName) {
        if (paramSetName.startsWith("ML-DSA-")) {
            return "ML-DSA";
        }
        if (paramSetName.startsWith("ML-KEM-")) {
            return "ML-KEM";
        }
        throw new IllegalArgumentException(
                "Unrecognized PQC algorithm family for parameter set: " + paramSetName);
    }

    /**
     * Returns the expected byte length of the expanded private key for the
     * given PQC algorithm parameter-set name (e.g. "ML-DSA-44").
     */
    private static int getExpandedKeyLength(String algName) throws InvalidKeyException {
        switch (algName) {
            case "ML-DSA-44":  return 2560;
            case "ML-DSA-65":  return 4032;
            case "ML-DSA-87":  return 4896;
            case "ML-KEM-512": return 1632;
            case "ML-KEM-768": return 2400;
            case "ML-KEM-1024":return 3168;
            default: throw new InvalidKeyException("Unexpected PQC algorithm: " + algName);
        }
    }

    /**
     * Returns the expected seed length in bytes for the given algorithm.
     * Per RFC 9881 (ML-DSA) the seed is always 32 bytes; per RFC 9935
     * (ML-KEM) the seed is always 64 bytes.
     */
    private static int getSeedLength(String algName) throws InvalidKeyException {
        if (algName.startsWith("ML-DSA-")) return 32;
        if (algName.startsWith("ML-KEM-")) return 64;
        throw new InvalidKeyException("Unexpected PQC algorithm: " + algName);
    }

    /**
     * Normalises private key material to a canonical CHOICE-encoded form
     * and validates structural correctness per RFC 9881 / RFC 9935.
     *
     * <p>Accepted inputs:
     * <ul>
     *   <li><b>seed</b> – {@code 0x80 LL <seed>} where LL is the seed length
     *       (32 for ML-DSA, 64 for ML-KEM).  Passed through as-is.</li>
     *   <li><b>expandedKey (encoded)</b> – {@code 0x04 0x82 HH LL <expanded>}.
     *       Passed through as-is.</li>
     *   <li><b>expandedKey (raw)</b> – bare expanded bytes with no DER header.
     *       Wrapped into {@code 0x04 0x82 HH LL <expanded>}.</li>
     *   <li><b>both</b> – {@code 0x30 0x82 MM MM ...}.  Passed through as-is
     *       after verifying the outer SEQUENCE length.</li>
     * </ul>
     *
     * <p>The tag byte unambiguously identifies the CHOICE per RFC 9881 §6:
     * {@code 0x80} = seed, {@code 0x04} = expandedKey, {@code 0x30} = both.
     * Any other first byte is rejected unless the total length exactly matches
     * the raw expanded key size, in which case it is treated as raw expanded.
     *
     * @param key      the key material to normalise
     * @param algName  the concrete parameter-set name (e.g. "ML-DSA-44")
     * @return         normalised CHOICE-encoded key material
     * @throws InvalidKeyException if the material does not match any valid format
     */
    private static byte[] normaliseKeyMaterial(byte[] key, String algName)
            throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Private key material is null");
        }
        if (key.length == 0) {
            throw new InvalidKeyException("Private key material is empty");
        }

        int expandedLen = getExpandedKeyLength(algName);
        int seedLen     = getSeedLength(algName);
        int tag         = key[0] & 0xFF;

        // --- seed: 0x80 LL <seed> ---
        // RFC 9881 §6: "fixed 32-byte OCTET STRING (34 bytes total with the 0x8020 tag and length)"
        // RFC 9935 §6: "fixed 64-byte OCTET STRING (66 bytes total with the 0x8040 tag and length)"
        if (tag == 0x80) {
            int expectedLen = seedLen + 2; // tag + 1-byte length + seed bytes
            if (key.length != expectedLen || (key[1] & 0xFF) != seedLen) {
                throw new InvalidKeyException(
                        "Invalid seed CHOICE encoding for " + algName
                        + ": expected " + expectedLen + " bytes, got " + key.length);
            }
            return key.clone();
        }

        // --- expandedKey (encoded): 0x04 0x82 HH LL <expanded> ---
        if (tag == 0x04) {
            if (key.length < 4) {
                throw new InvalidKeyException("expandedKey CHOICE too short for " + algName);
            }
            int derLen = ((key[2] & 0xFF) << 8) | (key[3] & 0xFF);
            if ((key[1] & 0xFF) != 0x82 || derLen != expandedLen || key.length != expandedLen + 4) {
                throw new InvalidKeyException(
                        "Invalid expandedKey CHOICE encoding for " + algName);
            }
            return key.clone();
        }

        // --- both: 0x30 0x82 MM MM <seed-octetstring> <expanded-octetstring> ---
        if (tag == 0x30) {
            if (key.length < 4) {
                throw new InvalidKeyException("both CHOICE too short for " + algName);
            }
            // Inner content: 0x04 LL <seed> + 0x04 0x82 HH LL <expanded>
            int innerLen = 2 + seedLen + 4 + expandedLen; // seed-TLV + expanded-TLV
            int derLen   = ((key[2] & 0xFF) << 8) | (key[3] & 0xFF);
            if ((key[1] & 0xFF) != 0x82 || derLen != innerLen || key.length != innerLen + 4) {
                throw new InvalidKeyException(
                        "Invalid both CHOICE encoding for " + algName);
            }
            return key.clone();
        }

        // --- raw expanded: no header, exact length match ---
        if (key.length == expandedLen) {
            DerValue pkOct = null;
            try {
                pkOct = new DerValue(DerValue.tag_OctetString, key);
                return pkOct.toByteArray();
            } finally {
                if (pkOct != null) pkOct.clear();
            }
        }

        throw new InvalidKeyException(
                "Unrecognised private key format for " + algName
                + " (length=" + key.length + ", tag=0x" + Integer.toHexString(tag) + ")");
    }
}
