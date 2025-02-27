/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class Digest implements Cloneable {

    /* ===========================================================================
       Digest caching mechanism
       Cache native SHA* digest contexts so that the same contexts could be reused later after resetting.
       */

    // index corresponding the SHA algorithm it's using
    // also used as a flag:
    // 0 - 4: it is using one of {SHA1, SHA224, SHA256, SHA384, SHA512}
    // -1   : Not initialized
    // -2   : Not a SHA* digest algorithm
    private int algIndx = -1;

    private boolean needsReinit = false;

    private boolean contextFromQueue = false;

    // Size of {SHA256, SHA384, SHA512, SHA224, SHA1}
    final static int[] digestLengths = {32, 48, 64, 28, 20};

    //disable caching mechanism for windows OS
    final static private boolean isWindows = System.getProperty("os.name").startsWith("Windows");

    final static private int numContexts;

    final static int numShaAlgos = 5;
    private static final String DIGEST_CONTEXT_CACHE_SIZE = "com.ibm.crypto.provider.DigestContextCacheSize";

    private static boolean needsInit = true;

    static private ConcurrentLinkedQueueLong contexts[];

    static private int runtimeContextNum[];

    class ConcurrentLinkedQueueLong extends ConcurrentLinkedQueue<Long> {
        private static final long serialVersionUID = 196745693267521676L;
    }

    static {
        // Configurable number of cached contexts
        int tmpNumContext = 0;
        if (isWindows) {
            tmpNumContext = 0;
        } else {
            try {
                tmpNumContext = Integer
                        .parseInt(System.getProperty(DIGEST_CONTEXT_CACHE_SIZE, "2048"));
            } catch (NumberFormatException e) {
                tmpNumContext = 0;
            }
        }
        numContexts = tmpNumContext;
    }

    void getContext() throws OCKException {
        if (needsInit) {
            synchronized (Digest.class) {
                if (needsInit) {
                    contexts = new ConcurrentLinkedQueueLong[numShaAlgos];
                    runtimeContextNum = new int[numShaAlgos];

                    for (int i = 0; i < numShaAlgos; i++) {
                        contexts[i] = new ConcurrentLinkedQueueLong();
                        runtimeContextNum[i] = 0;
                    }
                    needsInit = false;
                }
            }
        }

        if (this.digestId != 0) {
            return;
        }

        if (this.algIndx == -1) {
            switch (this.digestAlgo) {
                case "SHA256":
                    this.algIndx = 0;
                    break;
                case "SHA384":
                    this.algIndx = 1;
                    break;
                case "SHA512":
                    this.algIndx = 2;
                    break;
                case "SHA224":
                    this.algIndx = 3;
                    break;
                case "SHA1":
                    this.algIndx = 4;
                    break;
                default:
                    this.algIndx = -2;
                    break;
            }
        }

        // Algorithm is not SHA*
        if (this.algIndx == -2) {
            this.digestId = NativeInterface.DIGEST_create(this.ockContext.getId(),
                    this.digestAlgo);
        } else {
            Long context = contexts[this.algIndx].poll();

            if (context == null) {
                // Create new context
                this.digestId = NativeInterface
                        .DIGEST_create(this.ockContext.getId(), this.digestAlgo);
                this.contextFromQueue = (runtimeContextNum[this.algIndx] < numContexts);
                if (runtimeContextNum[this.algIndx] < numContexts) {
                    runtimeContextNum[this.algIndx]++;
                }
            } else {
                this.digestId = context;
                this.contextFromQueue = true;
            }
        }
        this.needsReinit = false;
    }

    void releaseContext() throws OCKException {

        if (this.digestId == 0) {
            return;
        }

        // not SHA* algorithm
        if (this.algIndx == -2) {
            if (validId(this.digestId)) {
                NativeInterface.DIGEST_delete(this.ockContext.getId(),
                        this.digestId);
                this.digestId = 0;
            }
        } else {
            if (this.contextFromQueue) {
                // reset now to make sure all contexts in the queue are ready to use
                this.reset();
                contexts[this.algIndx].add(this.digestId);
                this.digestId = 0;
                this.contextFromQueue = false;
            } else {
                // delete context
                if (validId(this.digestId)) {
                    NativeInterface.DIGEST_delete(this.ockContext.getId(),
                            this.digestId);
                    this.digestId = 0;
                }
            }
        }
        this.digestId = 0;
    }

    /* end digest caching mechanism
     * ===========================================================================
     */

    private OCKContext ockContext = null;
    private int digestLength = 0;
    private final String badIdMsg = "Digest Identifier is not valid";
    private static final String debPrefix = "DIGEST";

    private String digestAlgo;

    private long digestId = 0;

    public static Digest getInstance(OCKContext ockContext, String digestAlgo) throws OCKException {
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (digestAlgo == null || digestAlgo.isEmpty()) {
            throw new IllegalArgumentException("digestAlgo is null/empty");
        }

        return new Digest(ockContext, digestAlgo);
    }

    private Digest(OCKContext ockContext, String digestAlgo) throws OCKException {
        //final String methodName = "Digest(String)";
        this.ockContext = ockContext;
        this.digestAlgo = digestAlgo;
        getContext();
        //OCKDebug.Msg(debPrefix, methodName,  "digestAlgo :" + digestAlgo);
    }

    private Digest() {
    }

    static void throwOCKException(int errorCode) throws OCKException {
        //final String methodName = "throwOCKExeption";
        // OCKDebug.Msg(debPrefix, methodName, "throwOCKException errorCode =  " + errorCode);
        switch (errorCode) {
            case -1:
                throw new OCKException("ICC_EVP_DigestFinal failed!");
            case -2:
                throw new OCKException("ICC_EVP_DigestInit failed!");
            case -3:
                throw new OCKException("ICC_EVP_DigestUpdate failed!");
            default:
                throw new OCKException("Unknow Error Code");
        }
    }

    public synchronized void update(byte[] input, int offset, int length) throws OCKException {
        //final String methodName = "update ";
        int errorCode = 0;

        if (length == 0) {
            return;
        }

        if (input == null || length < 0 || offset < 0 || (offset + length) > input.length) {
            throw new IllegalArgumentException("Input range is invalid.");
        }

        //OCKDebug.Msg(debPrefix, methodName, "offset :"  + offset + " digestId :" + this.digestId + " length :" + length);
        if (!validId(this.digestId)) {
            throw new OCKException(badIdMsg);
        }

        errorCode = NativeInterface.DIGEST_update(this.ockContext.getId(),
                this.digestId, input, offset, length);
        if (errorCode < 0) {
            throwOCKException(errorCode);
        }
        this.needsReinit = true;
    }

    public synchronized byte[] digest() throws OCKException {
        //final String methodName = "digest()";
        int errorCode = 0;

        if (!validId(this.digestId)) {
            throw new OCKException(badIdMsg);
        }
        //OCKDebug.Msg (debPrefix, methodName, "digestId :" + this.digestId);


        // push data from the buffer that haven't got updated yet
        int digestLength = getDigestLength();
        byte[] digestBytes = new byte[digestLength];

        errorCode = NativeInterface.DIGEST_digest_and_reset(this.ockContext.getId(),
                this.digestId, digestBytes);
        if (errorCode < 0) {
            throwOCKException(errorCode);
        }
        this.needsReinit = false;

        return digestBytes;
    }

    protected long getId() throws OCKException {
        //final String methodName = "getId()";
        //OCKDebug.Msg(debPrefix, methodName, "digestId :" + this.digestId);
        return this.digestId;
    }

    public int getDigestLength() throws OCKException {
        //final String methodName = "getDigestLength()";

        if (digestLength == 0) {
            obtainDigestLength();
        }
        //OCKDebug.Msg(debPrefix, methodName, "digestLength :" + digestLength);
        return digestLength;
    }

    public synchronized void reset() throws OCKException {
        //final String methodName = "reset ";
        //OCKDebug.Msg(debPrefix, methodName,  "digestId =" + this.digestId);

        if (this.digestId == 0) {
            return;
        }

        if (!validId(this.digestId)) {
            throw new OCKException(badIdMsg);
        }
        if (this.needsReinit) {
            NativeInterface.DIGEST_reset(this.ockContext.getId(), this.digestId);
        }
        this.needsReinit = false;
    }

    private synchronized void obtainDigestLength() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getDigestLength at the same time, we only want to call the
        // native code one time.

        // if SHA* algorithms
        if (this.algIndx >= 0 && this.algIndx < numShaAlgos) {
            this.digestLength = digestLengths[this.algIndx];
        } else {
            if (this.digestLength == 0) {
                if (!validId(this.digestId)) {
                    throw new OCKException(badIdMsg);
                }
                this.digestLength = NativeInterface.DIGEST_size(this.ockContext.getId(),
                        this.digestId);
            }
        }
    }

    @Override
    protected synchronized void finalize() throws Throwable {
        //final String methodName = "finalize";

        try {
            //OCKDebug.Msg(debPrefix, methodName,  "digestId =" + this.digestId);
            releaseContext();
        } finally {
            super.finalize();
        }
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {
        //final String methodName = "validId";
        //OCKDebug.Msg(debPrefix, methodName,  "Id : " + id);
        return (id != 0L);
    }

    /**
     * Clones a given Digest.
     */
    public synchronized Object clone() throws CloneNotSupportedException {
        // Create new Digest instance and copy all relevant fields into the copy.
        // Clones do not make use of the cache so always set the value of
        // contextFromQueue to false to ensure that the context is later freed
        // correctly.
        Digest copy = new Digest();
        copy.digestLength = this.digestLength;
        copy.algIndx = this.algIndx;
        copy.digestAlgo = new String(this.digestAlgo);
        copy.needsReinit = this.needsReinit;
        copy.ockContext = this.ockContext;
        copy.contextFromQueue = false;

        // Allocate a new context for the digestId and copy all state information from our
        // original context into the copy. 
        try {
            copy.digestId = NativeInterface.DIGEST_copy(
                this.ockContext.getId(), getId());
            if (0 == copy.digestId) {
                throw new CloneNotSupportedException("Copy of native digest context failed.");
            }
        } catch (OCKException e) {
            StackTraceElement[] stackTraceArray = e.getStackTrace();
            String stackTrace = Stream.of(stackTraceArray)
                                      .map(t -> t.toString())
                                      .collect(Collectors.joining("\n"));
            throw new CloneNotSupportedException(stackTrace);
        }
        return copy;
    }
}
