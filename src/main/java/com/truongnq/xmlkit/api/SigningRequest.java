package com.truongnq.xmlkit.api;

import com.truongnq.xmlkit.core.SignatureAssembler;

public class SigningRequest {
    private final PreparedSignature prepared;
    private final SignatureAssembler assembler;
    private final byte[] digestToSign;

    SigningRequest(PreparedSignature prepared, SignatureAssembler assembler, byte[] digestToSign) {
        this.prepared = prepared;
        this.assembler = assembler;
        this.digestToSign = digestToSign.clone();
    }

    public byte[] getDigestToSign() {
        return digestToSign.clone();
    }

    public SignedDocument complete(byte[] signatureValue) {
        return assembler.assemble(prepared, signatureValue);
    }

    protected PreparedSignature prepared() {
        return prepared;
    }

    protected SignatureAssembler assembler() {
        return assembler;
    }
}
