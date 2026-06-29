package com.truongnq.xmlkit.api;

import com.truongnq.xmlkit.core.DigestEngine;
import com.truongnq.xmlkit.core.SignatureAssembler;
import com.truongnq.xmlkit.model.DigestAlgorithm;

public final class ExtendedSigningRequest extends SigningRequest {
    private final DigestEngine digestEngine;

    ExtendedSigningRequest(
        PreparedSignature prepared,
        SignatureAssembler assembler,
        DigestEngine digestEngine,
        byte[] digestToSign
    ) {
        super(prepared, assembler, digestToSign);
        this.digestEngine = digestEngine;
    }

    public byte[] getSignatureValueDigest(byte[] signatureValue) {
        return digestEngine.digest(DigestAlgorithm.SHA256, signatureValue);
    }

    public SignedDocument complete(byte[] signatureValue, byte[] timestampToken) {
        return assembler().assemble(prepared(), signatureValue, timestampToken);
    }
}
