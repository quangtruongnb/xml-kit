package com.truongnq.xmlkit.api;

import com.truongnq.xmlkit.core.SignatureAssembler;
import com.truongnq.xmlkit.exception.XmlKitException;

public final class PostSignatureRequest {
    private final PreparedSignature prepared;
    private final SignatureAssembler assembler;
    private final byte[] signatureValue;
    private final byte[] signatureValueDigest;

    PostSignatureRequest(
        PreparedSignature prepared,
        SignatureAssembler assembler,
        byte[] signatureValue,
        byte[] signatureValueDigest
    ) {
        this.prepared = prepared;
        this.assembler = assembler;
        this.signatureValue = signatureValue.clone();
        this.signatureValueDigest = signatureValueDigest.clone();
    }

    public byte[] getSignatureValueDigest() {
        return signatureValueDigest.clone();
    }

    public SignedDocument completeTimestamp(byte[] timestampToken) {
        return completeTimestamp(timestampToken, ValidationMaterial.empty());
    }

    public SignedDocument completeTimestamp(byte[] timestampToken, ValidationMaterial validationMaterial) {
        if (timestampToken == null) {
            throw new XmlKitException("Timestamp token is required for the configured signature profile.");
        }
        return assembler.assemble(prepared, signatureValue, timestampToken, validationMaterial);
    }
}
