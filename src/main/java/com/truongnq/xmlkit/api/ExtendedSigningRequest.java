package com.truongnq.xmlkit.api;

import com.truongnq.xmlkit.core.DigestEngine;
import com.truongnq.xmlkit.core.SignatureAssembler;
import com.truongnq.xmlkit.exception.XmlKitException;
import com.truongnq.xmlkit.model.DigestAlgorithm;

public final class ExtendedSigningRequest extends SigningRequest {
    private final DigestEngine digestEngine;
    private final DigestAlgorithm digestAlgorithm;

    ExtendedSigningRequest(
        PreparedSignature prepared,
        SignatureAssembler assembler,
        DigestEngine digestEngine,
        byte[] digestToSign
    ) {
        super(prepared, assembler, digestToSign);
        this.digestEngine = digestEngine;
        this.digestAlgorithm = prepared.digestAlgorithm();
    }

    public byte[] getSignatureValueDigest(byte[] signatureValue) {
        return digestEngine.digest(digestAlgorithm, signatureValue);
    }

    @Override
    public SignedDocument complete(byte[] signatureValue) {
        throw new XmlKitException("Timestamp token is required for the configured signature profile.");
    }

    public PostSignatureRequest completeSignature(byte[] signatureValue) {
        return new PostSignatureRequest(
            prepared(),
            assembler(),
            signatureValue,
            getSignatureValueDigest(signatureValue)
        );
    }

    public SignedDocument completeTimestamp(byte[] timestampToken) {
        throw new XmlKitException("Signature value must be provided before timestamp completion.");
    }

    public SignedDocument complete(byte[] signatureValue, byte[] timestampToken) {
        return completeSignature(signatureValue).completeTimestamp(timestampToken);
    }
}
