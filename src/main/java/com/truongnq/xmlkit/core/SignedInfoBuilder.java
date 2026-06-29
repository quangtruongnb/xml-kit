package com.truongnq.xmlkit.core;

import com.truongnq.xmlkit.model.CanonicalizationMethod;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureType;
import org.w3c.dom.Document;

public final class SignedInfoBuilder {
    private static final String RSA_SHA256_URI = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private final DigestEngine digestEngine;

    public SignedInfoBuilder(DigestEngine digestEngine) {
        this.digestEngine = digestEngine;
    }

    public SignedInfoData build(
        Document document,
        SignatureType signatureType,
        DigestAlgorithm digestAlgorithm,
        CanonicalizationMethod canonicalizationMethod
    ) {
        String referenceUri = switch (signatureType) {
            case ENVELOPED -> "";
            case ENVELOPING -> "#object-1";
            case DETACHED -> "#detached-content";
        };

        String referenceDigest = digestEngine.digestBase64(digestAlgorithm, XmlSupport.canonicalize(document.getDocumentElement()));
        return new SignedInfoData(
            referenceUri,
            referenceDigest,
            canonicalizationMethod.uri(),
            digestAlgorithm.uri(),
            RSA_SHA256_URI
        );
    }
}
