package com.truongnq.xmlkit.api;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.model.SignatureType;
import com.truongnq.xmlkit.testing.TestXml;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

class XmlSignatureBuilderPrepareTest {
    @Test
    void prepareReturnsDigestAndCompleteInsertsEnvelopedSignature() {
        Document document = TestXml.document("<invoice><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XMLDSIG)
            .placementXPath("//slot")
            .prepare();

        assertTrue(request.getDigestToSign().length > 0);

        SignedDocument signed = request.complete(new byte[] {1, 2, 3});

        assertTrue(signed.xml().contains("Signature"));
        assertTrue(signed.xml().contains("SignatureValue"));
    }

    @Test
    void xadesTPrepareReturnsExtendedRequest() {
        Document document = TestXml.document("<invoice><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_T)
            .placementXPath("//slot")
            .prepare();

        assertInstanceOf(ExtendedSigningRequest.class, request);
    }
}
