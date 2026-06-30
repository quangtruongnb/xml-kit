package com.truongnq.xmlkit.api;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.truongnq.xmlkit.exception.XmlKitException;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.model.SignatureType;
import com.truongnq.xmlkit.testing.TestCertificates;
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
            .certificate(TestCertificates.certificate())
            .placementXPath("//slot")
            .prepare();

        assertTrue(request.getDigestToSign().length > 0);

        SignedDocument signed = request.complete(new byte[] {1, 2, 3});

        assertTrue(signed.xml().contains("Signature"));
        assertTrue(signed.xml().contains("SignatureValue"));
        assertTrue(signed.xml().contains("Transforms"));
        assertTrue(signed.xml().contains("http://www.w3.org/2000/09/xmldsig#enveloped-signature"));
    }

    @Test
    void xadesTPrepareReturnsExtendedRequest() {
        Document document = TestXml.document("<invoice><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_T)
            .certificate(TestCertificates.certificate())
            .placementXPath("//slot")
            .prepare();

        assertInstanceOf(ExtendedSigningRequest.class, request);
    }

    @Test
    void detachedSignedInfoDoesNotAddEnvelopedTransform() {
        Document document = TestXml.document("<invoice><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
            .signatureType(SignatureType.DETACHED)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(TestCertificates.certificate())
            .placementXPath("//slot")
            .prepare();

        SignedDocument signed = request.complete(new byte[] {1, 2, 3});

        assertFalse(signed.xml().contains("http://www.w3.org/2000/09/xmldsig#enveloped-signature"));
    }

    @Test
    void signedInfoUsesSignatureMethodMatchingConfiguredDigestAlgorithm() {
        Document document = TestXml.document("<invoice><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(TestCertificates.certificate())
            .digestAlgorithm(DigestAlgorithm.SHA512)
            .placementXPath("//slot")
            .prepare();

        SignedDocument signed = request.complete(new byte[] {1, 2, 3});

        assertTrue(signed.xml().contains("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"));
        assertTrue(signed.xml().contains(DigestAlgorithm.SHA512.uri()));
    }

    @Test
    void prepareRejectsNonElementPlacementTargets() {
        Document document = TestXml.document("<invoice><slot>value</slot></invoice>");

        assertThrows(XmlKitException.class, () -> XmlSignatureBuilder.forDocument(document)
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(TestCertificates.certificate())
            .placementXPath("//slot/text()")
            .prepare());
    }

    @Test
    void targetXPathDeterminesSignedPayloadNode() {
        Document document = TestXml.document("<invoice><data>123</data><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
            .signatureType(SignatureType.DETACHED)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(TestCertificates.certificate())
            .placementXPath("//slot")
            .targetXPath("//data")
            .prepare();

        SignedDocument signed = request.complete(new byte[] {1, 2, 3});

        assertTrue(signed.xml().matches("(?s).*<data Id=\"id-.*\">123</data>.*"));
        assertTrue(signed.xml().contains("URI=\"#id-"));
    }

    @Test
    void prepareAppliesClientProvidedReferenceId() {
        Document document = TestXml.document("<invoice><data>123</data><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
            .signatureType(SignatureType.DETACHED)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(TestCertificates.certificate())
            .placementXPath("//slot")
            .targetXPath("//data")
            .referenceId("custom-client-id")
            .prepare();

        SignedDocument signed = request.complete(new byte[] {1, 2, 3});

        assertTrue(signed.xml().contains("<data Id=\"custom-client-id\">123</data>"));
        assertTrue(signed.xml().contains("URI=\"#custom-client-id\""));
    }
}
