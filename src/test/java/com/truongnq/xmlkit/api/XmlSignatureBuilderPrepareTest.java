package com.truongnq.xmlkit.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.truongnq.xmlkit.exception.XmlKitException;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.model.SignatureType;
import com.truongnq.xmlkit.testing.TestCertificates;
import com.truongnq.xmlkit.testing.TestXml;
import java.util.List;
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
                .placementSelector(Selector.builder("//slot").build())
                .prepare();

        assertTrue(request.getDigestToSign().length > 0);

        SignedDocument signed = request.complete(new byte[] { 1, 2, 3 });

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
                .placementSelector(Selector.builder("//slot").build())
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
                .placementSelector(Selector.builder("//slot").build())
                .prepare();

        SignedDocument signed = request.complete(new byte[] { 1, 2, 3 });

        assertFalse(signed.xml().contains("http://www.w3.org/2000/09/xmldsig#enveloped-signature"));
    }

    @Test
    void detachedReferenceUsesCallerProvidedTransforms() {
        Document document = TestXml.document("<invoice><data>123</data><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(TestCertificates.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .targets(List.of(
                        TargetReference.of(
                                Selector.builder("//data").build(),
                                ReferenceOptions.builder()
                                        .transformUris(List.of(
                                                "http://www.w3.org/TR/1999/REC-xpath-19991116",
                                                "http://www.w3.org/2001/10/xml-exc-c14n#"))
                                        .build())))
                .prepare();

        SignedDocument signed = request.complete(new byte[] { 1, 2, 3 });

        assertTrue(signed.xml().contains("http://www.w3.org/TR/1999/REC-xpath-19991116"));
        assertTrue(signed.xml().contains("http://www.w3.org/2001/10/xml-exc-c14n#"));
    }

    @Test
    void envelopedReferenceUsesCallerProvidedTransformsWithoutAddingDefaults() {
        Document document = TestXml.document("<invoice><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.ENVELOPED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(TestCertificates.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .addTarget(
                        Selector.builder("/invoice").build(),
                        ReferenceOptions.builder()
                                .transformUris(List.of(
                                        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                                        "http://www.w3.org/2001/10/xml-exc-c14n#"))
                                .build())
                .prepare();

        SignedDocument signed = request.complete(new byte[] { 1, 2, 3 });

        assertTrue(signed.xml().contains("http://www.w3.org/2000/09/xmldsig#enveloped-signature"));
        assertTrue(signed.xml().contains("http://www.w3.org/2001/10/xml-exc-c14n#"));
        assertEquals(1, countOccurrences(signed.xml(), "http://www.w3.org/2000/09/xmldsig#enveloped-signature"));
        assertEquals(2, countOccurrences(signed.xml(), "<ds:Transform Algorithm="));
    }

    @Test
    void prepareRejectsEnvelopedTransformsWithoutEnvelopedSignatureTransform() {
        Document document = TestXml.document("<invoice><slot/></invoice>");

        assertThrows(XmlKitException.class, () -> XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.ENVELOPED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(TestCertificates.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .addTarget(
                        Selector.builder("/invoice").build(),
                        ReferenceOptions.builder()
                                .transformUris(List.of("http://www.w3.org/2001/10/xml-exc-c14n#"))
                                .build())
                .prepare());
    }

    @Test
    void signedInfoUsesSignatureMethodMatchingConfiguredDigestAlgorithm() {
        Document document = TestXml.document("<invoice><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.ENVELOPED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(TestCertificates.certificate())
                .digestAlgorithm(DigestAlgorithm.SHA512)
                .placementSelector(Selector.builder("//slot").build())
                .prepare();

        SignedDocument signed = request.complete(new byte[] { 1, 2, 3 });

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
                .placementSelector(Selector.builder("//slot/text()").build())
                .prepare());
    }

    @Test
    void targetXPathDeterminesSignedPayloadNode() {
        Document document = TestXml.document("<invoice><data>123</data><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(TestCertificates.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .targets(List.of(TargetReference.of(Selector.builder("//data").build())))
                .prepare();

        SignedDocument signed = request.complete(new byte[] { 1, 2, 3 });

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
                .placementSelector(Selector.builder("//slot").build())
                .targets(List.of(TargetReference.of(
                        Selector.builder("//data").build(),
                        ReferenceOptions.builder().referenceId("custom-client-id").build())))
                .prepare();

        SignedDocument signed = request.complete(new byte[] { 1, 2, 3 });

        assertTrue(signed.xml().contains("<data Id=\"custom-client-id\">123</data>"));
        assertTrue(signed.xml().contains("URI=\"#custom-client-id\""));
    }

    @Test
    void prepareBuildsOneDetachedReferencePerConfiguredTarget() {
        Document document = TestXml.document("<invoice><data>123</data><meta>abc</meta><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(TestCertificates.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .targets(List.of(
                        TargetReference.of(
                                Selector.builder("//data").build(),
                                ReferenceOptions.builder().referenceId("data-ref").build()),
                        TargetReference.of(
                                Selector.builder("//meta").build(),
                                ReferenceOptions.builder().referenceId("meta-ref").build())))
                .prepare();

        SignedDocument signed = request.complete(new byte[] { 1, 2, 3 });

        assertTrue(signed.xml().contains("URI=\"#data-ref\""));
        assertTrue(signed.xml().contains("URI=\"#meta-ref\""));
    }

    @Test
    void addTargetXPathAppendsTargetToReferenceList() {
        Document document = TestXml.document("<invoice><data>123</data><meta>abc</meta><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(TestCertificates.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .addTarget(Selector.builder("//data").build(), ReferenceOptions.builder().referenceId("data-ref").build())
                .addTarget(Selector.builder("//meta").build(), ReferenceOptions.builder().referenceId("meta-ref").build())
                .prepare();

        SignedDocument signed = request.complete(new byte[] { 1, 2, 3 });

        assertTrue(signed.xml().contains("URI=\"#data-ref\""));
        assertTrue(signed.xml().contains("URI=\"#meta-ref\""));
    }

    @Test
    void prepareRejectsDuplicateResolvedTargets() {
        Document document = TestXml.document("<invoice><data>123</data><slot/></invoice>");

        assertThrows(XmlKitException.class, () -> XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(TestCertificates.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .targets(List.of(
                        TargetReference.of(Selector.builder("//data").build()),
                        TargetReference.of(Selector.builder("/invoice/data").build())))
                .prepare());
    }

    @Test
    void prepareRejectsMultipleTargetsForEnvelopedSignature() {
        Document document = TestXml.document("<invoice><data>123</data><meta>abc</meta><slot/></invoice>");

        assertThrows(XmlKitException.class, () -> XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.ENVELOPED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(TestCertificates.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .targets(List.of(
                        TargetReference.of(Selector.builder("//data").build()),
                        TargetReference.of(Selector.builder("//meta").build())))
                .prepare());
    }

    private int countOccurrences(String text, String needle) {
        return text.split(java.util.regex.Pattern.quote(needle), -1).length - 1;
    }
}
