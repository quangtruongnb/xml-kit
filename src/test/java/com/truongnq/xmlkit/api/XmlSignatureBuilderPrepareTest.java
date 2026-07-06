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
import com.truongnq.xmlkit.model.Transform;
import com.truongnq.xmlkit.testing.FakeRemoteSigner;
import com.truongnq.xmlkit.testing.TestXml;
import com.truongnq.xmlkit.testing.XmlSignatureVerifier;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

class XmlSignatureBuilderPrepareTest {
    private final FakeRemoteSigner remoteSigner = new FakeRemoteSigner();

    @Test
    void prepareReturnsDigestAndCompleteInsertsEnvelopedSignature() {
        Document document = TestXml.document("<invoice><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.ENVELOPED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(FakeRemoteSigner.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .prepare();

        assertTrue(request.getDigestToSign().length > 0);

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        assertTrue(signed.xml().contains("Signature"));
        assertTrue(signed.xml().contains("SignatureValue"));
        assertTrue(signed.xml().contains("Transforms"));
        assertTrue(signed.xml().contains("http://www.w3.org/2000/09/xmldsig#enveloped-signature"));
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void xadesTPrepareReturnsExtendedRequest() {
        Document document = TestXml.document("<invoice><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.ENVELOPED)
                .profile(SignatureProfile.XADES_T)
                .certificate(FakeRemoteSigner.certificate())
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
                .certificate(FakeRemoteSigner.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        assertFalse(signed.xml().contains("http://www.w3.org/2000/09/xmldsig#enveloped-signature"));
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void detachedReferenceUsesCallerProvidedTransforms() {
        Document document = TestXml.document("<invoice><data>123</data><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(FakeRemoteSigner.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .targets(List.of(
                        TargetReference.of(
                                Selector.builder("//data").build(),
                                ReferenceOptions.builder()
                                        .transforms(List.of(
                                                Transform.xpath("not(ancestor-or-self::Signature)"),
                                                Transform.of("http://www.w3.org/2001/10/xml-exc-c14n#")))
                                        .build())))
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        assertTrue(signed.xml().contains("http://www.w3.org/TR/1999/REC-xpath-19991116"));
        assertTrue(signed.xml().contains("http://www.w3.org/2001/10/xml-exc-c14n#"));
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void envelopedReferenceUsesCallerProvidedTransformsWithoutAddingDefaults() {
        Document document = TestXml.document("<invoice><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.ENVELOPED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(FakeRemoteSigner.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .addTarget(
                        Selector.builder("/invoice").build(),
                        ReferenceOptions.builder()
                                .transforms(List.of(
                                        Transform.of("http://www.w3.org/2000/09/xmldsig#enveloped-signature"),
                                        Transform.of("http://www.w3.org/2001/10/xml-exc-c14n#")))
                                .build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        assertTrue(signed.xml().contains("http://www.w3.org/2000/09/xmldsig#enveloped-signature"));
        assertTrue(signed.xml().contains("http://www.w3.org/2001/10/xml-exc-c14n#"));
        assertEquals(1, countOccurrences(signed.xml(), "http://www.w3.org/2000/09/xmldsig#enveloped-signature"));
        assertEquals(2, countOccurrences(signed.xml(), "<ds:Transform Algorithm="));
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void prepareRejectsEnvelopedTransformsWithoutEnvelopedSignatureTransform() {
        Document document = TestXml.document("<invoice><slot/></invoice>");

        assertThrows(XmlKitException.class, () -> XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.ENVELOPED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(FakeRemoteSigner.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .addTarget(
                        Selector.builder("/invoice").build(),
                        ReferenceOptions.builder()
                                .transforms(List.of(Transform.of("http://www.w3.org/2001/10/xml-exc-c14n#")))
                                .build())
                .prepare());
    }

    @Test
    void signedInfoUsesSignatureMethodMatchingConfiguredDigestAlgorithm() {
        Document document = TestXml.document("<invoice><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.ENVELOPED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(FakeRemoteSigner.certificate())
                .digestAlgorithm(DigestAlgorithm.SHA512)
                .placementSelector(Selector.builder("//slot").build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA512);
        SignedDocument signed = request.complete(signatureValue);

        assertTrue(signed.xml().contains("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"));
        assertTrue(signed.xml().contains(DigestAlgorithm.SHA512.uri()));
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign(), DigestAlgorithm.SHA512));
    }

    @Test
    void prepareRejectsNonElementPlacementTargets() {
        Document document = TestXml.document("<invoice><slot>value</slot></invoice>");

        assertThrows(XmlKitException.class, () -> XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.ENVELOPED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(FakeRemoteSigner.certificate())
                .placementSelector(Selector.builder("//slot/text()").build())
                .prepare());
    }

    @Test
    void targetXPathDeterminesSignedPayloadNode() {
        Document document = TestXml.document("<invoice><data>123</data><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(FakeRemoteSigner.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .targets(List.of(TargetReference.of(Selector.builder("//data").build())))
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        assertTrue(signed.xml().matches("(?s).*<data Id=\"id-.*\">123</data>.*"));
        assertTrue(signed.xml().contains("URI=\"#id-"));
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void prepareAppliesClientProvidedReferenceId() {
        Document document = TestXml.document("<invoice><data>123</data><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(FakeRemoteSigner.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .targets(List.of(TargetReference.of(
                        Selector.builder("//data").build(),
                        ReferenceOptions.builder().referenceId("custom-client-id").build())))
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        assertTrue(signed.xml().contains("<data Id=\"custom-client-id\">123</data>"));
        assertTrue(signed.xml().contains("URI=\"#custom-client-id\""));
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void prepareBuildsOneDetachedReferencePerConfiguredTarget() {
        Document document = TestXml.document("<invoice><data>123</data><meta>abc</meta><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(FakeRemoteSigner.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .targets(List.of(
                        TargetReference.of(
                                Selector.builder("//data").build(),
                                ReferenceOptions.builder().referenceId("data-ref").build()),
                        TargetReference.of(
                                Selector.builder("//meta").build(),
                                ReferenceOptions.builder().referenceId("meta-ref").build())))
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        assertTrue(signed.xml().contains("URI=\"#data-ref\""));
        assertTrue(signed.xml().contains("URI=\"#meta-ref\""));
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void addTargetXPathAppendsTargetToReferenceList() {
        Document document = TestXml.document("<invoice><data>123</data><meta>abc</meta><slot/></invoice>");

        SigningRequest request = XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(FakeRemoteSigner.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .addTarget(Selector.builder("//data").build(), ReferenceOptions.builder().referenceId("data-ref").build())
                .addTarget(Selector.builder("//meta").build(), ReferenceOptions.builder().referenceId("meta-ref").build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        assertTrue(signed.xml().contains("URI=\"#data-ref\""));
        assertTrue(signed.xml().contains("URI=\"#meta-ref\""));
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void prepareRejectsDuplicateResolvedTargets() {
        Document document = TestXml.document("<invoice><data>123</data><slot/></invoice>");

        assertThrows(XmlKitException.class, () -> XmlSignatureBuilder.forDocument(document)
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(FakeRemoteSigner.certificate())
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
                .certificate(FakeRemoteSigner.certificate())
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
