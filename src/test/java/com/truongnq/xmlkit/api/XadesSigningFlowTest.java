package com.truongnq.xmlkit.api;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.truongnq.xmlkit.core.DigestEngine;
import com.truongnq.xmlkit.exception.XmlKitException;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.model.SignatureType;
import com.truongnq.xmlkit.testing.TestCertificates;
import com.truongnq.xmlkit.testing.TestXml;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

class XadesSigningFlowTest {
    @Test
    void extendedRequestExposesSignatureValueDigestAndTimestampCompletion() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_T)
            .certificate(TestCertificates.certificate())
            .placementXPath("//slot")
            .prepare();

        PostSignatureRequest postSignature = request.completeSignature(new byte[] {9, 8, 7});
        assertArrayEquals(request.getSignatureValueDigest(new byte[] {9, 8, 7}), postSignature.getSignatureValueDigest());

        SignedDocument signed = postSignature.completeTimestamp(new byte[] {7, 8, 9});

        assertTrue(signed.xml().contains("UnsignedProperties"));
        assertTrue(signed.xml().contains("EncapsulatedTimeStamp"));
    }

    @Test
    void timestampFlowRequiresSignaturePhaseBeforeTimestampCompletion() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_T)
            .certificate(TestCertificates.certificate())
            .placementXPath("//slot")
            .prepare();

        assertThrows(XmlKitException.class, () -> request.completeTimestamp(new byte[] {7, 8, 9}));
    }

    @Test
    void timestampProfilesRequireTimestampCompletionStep() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_T)
            .certificate(TestCertificates.certificate())
            .placementXPath("//slot")
            .prepare();

        assertThrows(XmlKitException.class, () -> request.complete(new byte[] {9, 8, 7}));
    }

    @Test
    void timestampProfilesRequireNonNullTimestampToken() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_T)
            .certificate(TestCertificates.certificate())
            .placementXPath("//slot")
            .prepare();

        PostSignatureRequest postSignature = request.completeSignature(new byte[] {9, 8, 7});

        assertThrows(XmlKitException.class, () -> postSignature.completeTimestamp(null));
    }

    @Test
    void signatureValueDigestUsesConfiguredDigestAlgorithm() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_T)
            .certificate(TestCertificates.certificate())
            .digestAlgorithm(DigestAlgorithm.SHA384)
            .placementXPath("//slot")
            .prepare();

        byte[] signatureValue = new byte[] {9, 8, 7};

        assertArrayEquals(
            new DigestEngine().digest(DigestAlgorithm.SHA384, signatureValue),
            request.getSignatureValueDigest(signatureValue)
        );
    }

    @Test
    void xadesCIncludesValidationReferenceStructures() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_C)
            .certificate(TestCertificates.certificate())
            .placementXPath("//slot")
            .prepare();

        SignedDocument signed = request.completeSignature(new byte[] {9, 8, 7}).completeTimestamp(new byte[] {7, 8, 9});

        assertTrue(signed.xml().contains("CompleteCertificateRefs"));
        assertTrue(signed.xml().contains("CompleteRevocationRefs"));
        assertTrue(signed.xml().contains("CertDigest"));
    }

    @Test
    void xadesCAcceptsCallerSuppliedValidationReferenceMaterial() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_C)
            .certificate(TestCertificates.certificate())
            .placementXPath("//slot")
            .prepare();

        ValidationMaterial validationMaterial = ValidationMaterial.builder()
            .revocationReferenceUris(List.of("urn:test:crl:one"))
            .build();

        SignedDocument signed = request.completeSignature(new byte[] {9, 8, 7})
            .completeTimestamp(new byte[] {7, 8, 9}, validationMaterial);

        assertTrue(signed.xml().contains("urn:test:crl:one"));
    }

    @Test
    void xadesCIncludesAdditionalCertificateReferencesFromValidationMaterial() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_C)
            .certificate(TestCertificates.certificate())
            .placementXPath("//slot")
            .prepare();

        ValidationMaterial validationMaterial = ValidationMaterial.builder()
            .additionalCertificates(List.of(TestCertificates.certificate()))
            .build();

        SignedDocument signed = request.completeSignature(new byte[] {9, 8, 7})
            .completeTimestamp(new byte[] {7, 8, 9}, validationMaterial);

        assertTrue(countOccurrences(signed.xml(), "<xades:Cert>") == 2);
    }

    @Test
    void xadesXLIncludesEmbeddedValidationValues() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_X_L)
            .certificate(TestCertificates.certificate())
            .placementXPath("//slot")
            .prepare();

        SignedDocument signed = request.completeSignature(new byte[] {9, 8, 7}).completeTimestamp(new byte[] {7, 8, 9});

        assertTrue(signed.xml().contains("CertificateValues"));
        assertTrue(signed.xml().contains("EncapsulatedX509Certificate"));
        assertTrue(signed.xml().contains("RevocationValues"));
    }

    @Test
    void xadesXLIncludesCallerSuppliedEmbeddedValidationValues() throws Exception {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_X_L)
            .certificate(TestCertificates.certificate())
            .placementXPath("//slot")
            .prepare();

        byte[] crlValue = new byte[] {4, 5, 6};
        ValidationMaterial validationMaterial = ValidationMaterial.builder()
            .additionalCertificates(List.of(TestCertificates.certificate()))
            .revocationValues(List.of(crlValue))
            .build();

        SignedDocument signed = request.completeSignature(new byte[] {9, 8, 7})
            .completeTimestamp(new byte[] {7, 8, 9}, validationMaterial);

        assertTrue(signed.xml().contains(Base64.getEncoder().encodeToString(TestCertificates.certificate().getEncoded())));
        assertTrue(signed.xml().contains(Base64.getEncoder().encodeToString(crlValue)));
    }

    @Test
    void xadesXLIncludesAdditionalCertificateReferencesFromValidationMaterial() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_X_L)
            .certificate(TestCertificates.certificate())
            .placementXPath("//slot")
            .prepare();

        ValidationMaterial validationMaterial = ValidationMaterial.builder()
            .additionalCertificates(List.of(TestCertificates.certificate()))
            .build();

        SignedDocument signed = request.completeSignature(new byte[] {9, 8, 7})
            .completeTimestamp(new byte[] {7, 8, 9}, validationMaterial);

        assertTrue(countOccurrences(signed.xml(), "<xades:Cert>") == 2);
    }

    private int countOccurrences(String text, String token) {
        return text.split(token, -1).length - 1;
    }
}
