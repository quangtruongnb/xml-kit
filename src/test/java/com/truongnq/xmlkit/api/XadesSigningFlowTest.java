package com.truongnq.xmlkit.api;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.truongnq.xmlkit.core.DigestEngine;
import com.truongnq.xmlkit.exception.XmlKitException;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.model.SignatureType;
import com.truongnq.xmlkit.model.Transform;
import com.truongnq.xmlkit.testing.FakeRemoteSigner;
import com.truongnq.xmlkit.testing.FakeTimestampAuthority;
import com.truongnq.xmlkit.testing.TestXml;
import com.truongnq.xmlkit.testing.XmlSignatureVerifier;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

class XadesSigningFlowTest {
    private final FakeRemoteSigner remoteSigner = new FakeRemoteSigner();
    private final FakeTimestampAuthority timestampAuthority = new FakeTimestampAuthority();

    @Test
    void extendedRequestExposesSignatureValueDigestAndTimestampCompletion() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_T)
            .certificate(FakeRemoteSigner.certificate())
            .placementSelector(Selector.builder("//slot").build())
            .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        PostSignatureRequest postSignature = request.completeSignature(signatureValue);
        assertArrayEquals(request.getSignatureValueDigest(signatureValue), postSignature.getSignatureValueDigest());

        byte[] timestampToken = timestampAuthority.timestamp(postSignature.getSignatureValueDigest());
        SignedDocument signed = postSignature.completeTimestamp(timestampToken);

        assertTrue(signed.xml().contains("UnsignedProperties"));
        assertTrue(signed.xml().contains("EncapsulatedTimeStamp"));
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void timestampFlowRequiresSignaturePhaseBeforeTimestampCompletion() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_T)
            .certificate(FakeRemoteSigner.certificate())
            .placementSelector(Selector.builder("//slot").build())
            .prepare();

        assertThrows(XmlKitException.class, () -> request.completeTimestamp(new byte[] {7, 8, 9}));
    }

    @Test
    void timestampProfilesRequireTimestampCompletionStep() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_T)
            .certificate(FakeRemoteSigner.certificate())
            .placementSelector(Selector.builder("//slot").build())
            .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        assertThrows(XmlKitException.class, () -> request.complete(signatureValue));
    }

    @Test
    void timestampProfilesRequireNonNullTimestampToken() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_T)
            .certificate(FakeRemoteSigner.certificate())
            .placementSelector(Selector.builder("//slot").build())
            .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        PostSignatureRequest postSignature = request.completeSignature(signatureValue);

        assertThrows(XmlKitException.class, () -> postSignature.completeTimestamp(null));
    }

    @Test
    void signatureValueDigestUsesConfiguredDigestAlgorithm() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_T)
            .certificate(FakeRemoteSigner.certificate())
            .digestAlgorithm(DigestAlgorithm.SHA384)
            .placementSelector(Selector.builder("//slot").build())
            .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA384);

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
            .certificate(FakeRemoteSigner.certificate())
            .placementSelector(Selector.builder("//slot").build())
            .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        PostSignatureRequest postSignature = request.completeSignature(signatureValue);
        byte[] timestampToken = timestampAuthority.timestamp(postSignature.getSignatureValueDigest());
        SignedDocument signed = postSignature.completeTimestamp(timestampToken);

        assertTrue(signed.xml().contains("CompleteCertificateRefs"));
        assertTrue(signed.xml().contains("CompleteRevocationRefs"));
        assertTrue(signed.xml().contains("CertDigest"));
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void xadesCAcceptsCallerSuppliedValidationReferenceMaterial() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_C)
            .certificate(FakeRemoteSigner.certificate())
            .placementSelector(Selector.builder("//slot").build())
            .prepare();

        ValidationMaterial validationMaterial = ValidationMaterial.builder()
            .revocationReferenceUris(List.of("urn:test:crl:one"))
            .build();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        PostSignatureRequest postSignature = request.completeSignature(signatureValue);
        byte[] timestampToken = timestampAuthority.timestamp(postSignature.getSignatureValueDigest());
        SignedDocument signed = postSignature.completeTimestamp(timestampToken, validationMaterial);

        assertTrue(signed.xml().contains("urn:test:crl:one"));
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void xadesCIncludesAdditionalCertificateReferencesFromValidationMaterial() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_C)
            .certificate(FakeRemoteSigner.certificate())
            .placementSelector(Selector.builder("//slot").build())
            .prepare();

        ValidationMaterial validationMaterial = ValidationMaterial.builder()
            .additionalCertificates(List.of(FakeRemoteSigner.certificate()))
            .build();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        PostSignatureRequest postSignature = request.completeSignature(signatureValue);
        byte[] timestampToken = timestampAuthority.timestamp(postSignature.getSignatureValueDigest());
        SignedDocument signed = postSignature.completeTimestamp(timestampToken, validationMaterial);

        assertTrue(countOccurrences(signed.xml(), "<xades:Cert>") == 3);
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void xadesXLIncludesEmbeddedValidationValues() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_X_L)
            .certificate(FakeRemoteSigner.certificate())
            .placementSelector(Selector.builder("//slot").build())
            .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        PostSignatureRequest postSignature = request.completeSignature(signatureValue);
        byte[] timestampToken = timestampAuthority.timestamp(postSignature.getSignatureValueDigest());
        SignedDocument signed = postSignature.completeTimestamp(timestampToken);

        assertTrue(signed.xml().contains("CertificateValues"));
        assertTrue(signed.xml().contains("EncapsulatedX509Certificate"));
        assertTrue(signed.xml().contains("RevocationValues"));
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void xadesXLIncludesCallerSuppliedEmbeddedValidationValues() throws Exception {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_X_L)
            .certificate(FakeRemoteSigner.certificate())
            .placementSelector(Selector.builder("//slot").build())
            .prepare();

        byte[] crlValue = new byte[] {4, 5, 6};
        ValidationMaterial validationMaterial = ValidationMaterial.builder()
            .additionalCertificates(List.of(FakeRemoteSigner.certificate()))
            .revocationValues(List.of(crlValue))
            .build();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        PostSignatureRequest postSignature = request.completeSignature(signatureValue);
        byte[] timestampToken = timestampAuthority.timestamp(postSignature.getSignatureValueDigest());
        SignedDocument signed = postSignature.completeTimestamp(timestampToken, validationMaterial);

        assertTrue(signed.xml().contains(Base64.getEncoder().encodeToString(FakeRemoteSigner.certificate().getEncoded())));
        assertTrue(signed.xml().contains(Base64.getEncoder().encodeToString(crlValue)));
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void xadesXLIncludesAdditionalCertificateReferencesFromValidationMaterial() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/><sig></sig></root>"))
            .signatureType(SignatureType.DETACHED)
            .profile(SignatureProfile.XADES_X_L)
            .certificate(FakeRemoteSigner.certificate())
            .targets(
                List.of(
                    TargetReference.of(Selector.builder("//slot").build(), 
                    ReferenceOptions.builder().transforms(List.of(Transform.of("http://www.w3.org/TR/2001/REC-xml-c14n-20010315"))).build())
                )
            )
            .placementSelector(Selector.builder("//sig").build())
            .prepare();

        ValidationMaterial validationMaterial = ValidationMaterial.builder()
            .additionalCertificates(List.of(FakeRemoteSigner.certificate()))
            .build();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        PostSignatureRequest postSignature = request.completeSignature(signatureValue);
        byte[] timestampToken = timestampAuthority.timestamp(postSignature.getSignatureValueDigest());
        SignedDocument signed = postSignature.completeTimestamp(timestampToken, validationMaterial);

        assertTrue(countOccurrences(signed.xml(), "<xades:Cert>") == 3);
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    private int countOccurrences(String text, String token) {
        return text.split(token, -1).length - 1;
    }
}
