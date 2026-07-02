package com.truongnq.xmlkit.api;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.truongnq.xmlkit.exception.XmlKitException;

import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.model.SignatureType;
import com.truongnq.xmlkit.testing.FakeRemoteSigner;
import com.truongnq.xmlkit.testing.FakeTimestampAuthority;
import com.truongnq.xmlkit.testing.TestCertificates;
import com.truongnq.xmlkit.testing.TestXml;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

class RemoteSigningIntegrationTest {
    @Test
    void fakeRemoteSignerWrapsSha512DigestBeforeSigningWithTestCertificatePrivateKey() throws Exception {
        FakeRemoteSigner remoteSigner = new FakeRemoteSigner();
        byte[] digestToSign = MessageDigest.getInstance("SHA-512")
                .digest("digest-to-sign".getBytes());

        byte[] signatureValue = remoteSigner.sign(digestToSign, DigestAlgorithm.SHA512);

        assertTrue(remoteSigner.verify(signatureValue, digestToSign, DigestAlgorithm.SHA512));
    }

    @Test
    void prepareRequiresCertificate() {
        assertThrows(XmlKitException.class,
                () -> XmlSignatureBuilder.forDocument(TestXml.document("<root><slot/></root>"))
                        .signatureType(SignatureType.ENVELOPED)
                        .profile(SignatureProfile.XMLDSIG)
                        .placementXPath(XPathLocation.builder("//slot").build())
                        .prepare());
    }

    @Test
    void xmldsigFlowSupportsRemoteSignerRoundTrip() {
        FakeRemoteSigner remoteSigner = new FakeRemoteSigner();
        SigningRequest request = XmlSignatureBuilder.forDocument(TestXml.document("<root><slot/></root>"))
                .signatureType(SignatureType.ENVELOPED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(TestCertificates.certificate())
                .placementXPath(XPathLocation.builder("//slot").build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        assertArrayEquals(request.getDigestToSign(), remoteSigner.lastDigestToSign());
        assertTrue(signed.xml().contains(Base64.getEncoder().encodeToString(signatureValue)));
        assertTrue(signed.xml().contains("KeyInfo"));
        assertFalse(signed.xml().contains("UnsignedProperties"));
    }

    @Test
    void xmldsigFlowSupportsDetachedSignature() {

        long start = System.currentTimeMillis();

        FakeRemoteSigner remoteSigner = new FakeRemoteSigner();
        SigningRequest request = XmlSignatureBuilder
                .forDocument(TestXml.document("<root><slot>1</slot><demo/></root>"))
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(TestCertificates.certificate())
                .targetXPaths(List.of(XPathLocation.builder("//slot").build()))
                .placementXPath(XPathLocation.builder("//demo").build())
                .prefix("")
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        assertArrayEquals(request.getDigestToSign(), remoteSigner.lastDigestToSign());
        assertTrue(signed.xml().contains(Base64.getEncoder().encodeToString(signatureValue)));
        assertTrue(signed.xml().contains("KeyInfo"));
        assertFalse(signed.xml().contains("UnsignedProperties"));
        assertTrue(signed.xml().contains("id-"));

        System.out.println(signed.xml());

        System.out.println("Time: " + (System.currentTimeMillis() - start));
    }

    @Test
    void xmldsigFlowSupportsDetachedSignature2Tag() {

        long start = System.currentTimeMillis();

        FakeRemoteSigner remoteSigner = new FakeRemoteSigner();
        SigningRequest request = XmlSignatureBuilder
                .forDocument(TestXml.document("<root><slot>1</slot><slot2>2</slot2><demo/></root>"))
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(TestCertificates.certificate())
                .addTargetXPath(XPathLocation.builder("//slot").build())
                .addTargetXPath(XPathLocation.builder("//slot2").build())
                .placementXPath(XPathLocation.builder("//demo").build())
                .prefix("")
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        assertArrayEquals(request.getDigestToSign(), remoteSigner.lastDigestToSign());
        assertTrue(signed.xml().contains(Base64.getEncoder().encodeToString(signatureValue)));
        assertTrue(signed.xml().contains("KeyInfo"));
        assertFalse(signed.xml().contains("UnsignedProperties"));
        assertTrue(signed.xml().contains("id-"));

        System.out.println("Sign 2 tag:\n" + signed.xml());

        System.out.println("Time: " + (System.currentTimeMillis() - start));
    }

    @Test
    void xadesFlowSupportsRemoteSignerAndTimestampAuthorityRoundTrip() {
        FakeRemoteSigner remoteSigner = new FakeRemoteSigner();
        FakeTimestampAuthority timestampAuthority = new FakeTimestampAuthority();
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
                .signatureType(SignatureType.ENVELOPED)
                .profile(SignatureProfile.XADES_T)
                .certificate(TestCertificates.certificate())
                .placementXPath(XPathLocation.builder("//slot").build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        PostSignatureRequest postSignature = request.completeSignature(signatureValue);
        byte[] timestampToken = timestampAuthority.timestamp(postSignature.getSignatureValueDigest());
        SignedDocument signed = postSignature.completeTimestamp(timestampToken);

        assertArrayEquals(request.getDigestToSign(), remoteSigner.lastDigestToSign());
        assertArrayEquals(postSignature.getSignatureValueDigest(), timestampAuthority.lastDigest());
        assertTrue(signed.xml().contains(Base64.getEncoder().encodeToString(signatureValue)));
        assertTrue(signed.xml().contains(Base64.getEncoder().encodeToString(timestampToken)));
        assertTrue(signed.xml().contains("UnsignedProperties"));
        assertTrue(signed.xml().contains("EncapsulatedTimeStamp"));
    }

    @Test
    void xadesBesFlowSupportsRemoteSignerRoundTrip() {
        FakeRemoteSigner remoteSigner = new FakeRemoteSigner();
        SigningRequest request = XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
                .signatureType(SignatureType.ENVELOPED)
                .profile(SignatureProfile.XADES_BES)
                .certificate(TestCertificates.certificate())
                .placementXPath(XPathLocation.builder("//slot").build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        assertArrayEquals(request.getDigestToSign(), remoteSigner.lastDigestToSign());
        assertTrue(signed.xml().contains(Base64.getEncoder().encodeToString(signatureValue)));
        assertTrue(signed.xml().contains("QualifyingProperties"));
        assertTrue(signed.xml().contains("SignedProperties"));
        assertFalse(signed.xml().contains("UnsignedProperties"));

        System.out.println(signed.xml());
    }

    @Test
    void xadesTFlowSupportsDetachedSignature() {
        FakeRemoteSigner remoteSigner = new FakeRemoteSigner();
        FakeTimestampAuthority timestampAuthority = new FakeTimestampAuthority();
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot>1</slot><demo/></root>"))
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XADES_T)
                .certificate(TestCertificates.certificate())
                .targetXPaths(List.of(XPathLocation.builder("//slot").build()))
                .placementXPath(XPathLocation.builder("//demo").build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        PostSignatureRequest postSignature = request.completeSignature(signatureValue);
        byte[] timestampToken = timestampAuthority.timestamp(postSignature.getSignatureValueDigest());
        SignedDocument signed = postSignature.completeTimestamp(timestampToken);

        assertArrayEquals(request.getDigestToSign(), remoteSigner.lastDigestToSign());
        assertArrayEquals(postSignature.getSignatureValueDigest(), timestampAuthority.lastDigest());
        assertTrue(signed.xml().contains(Base64.getEncoder().encodeToString(signatureValue)));
        assertTrue(signed.xml().contains(Base64.getEncoder().encodeToString(timestampToken)));
        assertTrue(signed.xml().contains("UnsignedProperties"));
        assertTrue(signed.xml().contains("EncapsulatedTimeStamp"));
        assertTrue(signed.xml().contains("id-"));

        System.out.println("====");
        System.out.println(signed.xml());
    }
}
