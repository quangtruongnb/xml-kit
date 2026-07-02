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
                        .placementSelector(Selector.builder("//slot").build())
                        .prepare());
    }

    @Test
    void xmldsigFlowSupportsRemoteSignerRoundTrip() {
        FakeRemoteSigner remoteSigner = new FakeRemoteSigner();
        SigningRequest request = XmlSignatureBuilder.forDocument(TestXml.document("<root><slot/></root>"))
                .signatureType(SignatureType.ENVELOPED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(TestCertificates.certificate())
                .placementSelector(Selector.builder("//slot").build())
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
                .targets(List.of(TargetReference.of(Selector.builder("//slot").build())))
                .placementSelector(Selector.builder("//demo").build())
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
                .addTarget(Selector.builder("//slot").build())
                .addTarget(Selector.builder("//slot2").build())
                .placementSelector(Selector.builder("//demo").build())
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
                .placementSelector(Selector.builder("//slot").build())
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
                .placementSelector(Selector.builder("//slot").build())
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
                .targets(List.of(TargetReference.of(Selector.builder("//slot").build())))
                .placementSelector(Selector.builder("//demo").build())
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

    @Test
    void detachedSignatureWithSignedGenericObject() {
        FakeRemoteSigner remoteSigner = new FakeRemoteSigner();
        org.w3c.dom.Document doc = TestXml.document("<root><slot>payload</slot><demo/></root>");
        org.w3c.dom.Element customData = doc.createElement("CustomData");
        customData.setTextContent("evidence-content");

        SigningRequest request = XmlSignatureBuilder.forDocument(doc)
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(TestCertificates.certificate())
                .targets(List.of(TargetReference.of(Selector.builder("//slot").build())))
                .placementSelector(Selector.builder("//demo").build())
                .addSignatureObject(SignatureObject.builder(customData)
                        .id("evidence-obj")
                        .includeInSignedInfo(true)
                        .build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        String xml = signed.xml();
        assertTrue(remoteSigner.verify(signatureValue, request.getDigestToSign(), DigestAlgorithm.SHA256));
        assertTrue(xml.contains("URI=\"#evidence-obj\""), "SignedInfo should reference the Object");
        assertTrue(xml.contains("Id=\"evidence-obj\""), "Object should have the Id");
        assertTrue(xml.contains("<CustomData>evidence-content</CustomData>"));
        assertTrue(xml.contains(Base64.getEncoder().encodeToString(signatureValue)));

        System.out.println("Detached with signed generic object:\n" + xml);
    }

    @Test
    void detachedSignatureWithUnsignedGenericObject() {
        FakeRemoteSigner remoteSigner = new FakeRemoteSigner();
        org.w3c.dom.Document doc = TestXml.document("<root><slot>payload</slot><demo/></root>");
        org.w3c.dom.Element metadata = doc.createElement("Metadata");
        metadata.setTextContent("decoration-only");

        SigningRequest request = XmlSignatureBuilder.forDocument(doc)
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(TestCertificates.certificate())
                .targets(List.of(TargetReference.of(Selector.builder("//slot").build())))
                .placementSelector(Selector.builder("//demo").build())
                .addSignatureObject(SignatureObject.builder(metadata)
                        .includeInSignedInfo(false)
                        .build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        String xml = signed.xml();
        assertTrue(remoteSigner.verify(signatureValue, request.getDigestToSign(), DigestAlgorithm.SHA256));
        assertTrue(xml.contains("<Metadata>decoration-only</Metadata>"));
        assertFalse(xml.contains("URI=\"#Metadata\""), "Unsigned object should not be referenced in SignedInfo");

        System.out.println("Detached with unsigned generic object:\n" + xml);
    }

    @Test
    void detachedSignatureWithSignaturePropertiesAndExplicitSignatureId() {
        FakeRemoteSigner remoteSigner = new FakeRemoteSigner();
        org.w3c.dom.Document doc = TestXml.document("<root><slot>payload</slot><demo/></root>");
        org.w3c.dom.Element signingTime = doc.createElement("SigningTime");
        signingTime.setTextContent("2026-07-02T21:00:00Z");
        org.w3c.dom.Element signerRole = doc.createElement("SignerRole");
        signerRole.setTextContent("Approver");

        SigningRequest request = XmlSignatureBuilder.forDocument(doc)
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(TestCertificates.certificate())
                .signatureId("sig-001")
                .targets(List.of(TargetReference.of(Selector.builder("//slot").build())))
                .placementSelector(Selector.builder("//demo").build())
                .addSignatureObject(SignatureObject.signatureProperties()
                        .id("sig-props")
                        .addProperty("prop-time", signingTime)
                        .addProperty("prop-role", signerRole)
                        .includeInSignedInfo(true)
                        .build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        String xml = signed.xml();
        assertTrue(remoteSigner.verify(signatureValue, request.getDigestToSign(), DigestAlgorithm.SHA256));
        assertTrue(xml.contains("Id=\"sig-001\""), "Signature should have explicit Id");
        assertTrue(xml.contains("Id=\"sig-props\""), "Object should have Id");
        assertTrue(xml.contains("URI=\"#sig-props\""), "SignedInfo should reference the properties object");
        assertTrue(xml.contains("Target=\"#sig-001\""), "SignatureProperty should target the Signature");
        assertTrue(xml.contains("Id=\"prop-time\""), "First property should have Id");
        assertTrue(xml.contains("Id=\"prop-role\""), "Second property should have Id");
        assertTrue(xml.contains("<SigningTime>2026-07-02T21:00:00Z</SigningTime>"));
        assertTrue(xml.contains("<SignerRole>Approver</SignerRole>"));
        assertTrue(xml.contains("SignatureProperties"));

        System.out.println("Detached with SignatureProperties (explicit signatureId):\n" + xml);
    }

    @Test
    void envelopedSignatureWithAutoGeneratedSignatureId() {
        FakeRemoteSigner remoteSigner = new FakeRemoteSigner();
        org.w3c.dom.Document doc = TestXml.document("<root><slot/></root>");
        org.w3c.dom.Element info = doc.createElement("Info");
        info.setTextContent("auto-id-test");

        SigningRequest request = XmlSignatureBuilder.forDocument(doc)
                .signatureType(SignatureType.ENVELOPED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(TestCertificates.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .addSignatureObject(SignatureObject.signatureProperties()
                        .addProperty("p1", info)
                        .includeInSignedInfo(false)
                        .build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        String xml = signed.xml();
        assertTrue(remoteSigner.verify(signatureValue, request.getDigestToSign(), DigestAlgorithm.SHA256));
        assertTrue(xml.matches("(?s).*Signature[^>]+Id=\"id-[^\"]+\".*"), "Signature should have auto-generated Id");
        assertTrue(xml.contains("Target=\"#id-"), "SignatureProperty should target auto-generated Signature Id");
        assertTrue(xml.contains("<Info>auto-id-test</Info>"));

        System.out.println("Enveloped with auto-generated signatureId:\n" + xml);
    }

    @Test
    void xadesTFlowWithSignatureProperties() {
        FakeRemoteSigner remoteSigner = new FakeRemoteSigner();
        FakeTimestampAuthority timestampAuthority = new FakeTimestampAuthority();
        org.w3c.dom.Document doc = TestXml.document("<root><slot>payload</slot><demo/></root>");
        org.w3c.dom.Element signingTime = doc.createElement("SigningTime");
        signingTime.setTextContent("2026-07-02T21:00:00Z");

        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(doc)
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XADES_T)
                .certificate(TestCertificates.certificate())
                .signatureId("xades-sig")
                .targets(List.of(TargetReference.of(Selector.builder("//slot").build())))
                .placementSelector(Selector.builder("//demo").build())
                .addSignatureObject(SignatureObject.signatureProperties()
                        .id("xades-props")
                        .addProperty("ts-prop", signingTime)
                        .includeInSignedInfo(true)
                        .build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        PostSignatureRequest postSignature = request.completeSignature(signatureValue);
        byte[] timestampToken = timestampAuthority.timestamp(postSignature.getSignatureValueDigest());
        SignedDocument signed = postSignature.completeTimestamp(timestampToken);

        String xml = signed.xml();
        assertTrue(remoteSigner.verify(signatureValue, request.getDigestToSign(), DigestAlgorithm.SHA256));
        // XAdES profile object
        assertTrue(xml.contains("QualifyingProperties"), "Should have XAdES profile object");
        assertTrue(xml.contains("EncapsulatedTimeStamp"), "Should have timestamp");
        // SignatureObject additions
        assertTrue(xml.contains("Id=\"xades-sig\""), "Signature should have Id");
        assertTrue(xml.contains("URI=\"#xades-props\""), "SignedInfo should reference properties");
        assertTrue(xml.contains("Target=\"#xades-sig\""), "Property should target Signature");
        assertTrue(xml.contains("<SigningTime>2026-07-02T21:00:00Z</SigningTime>"));

        System.out.println("XAdES-T with SignatureProperties:\n" + xml);
    }

    @Test
    void envelopingSignatureWithMixedSignedAndUnsignedObjects() {
        FakeRemoteSigner remoteSigner = new FakeRemoteSigner();
        org.w3c.dom.Document doc = TestXml
                .document("<root><container><data>enveloping-content</data></container></root>");
        org.w3c.dom.Element signedExtra = doc.createElement("SignedExtra");
        signedExtra.setTextContent("signed-content");
        org.w3c.dom.Element unsignedExtra = doc.createElement("UnsignedExtra");
        unsignedExtra.setTextContent("unsigned-content");

        SigningRequest request = XmlSignatureBuilder.forDocument(doc)
                .signatureType(SignatureType.ENVELOPING)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(TestCertificates.certificate())
                .placementSelector(Selector.builder("//container").build())
                .addSignatureObject(SignatureObject.builder(signedExtra)
                        .id("extra-signed")
                        .includeInSignedInfo(true)
                        .build())
                .addSignatureObject(SignatureObject.builder(unsignedExtra)
                        .includeInSignedInfo(false)
                        .build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        String xml = signed.xml();
        assertTrue(remoteSigner.verify(signatureValue, request.getDigestToSign(), DigestAlgorithm.SHA256));
        // Enveloping payload object
        assertTrue(xml.contains("<data>enveloping-content</data>"), "Should contain enveloped payload");
        // Signed extra object
        assertTrue(xml.contains("URI=\"#extra-signed\""), "SignedInfo should reference extra signed object");
        assertTrue(xml.contains("<SignedExtra>signed-content</SignedExtra>"));
        // Unsigned extra object
        assertTrue(xml.contains("<UnsignedExtra>unsigned-content</UnsignedExtra>"));

        System.out.println("Enveloping with mixed signed/unsigned objects:\n" + xml);
    }

    @Test
    void multipleSignatureObjectsWithRemoteSignerRoundTrip() {
        FakeRemoteSigner remoteSigner = new FakeRemoteSigner();
        org.w3c.dom.Document doc = TestXml.document("<root><slot>payload</slot><demo/></root>");
        org.w3c.dom.Element signingTime = doc.createElement("SigningTime");
        signingTime.setTextContent("2026-07-02T21:00:00Z");
        org.w3c.dom.Element evidence = doc.createElement("Evidence");
        evidence.setTextContent("evidence-data");
        org.w3c.dom.Element audit = doc.createElement("AuditTrail");
        audit.setTextContent("unsigned-audit");

        SigningRequest request = XmlSignatureBuilder.forDocument(doc)
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(TestCertificates.certificate())
                .signatureId("multi-sig")
                .targets(List.of(TargetReference.of(Selector.builder("//slot").build())))
                .placementSelector(Selector.builder("//demo").build())
                .addSignatureObject(SignatureObject.signatureProperties()
                        .id("props-obj")
                        .addProperty("time-prop", signingTime)
                        .includeInSignedInfo(true)
                        .build())
                .addSignatureObject(SignatureObject.builder(evidence)
                        .id("evidence-obj")
                        .includeInSignedInfo(true)
                        .build())
                .addSignatureObject(SignatureObject.builder(audit)
                        .includeInSignedInfo(false)
                        .build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        String xml = signed.xml();
        assertTrue(remoteSigner.verify(signatureValue, request.getDigestToSign(), DigestAlgorithm.SHA256));
        // 3 references: payload + 2 signed objects
        assertTrue(xml.contains("URI=\"#props-obj\""), "Properties object should be referenced");
        assertTrue(xml.contains("URI=\"#evidence-obj\""), "Evidence object should be referenced");
        // All objects present
        assertTrue(xml.contains("Target=\"#multi-sig\""), "Property should target Signature");
        assertTrue(xml.contains("<SigningTime>2026-07-02T21:00:00Z</SigningTime>"));
        assertTrue(xml.contains("<Evidence>evidence-data</Evidence>"));
        assertTrue(xml.contains("<AuditTrail>unsigned-audit</AuditTrail>"));
        // Order preserved
        assertTrue(xml.indexOf("Id=\"props-obj\"") < xml.indexOf("Id=\"evidence-obj\""),
                "Objects should appear in builder-call order");

        System.out.println("Multiple objects with remote signer:\n" + xml);

    }
}
