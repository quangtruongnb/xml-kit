package com.truongnq.xmlkit.testing;

import com.truongnq.xmlkit.api.*;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.model.SignatureType;
import com.truongnq.xmlkit.model.Transform;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Generates signed XML files for cross-verification with the Python signxml verifier.
 * Each test writes its output to test-scripts/ for external validation.
 */
class PythonVerifierExportTest {
    private static final Path OUTPUT_DIR = Path.of("test-scripts/generated");
    private final FakeRemoteSigner remoteSigner = new FakeRemoteSigner();
    private final FakeTimestampAuthority timestampAuthority = new FakeTimestampAuthority();

    private void writeXml(String name, String xml) throws Exception {
        Files.createDirectories(OUTPUT_DIR);
        Files.writeString(OUTPUT_DIR.resolve(name + ".xml"), xml);
    }

    @Test
    void envelopedXmldsig() throws Exception {
        SigningRequest request = XmlSignatureBuilder.forDocument(TestXml.document("<root><slot/></root>"))
                .signatureType(SignatureType.ENVELOPED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(FakeRemoteSigner.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);
        writeXml("01_enveloped_xmldsig", signed.xml());
    }

    @Test
    void detachedXmldsig() throws Exception {
        SigningRequest request = XmlSignatureBuilder
                .forDocument(TestXml.document("<root><slot>1</slot><demo/></root>"))
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(FakeRemoteSigner.certificate())
                .targets(List.of(TargetReference.of(Selector.builder("//slot").build())))
                .placementSelector(Selector.builder("//demo").build())
                .prefix("")
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);
        writeXml("02_detached_xmldsig", signed.xml());
    }

    @Test
    void detachedXmldsig2Targets() throws Exception {
        SigningRequest request = XmlSignatureBuilder
                .forDocument(TestXml.document("<root><slot>1</slot><slot2>2</slot2><demo/></root>"))
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(FakeRemoteSigner.certificate())
                .addTarget(Selector.builder("//slot").build())
                .addTarget(Selector.builder("//slot2").build())
                .placementSelector(Selector.builder("//demo").build())
                .prefix("")
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);
        writeXml("03_detached_xmldsig_2targets", signed.xml());
    }

    @Test
    void envelopedXadesBes() throws Exception {
        SigningRequest request = XmlSignatureBuilder.forDocument(TestXml.document("<root><slot/></root>"))
                .signatureType(SignatureType.ENVELOPED)
                .profile(SignatureProfile.XADES_BES)
                .certificate(FakeRemoteSigner.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);
        writeXml("04_enveloped_xades_bes", signed.xml());
    }

    @Test
    void envelopedXadesT() throws Exception {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
                .signatureType(SignatureType.ENVELOPED)
                .profile(SignatureProfile.XADES_T)
                .certificate(FakeRemoteSigner.certificate())
                .placementSelector(Selector.builder("//slot").build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        PostSignatureRequest postSignature = request.completeSignature(signatureValue);
        byte[] timestampToken = timestampAuthority.timestamp(postSignature.getSignatureValueDigest());
        SignedDocument signed = postSignature.completeTimestamp(timestampToken);
        writeXml("05_enveloped_xades_t", signed.xml());
    }

    @Test
    void detachedXadesT() throws Exception {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot>1</slot><demo/></root>"))
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XADES_T)
                .certificate(FakeRemoteSigner.certificate())
                .targets(List.of(TargetReference.of(Selector.builder("//slot").build())))
                .placementSelector(Selector.builder("//demo").build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        PostSignatureRequest postSignature = request.completeSignature(signatureValue);
        byte[] timestampToken = timestampAuthority.timestamp(postSignature.getSignatureValueDigest());
        SignedDocument signed = postSignature.completeTimestamp(timestampToken);
        writeXml("06_detached_xades_t", signed.xml());
    }

    @Test
    void xadesC() throws Exception {
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
        writeXml("07_enveloped_xades_c", signed.xml());
    }

    @Test
    void xadesXL() throws Exception {
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
        writeXml("08_enveloped_xades_xl", signed.xml());
    }

    @Test
    void detachedWithSignedObject() throws Exception {
        org.w3c.dom.Document doc = TestXml.document("<root><slot>payload</slot><demo/></root>");
        org.w3c.dom.Element customData = doc.createElement("CustomData");
        customData.setTextContent("evidence-content");

        SigningRequest request = XmlSignatureBuilder.forDocument(doc)
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(FakeRemoteSigner.certificate())
                .targets(List.of(TargetReference.of(Selector.builder("//slot").build())))
                .placementSelector(Selector.builder("//demo").build())
                .addSignatureObject(SignatureObject.builder(customData)
                        .id("evidence-obj")
                        .includeInSignedInfo(true)
                        .build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);
        writeXml("09_detached_signed_object", signed.xml());
    }

    @Test
    void detachedWithSignatureProperties() throws Exception {
        org.w3c.dom.Document doc = TestXml.document("<root><slot>payload</slot><demo/></root>");
        org.w3c.dom.Element signingTime = doc.createElement("SigningTime");
        signingTime.setTextContent("2026-07-02T21:00:00Z");

        SigningRequest request = XmlSignatureBuilder.forDocument(doc)
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(FakeRemoteSigner.certificate())
                .signatureId("sig-001")
                .targets(List.of(TargetReference.of(Selector.builder("//slot").build())))
                .placementSelector(Selector.builder("//demo").build())
                .addSignatureObject(SignatureObject.signatureProperties()
                        .id("sig-props")
                        .addProperty("prop-time", signingTime)
                        .includeInSignedInfo(true)
                        .build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);
        writeXml("10_detached_signature_properties", signed.xml());
    }

    @Test
    void envelopingWithMixedObjects() throws Exception {
        org.w3c.dom.Document doc = TestXml
                .document("<root><container><data>enveloping-content</data></container></root>");
        org.w3c.dom.Element signedExtra = doc.createElement("SignedExtra");
        signedExtra.setTextContent("signed-content");
        org.w3c.dom.Element unsignedExtra = doc.createElement("UnsignedExtra");
        unsignedExtra.setTextContent("unsigned-content");

        SigningRequest request = XmlSignatureBuilder.forDocument(doc)
                .signatureType(SignatureType.ENVELOPING)
                .profile(SignatureProfile.XMLDSIG)
                .certificate(FakeRemoteSigner.certificate())
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
        writeXml("11_enveloping_mixed_objects", signed.xml());
    }

    @Test
    void multipleSignatureObjects() throws Exception {
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
                .certificate(FakeRemoteSigner.certificate())
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
        writeXml("12_multiple_signature_objects", signed.xml());
    }

    @Test
    void detachedXadesXL() throws Exception {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/><sig></sig></root>"))
                .signatureType(SignatureType.DETACHED)
                .profile(SignatureProfile.XADES_X_L)
                .certificate(FakeRemoteSigner.certificate())
                .targets(List.of(
                    TargetReference.of(Selector.builder("//slot").build(),
                    ReferenceOptions.builder().transforms(
                        List.of(Transform.of("http://www.w3.org/TR/2001/REC-xml-c14n-20010315"))
                    ).build())
                ))
                .placementSelector(Selector.builder("//sig").build())
                .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        PostSignatureRequest postSignature = request.completeSignature(signatureValue);
        byte[] timestampToken = timestampAuthority.timestamp(postSignature.getSignatureValueDigest());
        SignedDocument signed = postSignature.completeTimestamp(timestampToken);
        writeXml("13_detached_xades_xl", signed.xml());
    }
}
