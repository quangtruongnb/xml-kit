package com.truongnq.xmlkit.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.truongnq.xmlkit.core.TransformEngine;
import com.truongnq.xmlkit.core.DigestEngine;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.model.SignatureType;
import com.truongnq.xmlkit.testing.FakeRemoteSigner;
import com.truongnq.xmlkit.testing.TestXml;
import com.truongnq.xmlkit.testing.XmlSignatureVerifier;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

class SignatureObjectIntegrationTest {
    private final FakeRemoteSigner remoteSigner = new FakeRemoteSigner();

    @Test
    void signedGenericObjectAppendsObjectAndReference() {
        Document doc = TestXml.document("<root><slot/></root>");
        Element content = doc.createElement("CustomData");
        content.setTextContent("hello");

        SigningRequest request = XmlSignatureBuilder.forDocument(doc)
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(FakeRemoteSigner.certificate())
            .placementSelector(Selector.builder("//slot").build())
            .addSignatureObject(SignatureObject.builder(content)
                .id("custom-obj-1")
                .includeInSignedInfo(true)
                .build())
            .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        assertTrue(signed.xml().contains("URI=\"#custom-obj-1\""));
        assertTrue(signed.xml().contains("Id=\"custom-obj-1\""));
        assertTrue(signed.xml().contains("<CustomData>hello</CustomData>"));
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void unsignedGenericObjectAppendsObjectWithoutReference() {
        Document doc = TestXml.document("<root><slot/></root>");
        Element content = doc.createElement("Metadata");
        content.setTextContent("info");

        SigningRequest request = XmlSignatureBuilder.forDocument(doc)
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(FakeRemoteSigner.certificate())
            .placementSelector(Selector.builder("//slot").build())
            .addSignatureObject(SignatureObject.builder(content)
                .includeInSignedInfo(false)
                .build())
            .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        assertTrue(signed.xml().contains("<Metadata>info</Metadata>"));
        assertTrue(signed.xml().contains("Object"));
        // No Reference URI pointing to the unsigned object
        org.w3c.dom.Document signedDoc = TestXml.document(signed.xml());
        int referenceCount = countByLocalName(signedDoc.getDocumentElement(), "Reference");
        // Only the payload reference, no additional reference for the unsigned object
        assertEquals(1, referenceCount);
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void signaturePropertiesBuildsCorrectStructure() {
        Document doc = TestXml.document("<root><slot/></root>");
        Element signingTime = doc.createElement("SigningTime");
        signingTime.setTextContent("2026-07-02T00:00:00Z");

        SigningRequest request = XmlSignatureBuilder.forDocument(doc)
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(FakeRemoteSigner.certificate())
            .signatureId("my-sig")
            .placementSelector(Selector.builder("//slot").build())
            .addSignatureObject(SignatureObject.signatureProperties()
                .id("sig-props")
                .addProperty("prop-1", signingTime)
                .includeInSignedInfo(true)
                .build())
            .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        String xml = signed.xml();
        assertTrue(xml.contains("Id=\"my-sig\""), "Signature should have Id attribute");
        assertTrue(xml.contains("Id=\"sig-props\""), "Object should have Id attribute");
        assertTrue(xml.contains("SignatureProperties"), "Should contain SignatureProperties element");
        assertTrue(xml.contains("Id=\"prop-1\""), "SignatureProperty should have Id attribute");
        assertTrue(xml.contains("Target=\"#my-sig\""), "SignatureProperty should target the Signature");
        assertTrue(xml.contains("<SigningTime>2026-07-02T00:00:00Z</SigningTime>"));
        assertTrue(xml.contains("URI=\"#sig-props\""), "SignedInfo should reference the Object");
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void signatureIdAutoGeneratedWhenPropertiesPresent() {
        Document doc = TestXml.document("<root><slot/></root>");
        Element content = doc.createElement("Info");
        content.setTextContent("test");

        SigningRequest request = XmlSignatureBuilder.forDocument(doc)
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(FakeRemoteSigner.certificate())
            .placementSelector(Selector.builder("//slot").build())
            .addSignatureObject(SignatureObject.signatureProperties()
                .addProperty("p1", content)
                .includeInSignedInfo(false)
                .build())
            .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        String xml = signed.xml();
        // Signature should have auto-generated Id because SignatureProperties is present
        assertTrue(xml.matches("(?s).*<ds:Signature[^>]+Id=\"id-[^\"]+\".*"), "Signature should have auto-generated Id");
        assertTrue(xml.contains("Target=\"#id-"), "SignatureProperty Target should reference auto-generated Id");
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void signatureIdExplicitlySet() {
        Document doc = TestXml.document("<root><slot/></root>");

        SigningRequest request = XmlSignatureBuilder.forDocument(doc)
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(FakeRemoteSigner.certificate())
            .signatureId("explicit-sig-id")
            .placementSelector(Selector.builder("//slot").build())
            .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        assertTrue(signed.xml().contains("Id=\"explicit-sig-id\""));
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void signedObjectDigestMatchesCanonicalizedObject() {
        Document doc = TestXml.document("<root><slot/></root>");
        Element content = doc.createElement("Payload");
        content.setTextContent("digest-test");

        SigningRequest request = XmlSignatureBuilder.forDocument(doc)
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(FakeRemoteSigner.certificate())
            .placementSelector(Selector.builder("//slot").build())
            .addSignatureObject(SignatureObject.builder(content)
                .id("digest-obj")
                .includeInSignedInfo(true)
                .build())
            .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        // Recompute the digest from the actual Object element in the signed output
        DigestEngine digestEngine = new DigestEngine();
        TransformEngine canonicalizationEngine = new TransformEngine();
        org.w3c.dom.Document signedDoc = TestXml.document(signed.xml());
        Node objectNode = findByAttribute(signedDoc.getDocumentElement(), "Object", "Id", "digest-obj");
        assertNotNull(objectNode, "Should find Object with Id=digest-obj");

        String expectedDigest = digestEngine.digestBase64(
            com.truongnq.xmlkit.model.DigestAlgorithm.SHA256,
            canonicalizationEngine.transform(
                objectNode,
                com.truongnq.xmlkit.model.CanonicalizationMethod.C14N_INCLUSIVE.uri()
            )
        );
        assertTrue(signed.xml().contains("<ds:DigestValue>" + expectedDigest + "</ds:DigestValue>"),
            "Digest in SignedInfo should match the canonicalized Object");
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void multipleObjectsPreserveOrder() {
        Document doc = TestXml.document("<root><slot/></root>");
        Element first = doc.createElement("First");
        first.setTextContent("1");
        Element second = doc.createElement("Second");
        second.setTextContent("2");

        SigningRequest request = XmlSignatureBuilder.forDocument(doc)
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(FakeRemoteSigner.certificate())
            .placementSelector(Selector.builder("//slot").build())
            .addSignatureObject(SignatureObject.builder(first)
                .id("obj-first")
                .includeInSignedInfo(true)
                .build())
            .addSignatureObject(SignatureObject.builder(second)
                .id("obj-second")
                .includeInSignedInfo(false)
                .build())
            .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        String xml = signed.xml();
        assertTrue(xml.indexOf("Id=\"obj-first\"") < xml.indexOf("Id=\"obj-second\""),
            "Objects should appear in builder-call order");
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void existingEnvelopingFlowUnchanged() {
        Document doc = TestXml.document("<root><container/></root>");

        SigningRequest request = XmlSignatureBuilder.forDocument(doc)
            .signatureType(SignatureType.ENVELOPING)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(FakeRemoteSigner.certificate())
            .placementSelector(Selector.builder("//container").build())
            .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        assertTrue(signed.xml().contains("Object"));
        assertNull(findAttribute(TestXml.document(signed.xml()).getDocumentElement(), "Signature", "Id"),
            "Signature should not have Id when not explicitly set and no properties");
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    private Node findByAttribute(Node node, String localName, String attrName, String attrValue) {
        if (localName.equals(node.getLocalName()) && node instanceof Element element
                && attrValue.equals(element.getAttribute(attrName))) {
            return node;
        }
        for (int i = 0; i < node.getChildNodes().getLength(); i++) {
            Node match = findByAttribute(node.getChildNodes().item(i), localName, attrName, attrValue);
            if (match != null) {
                return match;
            }
        }
        return null;
    }

    private String findAttribute(Node node, String localName, String attrName) {
        if (localName.equals(node.getLocalName()) && node instanceof Element element) {
            return element.hasAttribute(attrName) ? element.getAttribute(attrName) : null;
        }
        for (int i = 0; i < node.getChildNodes().getLength(); i++) {
            String result = findAttribute(node.getChildNodes().item(i), localName, attrName);
            if (result != null) {
                return result;
            }
        }
        return null;
    }

    private int countByLocalName(Node node, String localName) {
        int count = localName.equals(node.getLocalName()) ? 1 : 0;
        for (int i = 0; i < node.getChildNodes().getLength(); i++) {
            count += countByLocalName(node.getChildNodes().item(i), localName);
        }
        return count;
    }
}
