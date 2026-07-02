package com.truongnq.xmlkit.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.truongnq.xmlkit.core.CanonicalizationEngine;
import com.truongnq.xmlkit.core.DigestEngine;
import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.model.SignatureType;
import com.truongnq.xmlkit.testing.TestCertificates;
import com.truongnq.xmlkit.testing.TestXml;
import java.util.List;
import org.junit.jupiter.api.Test;

class SignaturePlacementIntegrationTest {
    @Test
    void envelopedPlacementUsesResolvedTargetNode() {
        SignedDocument signed = sign(SignatureType.ENVELOPED, "<root><before/><slot/><after/></root>", "//slot");

        assertEquals(List.of("Signature"), TestXml.childNames(signed.document(), "/root/slot"));
    }

    @Test
    void envelopingPlacementAttachesEnvelopeToTargetNode() {
        SignedDocument signed = sign(SignatureType.ENVELOPING, "<root><container/></root>", "//container");

        assertEquals(List.of("Signature"), TestXml.childNames(signed.document(), "/root/container"));
        assertTrue(signed.xml().contains("Object"));
    }

    @Test
    void envelopingSignedInfoDigestBindsToReferencedObjectElement() {
        String xml = "<root><container><payload>abc</payload></container></root>";
        SignedDocument signed = sign(SignatureType.ENVELOPING, xml, "//container");
        DigestEngine digestEngine = new DigestEngine();
        CanonicalizationEngine canonicalizationEngine = new CanonicalizationEngine();
        org.w3c.dom.Document signedDocument = TestXml.document(signed.xml());
        org.w3c.dom.Node objectNode = findFirstByLocalName(signedDocument.getDocumentElement(), "Object");
        String expectedDigest = digestEngine.digestBase64(
            com.truongnq.xmlkit.model.DigestAlgorithm.SHA256,
            canonicalizationEngine.canonicalize(
                objectNode,
                com.truongnq.xmlkit.model.CanonicalizationMethod.C14N_INCLUSIVE
            )
        );

        assertTrue(signed.xml().contains("URI=\"#id-"));
        assertTrue(signed.xml().contains("<ds:DigestValue>" + expectedDigest + "</ds:DigestValue>"));
    }

    @Test
    void detachedPlacementAttachesDetachedSignatureArtifactAsSiblingOfTargetNode() {
        SignedDocument signed = sign(SignatureType.DETACHED, "<root><container/></root>", "//container");

        assertEquals(List.of("container", "Signature"), TestXml.childNames(signed.document(), "/root"));
        assertTrue(signed.xml().contains("URI=\"#id-"));
    }

    @Test
    void detachedSignedInfoDigestBindsToPlacementPayloadNode() {
        String xml = "<root><container><payload>abc</payload></container><other>zzz</other></root>";
        SignedDocument signed = sign(SignatureType.DETACHED, xml, "//container/payload");
        DigestEngine digestEngine = new DigestEngine();
        CanonicalizationEngine canonicalizationEngine = new CanonicalizationEngine();
        
        org.w3c.dom.Document signedDocument = TestXml.document(signed.xml());
        org.w3c.dom.Element actualPayload = (org.w3c.dom.Element) signedDocument.getDocumentElement().getFirstChild().getFirstChild();
        String id = actualPayload.getAttribute("Id");
        
        org.w3c.dom.Document expectedDocument = TestXml.document(xml);
        org.w3c.dom.Element expectedPayload = (org.w3c.dom.Element) expectedDocument.getDocumentElement().getFirstChild().getFirstChild();
        expectedPayload.setAttribute("Id", id);
        
        String expectedDigest = digestEngine.digestBase64(
            com.truongnq.xmlkit.model.DigestAlgorithm.SHA256,
            canonicalizationEngine.canonicalize(
                expectedPayload,
                com.truongnq.xmlkit.model.CanonicalizationMethod.C14N_INCLUSIVE
            )
        );

        assertTrue(signed.xml().contains("<ds:DigestValue>" + expectedDigest + "</ds:DigestValue>"));
    }

    @Test
    void detachedSignatureAssignsReferenceIdToPayloadNode() {
        SignedDocument signed = sign(
            SignatureType.DETACHED,
            "<root><container><payload>abc</payload></container></root>",
            "//container/payload"
        );

        assertTrue(signed.xml().matches("(?s).*<payload Id=\"id-.*\">abc.*"));
        assertTrue(signed.xml().contains("URI=\"#id-"));
    }

    @Test
    void detachedMultiTargetProducesMultipleReferencesInCallerOrder() {
        SignedDocument signed = XmlSignatureBuilder.forDocument(
                TestXml.document("<root><container><first>abc</first><second>xyz</second></container><slot/></root>"))
            .signatureType(SignatureType.DETACHED)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(TestCertificates.certificate())
            .placementXPath(XPathLocation.builder("//slot").build())
            .targetXPaths(List.of(
                XPathLocation.builder("//second").referenceId("second-ref").build(),
                XPathLocation.builder("//first").referenceId("first-ref").build()))
            .prepare()
            .complete(new byte[] {1, 2, 3});

        assertTrue(signed.xml().indexOf("URI=\"#second-ref\"") < signed.xml().indexOf("URI=\"#first-ref\""));
    }

    @Test
    void envelopingMultiTargetCreatesOneObjectPerTarget() {
        SignedDocument signed = XmlSignatureBuilder.forDocument(
                TestXml.document("<root><payloadA>abc</payloadA><payloadB>xyz</payloadB><container/></root>"))
            .signatureType(SignatureType.ENVELOPING)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(TestCertificates.certificate())
            .placementXPath(XPathLocation.builder("//container").build())
            .addTargetXPath(XPathLocation.builder("//payloadA").referenceId("obj-a").build())
            .addTargetXPath(XPathLocation.builder("//payloadB").referenceId("obj-b").build())
            .prepare()
            .complete(new byte[] {1, 2, 3});

        assertTrue(signed.xml().contains("URI=\"#obj-a\""));
        assertTrue(signed.xml().contains("URI=\"#obj-b\""));
        assertEquals(2, countByLocalName(TestXml.document(signed.xml()).getDocumentElement(), "Object"));
    }

    private SignedDocument sign(SignatureType signatureType, String xml, String placementXPath) {
        return XmlSignatureBuilder.forDocument(TestXml.document(xml))
            .signatureType(signatureType)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(TestCertificates.certificate())
            .placementXPath(XPathLocation.builder(placementXPath).build())
            .prepare()
            .complete(new byte[] {1, 2, 3});
    }

    private org.w3c.dom.Node findFirstByLocalName(org.w3c.dom.Node node, String localName) {
        if (localName.equals(node.getLocalName())) {
            return node;
        }
        for (int index = 0; index < node.getChildNodes().getLength(); index++) {
            org.w3c.dom.Node match = findFirstByLocalName(node.getChildNodes().item(index), localName);
            if (match != null) {
                return match;
            }
        }
        return null;
    }

    private int countByLocalName(org.w3c.dom.Node node, String localName) {
        int count = localName.equals(node.getLocalName()) ? 1 : 0;
        for (int index = 0; index < node.getChildNodes().getLength(); index++) {
            count += countByLocalName(node.getChildNodes().item(index), localName);
        }
        return count;
    }
}
