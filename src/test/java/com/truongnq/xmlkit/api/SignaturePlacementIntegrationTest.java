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

    private SignedDocument sign(SignatureType signatureType, String xml, String placementXPath) {
        return XmlSignatureBuilder.forDocument(TestXml.document(xml))
            .signatureType(signatureType)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(TestCertificates.certificate())
            .placementXPath(placementXPath)
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
}
