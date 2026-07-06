package com.truongnq.xmlkit.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.truongnq.xmlkit.core.TransformEngine;
import com.truongnq.xmlkit.core.DigestEngine;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.model.SignatureType;
import com.truongnq.xmlkit.testing.FakeRemoteSigner;
import com.truongnq.xmlkit.testing.TestXml;
import com.truongnq.xmlkit.testing.XmlSignatureVerifier;
import java.util.List;
import org.junit.jupiter.api.Test;

class SignaturePlacementIntegrationTest {
    private final FakeRemoteSigner remoteSigner = new FakeRemoteSigner();

    private record SignResult(SignedDocument document, byte[] digestToSign) {}

    @Test
    void envelopedPlacementUsesResolvedTargetNode() {
        SignResult result = sign(SignatureType.ENVELOPED, "<root><before/><slot/><after/></root>", "//slot");

        assertEquals(List.of("Signature"), TestXml.childNames(result.document().document(), "/root/slot"));
        assertTrue(XmlSignatureVerifier.verify(result.document(), result.digestToSign()));
    }

    @Test
    void envelopingPlacementAttachesEnvelopeToTargetNode() {
        SignResult result = sign(SignatureType.ENVELOPING, "<root><container/></root>", "//container");

        assertEquals(List.of("Signature"), TestXml.childNames(result.document().document(), "/root/container"));
        assertTrue(result.document().xml().contains("Object"));
        assertTrue(XmlSignatureVerifier.verify(result.document(), result.digestToSign()));
    }

    @Test
    void envelopingSignedInfoDigestBindsToReferencedObjectElement() {
        String xml = "<root><container><payload>abc</payload></container></root>";
        SignResult result = sign(SignatureType.ENVELOPING, xml, "//container");
        DigestEngine digestEngine = new DigestEngine();
        TransformEngine canonicalizationEngine = new TransformEngine();
        org.w3c.dom.Document signedDocument = TestXml.document(result.document().xml());
        org.w3c.dom.Node objectNode = findFirstByLocalName(signedDocument.getDocumentElement(), "Object");
        String expectedDigest = digestEngine.digestBase64(
            com.truongnq.xmlkit.model.DigestAlgorithm.SHA256,
            canonicalizationEngine.transform(
                objectNode,
                com.truongnq.xmlkit.model.CanonicalizationMethod.C14N_INCLUSIVE.uri()
            )
        );

        assertTrue(result.document().xml().contains("URI=\"#id-"));
        assertTrue(result.document().xml().contains("<ds:DigestValue>" + expectedDigest + "</ds:DigestValue>"));
        assertTrue(XmlSignatureVerifier.verify(result.document(), result.digestToSign()));
    }

    @Test
    void detachedPlacementAttachesDetachedSignatureArtifactAsSiblingOfTargetNode() {
        SignResult result = sign(SignatureType.DETACHED, "<root><container/></root>", "//container");

        assertEquals(List.of("container", "Signature"), TestXml.childNames(result.document().document(), "/root"));
        assertTrue(result.document().xml().contains("URI=\"#id-"));
        assertTrue(XmlSignatureVerifier.verify(result.document(), result.digestToSign()));
    }

    @Test
    void detachedSignedInfoDigestBindsToPlacementPayloadNode() {
        String xml = "<root><container><payload>abc</payload></container><other>zzz</other></root>";
        SignResult result = sign(SignatureType.DETACHED, xml, "//container/payload");
        DigestEngine digestEngine = new DigestEngine();
        TransformEngine canonicalizationEngine = new TransformEngine();
        
        org.w3c.dom.Document signedDocument = TestXml.document(result.document().xml());
        org.w3c.dom.Element actualPayload = (org.w3c.dom.Element) signedDocument.getDocumentElement().getFirstChild().getFirstChild();
        String id = actualPayload.getAttribute("Id");
        
        org.w3c.dom.Document expectedDocument = TestXml.document(xml);
        org.w3c.dom.Element expectedPayload = (org.w3c.dom.Element) expectedDocument.getDocumentElement().getFirstChild().getFirstChild();
        expectedPayload.setAttribute("Id", id);
        
        String expectedDigest = digestEngine.digestBase64(
            com.truongnq.xmlkit.model.DigestAlgorithm.SHA256,
            canonicalizationEngine.transform(
                expectedPayload,
                com.truongnq.xmlkit.model.CanonicalizationMethod.C14N_INCLUSIVE.uri()
            )
        );

        assertTrue(result.document().xml().contains("<ds:DigestValue>" + expectedDigest + "</ds:DigestValue>"));
        assertTrue(XmlSignatureVerifier.verify(result.document(), result.digestToSign()));
    }

    @Test
    void detachedSignatureAssignsReferenceIdToPayloadNode() {
        SignResult result = sign(
            SignatureType.DETACHED,
            "<root><container><payload>abc</payload></container></root>",
            "//container/payload"
        );

        assertTrue(result.document().xml().matches("(?s).*<payload Id=\"id-.*\">abc.*"));
        assertTrue(result.document().xml().contains("URI=\"#id-"));
        assertTrue(XmlSignatureVerifier.verify(result.document(), result.digestToSign()));
    }

    @Test
    void detachedMultiTargetProducesMultipleReferencesInCallerOrder() {
        SigningRequest request = XmlSignatureBuilder.forDocument(
                TestXml.document("<root><container><first>abc</first><second>xyz</second></container><slot/></root>"))
            .signatureType(SignatureType.DETACHED)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(FakeRemoteSigner.certificate())
            .placementSelector(Selector.builder("//slot").build())
            .targets(List.of(
                TargetReference.of(
                    Selector.builder("//second").build(),
                    ReferenceOptions.builder().referenceId("second-ref").build()),
                TargetReference.of(
                    Selector.builder("//first").build(),
                    ReferenceOptions.builder().referenceId("first-ref").build())))
            .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        assertTrue(signed.xml().indexOf("URI=\"#second-ref\"") < signed.xml().indexOf("URI=\"#first-ref\""));
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    @Test
    void envelopingMultiTargetCreatesOneObjectPerTarget() {
        SigningRequest request = XmlSignatureBuilder.forDocument(
                TestXml.document("<root><payloadA>abc</payloadA><payloadB>xyz</payloadB><container/></root>"))
            .signatureType(SignatureType.ENVELOPING)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(FakeRemoteSigner.certificate())
            .placementSelector(Selector.builder("//container").build())
            .addTarget(Selector.builder("//payloadA").build(), ReferenceOptions.builder().referenceId("obj-a").build())
            .addTarget(Selector.builder("//payloadB").build(), ReferenceOptions.builder().referenceId("obj-b").build())
            .prepare();

        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        SignedDocument signed = request.complete(signatureValue);

        assertTrue(signed.xml().contains("URI=\"#obj-a\""));
        assertTrue(signed.xml().contains("URI=\"#obj-b\""));
        assertEquals(2, countByLocalName(TestXml.document(signed.xml()).getDocumentElement(), "Object"));
        assertTrue(XmlSignatureVerifier.verify(signed, request.getDigestToSign()));
    }

    private SignResult sign(SignatureType signatureType, String xml, String placementXPath) {
        SigningRequest request = XmlSignatureBuilder.forDocument(TestXml.document(xml))
            .signatureType(signatureType)
            .profile(SignatureProfile.XMLDSIG)
            .certificate(FakeRemoteSigner.certificate())
            .placementSelector(Selector.builder(placementXPath).build())
            .prepare();
        byte[] signatureValue = remoteSigner.sign(request.getDigestToSign(), DigestAlgorithm.SHA256);
        return new SignResult(request.complete(signatureValue), request.getDigestToSign());
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
