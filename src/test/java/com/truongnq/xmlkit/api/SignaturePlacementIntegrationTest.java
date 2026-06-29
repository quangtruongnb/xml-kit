package com.truongnq.xmlkit.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.model.SignatureType;
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
    void detachedPlacementAttachesDetachedSignatureArtifactToTargetNode() {
        SignedDocument signed = sign(SignatureType.DETACHED, "<root><container/></root>", "//container");

        assertEquals(List.of("Signature"), TestXml.childNames(signed.document(), "/root/container"));
        assertTrue(signed.xml().contains("URI=\"#detached-content\""));
    }

    private SignedDocument sign(SignatureType signatureType, String xml, String placementXPath) {
        return XmlSignatureBuilder.forDocument(TestXml.document(xml))
            .signatureType(signatureType)
            .profile(SignatureProfile.XMLDSIG)
            .placementXPath(placementXPath)
            .prepare()
            .complete(new byte[] {1, 2, 3});
    }
}
