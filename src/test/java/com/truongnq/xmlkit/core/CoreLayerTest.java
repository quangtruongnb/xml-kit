package com.truongnq.xmlkit.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.truongnq.xmlkit.model.CanonicalizationMethod;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureType;
import com.truongnq.xmlkit.testing.TestXml;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

class CoreLayerTest {
    @Test
    void canonicalizationEngineRetainsAncestorNamespacesForInclusiveC14n() {
        Document document = TestXml.document(
            "<env:Envelope xmlns:env='urn:env' xmlns:keep='urn:keep' xmlns:unused='urn:unused'>" +
                "<env:Body><keep:Payload Id='p1'>value</keep:Payload></env:Body>" +
            "</env:Envelope>"
        );

        byte[] bytes = new CanonicalizationEngine().canonicalize(
            document.getDocumentElement().getFirstChild().getFirstChild(),
            CanonicalizationMethod.C14N_INCLUSIVE
        );
        String xml = new String(bytes, StandardCharsets.UTF_8);

        assertTrue(xml.contains("xmlns:keep=\"urn:keep\""));
        assertTrue(xml.contains("xmlns:unused=\"urn:unused\""));
    }

    @Test
    void canonicalizationEngineOmitsUnusedAncestorNamespacesForExclusiveC14n() {
        Document document = TestXml.document(
            "<env:Envelope xmlns:env='urn:env' xmlns:keep='urn:keep' xmlns:unused='urn:unused'>" +
                "<env:Body><keep:Payload Id='p1'>value</keep:Payload></env:Body>" +
            "</env:Envelope>"
        );

        byte[] bytes = new CanonicalizationEngine().canonicalize(
            document.getDocumentElement().getFirstChild().getFirstChild(),
            CanonicalizationMethod.C14N_EXCLUSIVE
        );
        String xml = new String(bytes, StandardCharsets.UTF_8);

        assertTrue(xml.contains("xmlns:keep=\"urn:keep\""));
        assertFalse(xml.contains("xmlns:unused=\"urn:unused\""));
    }

    @Test
    void canonicalizationEngineSerializesXmlNodes() {
        Document document = TestXml.document("<root><child attr='1'>value</child></root>");

        byte[] bytes = new CanonicalizationEngine().canonicalize(
            document.getDocumentElement(),
            CanonicalizationMethod.C14N_INCLUSIVE
        );

        assertArrayEquals("<root><child attr=\"1\">value</child></root>".getBytes(StandardCharsets.UTF_8), bytes);
    }

    @Test
    void referenceBuilderCreatesDetachedReferenceDigest() {
        Document document = TestXml.document("<root><payload>abc</payload></root>");
        Element payload = (Element) document.getDocumentElement().getFirstChild();

        ReferenceData reference = new ReferenceBuilder(new DigestEngine(), new CanonicalizationEngine(), "ds").build(
            document,
            payload,
            SignatureType.DETACHED,
            DigestAlgorithm.SHA256,
            CanonicalizationMethod.C14N_INCLUSIVE,
            null,
            null
        );

        assertTrue(reference.uri().startsWith("#id-"));
        assertEquals(DigestAlgorithm.SHA256.uri(), reference.digestMethodUri());
        assertTrue(reference.digestValue().length() > 0);
    }

    @Test
    void detachedReferenceUsesPayloadNodeDigestInsteadOfWholeDocumentDigest() {
        Document document = TestXml.document("<root><payload>abc</payload><other>zzz</other></root>");
        Element payload = (Element) document.getDocumentElement().getFirstChild();
        DigestEngine digestEngine = new DigestEngine();
        CanonicalizationEngine canonicalizationEngine = new CanonicalizationEngine();

        ReferenceData reference = new ReferenceBuilder(digestEngine, canonicalizationEngine, "ds").build(
            document,
            payload,
            SignatureType.DETACHED,
            DigestAlgorithm.SHA256,
            CanonicalizationMethod.C14N_INCLUSIVE,
            null,
            null
        );

        String payloadDigest = digestEngine.digestBase64(
            DigestAlgorithm.SHA256,
            canonicalizationEngine.canonicalize(payload, CanonicalizationMethod.C14N_INCLUSIVE)
        );
        String wholeDocumentDigest = digestEngine.digestBase64(
            DigestAlgorithm.SHA256,
            canonicalizationEngine.canonicalize(document.getDocumentElement(), CanonicalizationMethod.C14N_INCLUSIVE)
        );

        assertEquals(payloadDigest, reference.digestValue());
        assertFalse(wholeDocumentDigest.equals(reference.digestValue()));
    }

    @Test
    void signedInfoBuilderDelegatesToReferenceBuilder() {
        Document document = TestXml.document("<root><payload>abc</payload></root>");
        ReferenceData fixedReference = new ReferenceData("custom-uri", "custom-digest-method", "custom-digest-value", java.util.List.of());
        SignedInfoBuilder builder = new SignedInfoBuilder(
            new ReferenceBuilder(new DigestEngine(), new CanonicalizationEngine(), "ds") {
                @Override
                public ReferenceData build(
                    Document ignoredDocument,
                    org.w3c.dom.Node ignoredPayloadNode,
                    SignatureType ignoredSignatureType,
                    DigestAlgorithm ignoredDigestAlgorithm,
                    CanonicalizationMethod ignoredCanonicalizationMethod,
                    String ignoredClientReferenceId,
                    List<String> ignoredCustomTransformUris
                ) {
                    return fixedReference;
                }
            },
            new CanonicalizationEngine(),
            "ds"
        );

        SignedInfoData signedInfo = builder.build(
            document,
            List.of(document.getDocumentElement()),
            SignatureType.ENVELOPED,
            DigestAlgorithm.SHA256,
            CanonicalizationMethod.C14N_INCLUSIVE,
            Collections.singletonList(null),
            Collections.singletonList(null),
            null
        );

        assertEquals("custom-uri", signedInfo.references().getFirst().uri());
        assertEquals("custom-digest-method", signedInfo.references().getFirst().digestMethodUri());
        assertEquals("custom-digest-value", signedInfo.references().getFirst().digestValue());
    }
}
