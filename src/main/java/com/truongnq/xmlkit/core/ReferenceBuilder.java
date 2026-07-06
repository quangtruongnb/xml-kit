package com.truongnq.xmlkit.core;

import com.truongnq.xmlkit.model.CanonicalizationMethod;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureType;
import com.truongnq.xmlkit.model.Transform;
import java.util.List;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import static com.truongnq.xmlkit.model.SignatureType.ENVELOPED;

public class ReferenceBuilder {
    private final DigestEngine digestEngine;
    private final TransformEngine transformEngine;
    private final String prefix;

    public ReferenceBuilder(DigestEngine digestEngine, TransformEngine transformEngine, String prefix) {
        this.digestEngine = digestEngine;
        this.transformEngine = transformEngine;
        this.prefix = prefix;
    }

    private String qName(String localName) {
        return prefix != null && !prefix.isEmpty() ? prefix + ":" + localName : localName;
    }

    public ReferenceData build(
        Document document,
        Node payloadNode,
        SignatureType signatureType,
        DigestAlgorithm digestAlgorithm,
        CanonicalizationMethod canonicalizationMethod,
        String clientReferenceId,
        List<Transform> customTransforms
    ) {
        String dynamicId = clientReferenceId != null ? clientReferenceId : "id-" + java.util.UUID.randomUUID().toString();

        String referenceUri = switch (signatureType) {
            case ENVELOPED -> "";
            case DETACHED -> "#" + (payloadNode instanceof Element e && e.hasAttribute("Id") ? e.getAttribute("Id") : dynamicId);
            case ENVELOPING -> "#" + dynamicId;
        };

        Node resolvedPayloadNode = switch (signatureType) {
            case ENVELOPED -> document.getDocumentElement();
            case DETACHED -> payloadNode != null ? payloadNode : document.getDocumentElement();
            case ENVELOPING -> buildEnvelopingObjectNode(document, payloadNode, dynamicId);
        };

        List<Transform> transforms = transformsFor(signatureType, customTransforms);
        String referenceDigest = digestEngine.digestBase64(
            digestAlgorithm,
            transformEngine.transform(resolvedPayloadNode, transforms)
        );
        return new ReferenceData(referenceUri, digestAlgorithm.uri(), referenceDigest, transforms);
    }

    private Node buildEnvelopingObjectNode(Document document, Node payloadNode, String objectId) {
        Document detachedDocument = XmlSupport.newDocument();
        Element signature = detachedDocument.createElementNS("http://www.w3.org/2000/09/xmldsig#", qName("Signature"));
        String xmlnsAttr = prefix != null && !prefix.isEmpty() ? "xmlns:" + prefix : "xmlns";
        signature.setAttribute(xmlnsAttr, "http://www.w3.org/2000/09/xmldsig#");
        detachedDocument.appendChild(signature);
        Element object = detachedDocument.createElementNS("http://www.w3.org/2000/09/xmldsig#", qName("Object"));
        object.setAttribute("Id", objectId);
        Node payload = payloadNode == null ? document.getDocumentElement() : payloadNode;
        object.appendChild(detachedDocument.importNode(payload, true));
        signature.appendChild(object);
        return object;
    }

    private List<Transform> transformsFor(
        SignatureType signatureType,
        List<Transform> customTransforms
    ) {
        if (customTransforms != null) {
            return List.copyOf(customTransforms);
        }
        return switch (signatureType) {
            case ENVELOPED -> List.of(Transform.of("http://www.w3.org/2000/09/xmldsig#enveloped-signature"));
            case DETACHED -> List.of();
            case ENVELOPING -> List.of();
        };
    }
}
