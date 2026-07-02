package com.truongnq.xmlkit.core;

import com.truongnq.xmlkit.model.CanonicalizationMethod;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureType;
import java.util.List;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import static com.truongnq.xmlkit.model.SignatureType.ENVELOPED;

public class ReferenceBuilder {
    private final DigestEngine digestEngine;
    private final CanonicalizationEngine canonicalizationEngine;

    private final String prefix;

    public ReferenceBuilder(DigestEngine digestEngine, CanonicalizationEngine canonicalizationEngine, String prefix) {
        this.digestEngine = digestEngine;
        this.canonicalizationEngine = canonicalizationEngine;
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
        List<String> customTransformUris
    ) {
        String referenceUri;
        Node resolvedPayloadNode;
        String dynamicId = clientReferenceId != null ? clientReferenceId : "id-" + java.util.UUID.randomUUID().toString();

        if (signatureType == SignatureType.ENVELOPED) {
            referenceUri = "";
            resolvedPayloadNode = document.getDocumentElement();
        } else if (signatureType == SignatureType.DETACHED) {
            if (payloadNode instanceof Element element && element.hasAttribute("Id")) {
                referenceUri = "#" + element.getAttribute("Id");
            } else {
                referenceUri = "#" + dynamicId;
            }
            resolvedPayloadNode = payloadNode != null ? payloadNode : document.getDocumentElement();
        } else if (signatureType == SignatureType.ENVELOPING) {
            referenceUri = "#" + dynamicId;
            resolvedPayloadNode = buildEnvelopingObjectNode(document, payloadNode, dynamicId);
        } else {
            referenceUri = "";
            resolvedPayloadNode = document.getDocumentElement();
        }

        String referenceDigest = digestEngine.digestBase64(
            digestAlgorithm,
            canonicalizationEngine.canonicalize(resolvedPayloadNode, canonicalizationMethod)
        );
        return new ReferenceData(referenceUri, digestAlgorithm.uri(), referenceDigest, transformsFor(signatureType, customTransformUris));
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

    private List<String> transformsFor(SignatureType signatureType, List<String> customTransformUris) {
        if (customTransformUris != null) {
            return List.copyOf(customTransformUris);
        }
        if (signatureType == ENVELOPED) {
            return List.of("http://www.w3.org/2000/09/xmldsig#enveloped-signature");
        }
        return List.of();
    }
}
