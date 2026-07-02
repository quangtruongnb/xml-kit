package com.truongnq.xmlkit.core;

import com.truongnq.xmlkit.api.PreparedSignature;
import com.truongnq.xmlkit.api.SignedDocument;
import com.truongnq.xmlkit.api.ValidationMaterial;
import com.truongnq.xmlkit.exception.SignatureAssemblyException;
import com.truongnq.xmlkit.model.SignatureType;
import com.truongnq.xmlkit.profile.ProfileObjectBuilderFactory;
import java.util.Base64;
import java.util.List;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public final class SignatureAssembler {
    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";

    private final DigestEngine digestEngine;
    private final ProfileObjectBuilderFactory profileObjectBuilderFactory;
    private final String prefix;

    public SignatureAssembler(DigestEngine digestEngine, String prefix) {
        this.digestEngine = digestEngine;
        this.profileObjectBuilderFactory = new ProfileObjectBuilderFactory(digestEngine, prefix);
        this.prefix = prefix;
    }

    private String qName(String localName) {
        return prefix != null && !prefix.isEmpty() ? prefix + ":" + localName : localName;
    }

    public SignedDocument assemble(PreparedSignature prepared, byte[] signatureValue) {
        return assemble(prepared, signatureValue, null);
    }

    public SignedDocument assemble(PreparedSignature prepared, byte[] signatureValue, byte[] timestampToken) {
        return assemble(prepared, signatureValue, timestampToken, ValidationMaterial.empty());
    }

    public SignedDocument assemble(
        PreparedSignature prepared,
        byte[] signatureValue,
        byte[] timestampToken,
        ValidationMaterial validationMaterial
    ) {
        Document document = prepared.document();
        Element signature = document.createElementNS(DS_NS, qName("Signature"));
        signature.appendChild(prepared.signedInfo().element());
        signature.appendChild(textElement(document, DS_NS, qName("SignatureValue"), digestEngine.base64(signatureValue)));
        signature.appendChild(buildKeyInfo(document, prepared));
        Element profileObject = profileObjectBuilderFactory
            .forProfile(prepared.profile())
            .buildProfileObject(prepared, timestampToken, validationMaterial);
        if (profileObject != null) {
            signature.appendChild(profileObject);
        }
        placeSignature(prepared, signature);
        return new SignedDocument(document);
    }



    private void placeSignature(PreparedSignature prepared, Element signature) {
        Node target = prepared.placementTarget();
        SignatureType signatureType = prepared.signatureType();
        switch (signatureType) {
            case ENVELOPED -> target.appendChild(signature);
            case DETACHED -> {
                Node parent = target.getParentNode();
                if (parent != null) {
                    parent.insertBefore(signature, target.getNextSibling());
                } else {
                    target.appendChild(signature);
                }
            }
            case ENVELOPING -> {
                appendEnvelopingObjects(prepared, signature, target.getOwnerDocument());
                target.appendChild(signature);
            }
        }
    }

    private void appendEnvelopingObjects(PreparedSignature prepared, Element signature, Document document) {
        List<Node> payloadTargets = prepared.payloadTargets();
        List<ReferenceData> references = prepared.signedInfo().references();
        for (int index = 0; index < payloadTargets.size(); index++) {
            Element object = document.createElementNS(DS_NS, qName("Object"));
            String refUri = references.get(index).uri();
            if (refUri != null && refUri.startsWith("#")) {
                object.setAttribute("Id", refUri.substring(1));
            } else {
                object.setAttribute("Id", "id-" + java.util.UUID.randomUUID().toString());
            }
            object.appendChild(document.importNode(payloadTargets.get(index), true));
            signature.appendChild(object);
        }
    }

    private Element buildKeyInfo(Document document, PreparedSignature prepared) {
        try {
            Element keyInfo = document.createElementNS(DS_NS, qName("KeyInfo"));
            Element x509Data = document.createElementNS(DS_NS, qName("X509Data"));
            Element x509Certificate = textElement(
                document,
                DS_NS,
                qName("X509Certificate"),
                Base64.getEncoder().encodeToString(prepared.certificate().getEncoded())
            );
            x509Data.appendChild(x509Certificate);
            keyInfo.appendChild(x509Data);
            return keyInfo;
        } catch (Exception exception) {
            throw new SignatureAssemblyException("Unable to encode X.509 certificate.", exception);
        }
    }

    private Element textElement(Document document, String namespace, String qualifiedName, String value) {
        Element element = document.createElementNS(namespace, qualifiedName);
        element.setTextContent(value);
        return element;
    }
}
