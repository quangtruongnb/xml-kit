package com.truongnq.xmlkit.core;

import com.truongnq.xmlkit.api.PreparedSignature;
import com.truongnq.xmlkit.api.SignedDocument;
import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.model.SignatureType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public final class SignatureAssembler {
    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String XADES_NS = "http://uri.etsi.org/01903/v1.3.2#";

    private final DigestEngine digestEngine;

    public SignatureAssembler(DigestEngine digestEngine) {
        this.digestEngine = digestEngine;
    }

    public SignedDocument assemble(PreparedSignature prepared, byte[] signatureValue) {
        return assemble(prepared, signatureValue, null);
    }

    public SignedDocument assemble(PreparedSignature prepared, byte[] signatureValue, byte[] timestampToken) {
        Document document = prepared.document();
        Element signature = document.createElementNS(DS_NS, "ds:Signature");
        signature.appendChild(buildSignedInfo(document, prepared.signedInfo()));
        signature.appendChild(textElement(document, DS_NS, "ds:SignatureValue", digestEngine.base64(signatureValue)));
        maybeAppendXadesObject(document, signature, prepared.profile(), timestampToken);
        placeSignature(prepared, signature);
        return new SignedDocument(document);
    }

    private Element buildSignedInfo(Document document, SignedInfoData signedInfo) {
        Element root = document.createElementNS(DS_NS, "ds:SignedInfo");
        Element canonicalization = document.createElementNS(DS_NS, "ds:CanonicalizationMethod");
        canonicalization.setAttribute("Algorithm", signedInfo.canonicalizationMethodUri());
        root.appendChild(canonicalization);

        Element signatureMethod = document.createElementNS(DS_NS, "ds:SignatureMethod");
        signatureMethod.setAttribute("Algorithm", signedInfo.signatureMethodUri());
        root.appendChild(signatureMethod);

        Element reference = document.createElementNS(DS_NS, "ds:Reference");
        reference.setAttribute("URI", signedInfo.referenceUri());
        root.appendChild(reference);

        Element digestMethod = document.createElementNS(DS_NS, "ds:DigestMethod");
        digestMethod.setAttribute("Algorithm", signedInfo.digestMethodUri());
        reference.appendChild(digestMethod);

        reference.appendChild(textElement(document, DS_NS, "ds:DigestValue", signedInfo.referenceDigestValue()));
        return root;
    }

    private void placeSignature(PreparedSignature prepared, Element signature) {
        Node target = prepared.placementTarget();
        SignatureType signatureType = prepared.signatureType();
        switch (signatureType) {
            case ENVELOPED, DETACHED -> target.appendChild(signature);
            case ENVELOPING -> {
                Element object = target.getOwnerDocument().createElementNS(DS_NS, "ds:Object");
                object.setAttribute("Id", "object-1");
                object.appendChild(target.getOwnerDocument().importNode(prepared.document().getDocumentElement(), true));
                signature.appendChild(object);
                target.appendChild(signature);
            }
        }
    }

    private void maybeAppendXadesObject(Document document, Element signature, SignatureProfile profile, byte[] timestampToken) {
        if (profile == SignatureProfile.XMLDSIG) {
            return;
        }

        Element object = document.createElementNS(DS_NS, "ds:Object");
        Element qualifyingProperties = document.createElementNS(XADES_NS, "xades:QualifyingProperties");
        object.appendChild(qualifyingProperties);

        Element signedProperties = document.createElementNS(XADES_NS, "xades:SignedProperties");
        qualifyingProperties.appendChild(signedProperties);
        signedProperties.appendChild(textElement(document, XADES_NS, "xades:Profile", profile.name()));

        if (profile.requiresTimestamp() && timestampToken != null) {
            Element unsignedProperties = document.createElementNS(XADES_NS, "xades:UnsignedProperties");
            Element unsignedSignatureProperties = document.createElementNS(XADES_NS, "xades:UnsignedSignatureProperties");
            Element signatureTimestamp = document.createElementNS(XADES_NS, "xades:SignatureTimeStamp");
            signatureTimestamp.appendChild(textElement(
                document,
                XADES_NS,
                "xades:EncapsulatedTimeStamp",
                digestEngine.base64(timestampToken)
            ));
            unsignedSignatureProperties.appendChild(signatureTimestamp);
            unsignedProperties.appendChild(unsignedSignatureProperties);
            qualifyingProperties.appendChild(unsignedProperties);
        }

        signature.appendChild(object);
    }

    private Element textElement(Document document, String namespace, String qualifiedName, String value) {
        Element element = document.createElementNS(namespace, qualifiedName);
        element.setTextContent(value);
        return element;
    }
}
