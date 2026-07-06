package com.truongnq.xmlkit.core;

import com.truongnq.xmlkit.model.CanonicalizationMethod;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureType;
import com.truongnq.xmlkit.model.Transform;
import java.util.ArrayList;
import java.util.List;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public final class SignedInfoBuilder {
    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String XPATH_URI = "http://www.w3.org/TR/1999/REC-xpath-19991116";

    private final ReferenceBuilder referenceBuilder;
    private final TransformEngine transformEngine;
    private final String prefix;

    public SignedInfoBuilder(DigestEngine digestEngine, String prefix) {
        this(new ReferenceBuilder(digestEngine, new TransformEngine(), prefix), new TransformEngine(), prefix);
    }

    public SignedInfoBuilder(ReferenceBuilder referenceBuilder, TransformEngine transformEngine, String prefix) {
        this.referenceBuilder = referenceBuilder;
        this.transformEngine = transformEngine;
        this.prefix = prefix;
    }

    private String qName(String localName) {
        return prefix != null && !prefix.isEmpty() ? prefix + ":" + localName : localName;
    }

    public SignedInfoData build(
        Document document,
        List<Node> payloadNodes,
        SignatureType signatureType,
        DigestAlgorithm digestAlgorithm,
        CanonicalizationMethod canonicalizationMethod,
        List<String> referenceIds,
        List<List<Transform>> referenceTransforms,
        List<ReferenceData> additionalReferences
    ) {
        List<ReferenceData> references = new ArrayList<>();
        for (int index = 0; index < payloadNodes.size(); index++) {
            references.add(referenceBuilder.build(
                document,
                payloadNodes.get(index),
                signatureType,
                digestAlgorithm,
                canonicalizationMethod,
                referenceIds.get(index),
                referenceTransforms.get(index)
            ));
        }
        if (additionalReferences != null) {
            references.addAll(additionalReferences);
        }

        Element signedInfoElement = buildSignedInfoElement(
            document,
            canonicalizationMethod,
            digestAlgorithm,
            references
        );
        // Exclusive C14N on a detached element requires visibly-utilized namespace
        // declarations to be explicitly present. createElementNS creates the binding
        // implicitly, but Apache XML Security's C14N may not render it unless it
        // appears as an explicit xmlns attribute. Set it so the canonicalized output
        // matches what third-party validators (e.g. Python signxml) expect.
        if (prefix != null && !prefix.isEmpty()) {
            signedInfoElement.setAttributeNS(
                "http://www.w3.org/2000/xmlns/", "xmlns:" + prefix, DS_NS);
        } else {
            signedInfoElement.setAttributeNS(
                "http://www.w3.org/2000/xmlns/", "xmlns", DS_NS);
        }
        byte[] canonicalizedBytes = transformEngine.transform(signedInfoElement, canonicalizationMethod.uri());

        return new SignedInfoData(
            List.copyOf(references),
            canonicalizationMethod.uri(),
            digestAlgorithm.signatureMethodUri(),
            signedInfoElement,
            canonicalizedBytes
        );
    }

    private Element buildSignedInfoElement(
        Document document,
        CanonicalizationMethod canonicalizationMethod,
        DigestAlgorithm digestAlgorithm,
        List<ReferenceData> references
    ) {
        Element root = document.createElementNS(DS_NS, qName("SignedInfo"));
        Element canonicalization = document.createElementNS(DS_NS, qName("CanonicalizationMethod"));
        canonicalization.setAttribute("Algorithm", canonicalizationMethod.uri());
        root.appendChild(canonicalization);

        Element signatureMethod = document.createElementNS(DS_NS, qName("SignatureMethod"));
        signatureMethod.setAttribute("Algorithm", digestAlgorithm.signatureMethodUri());
        root.appendChild(signatureMethod);

        for (ReferenceData referenceData : references) {
            Element reference = document.createElementNS(DS_NS, qName("Reference"));
            reference.setAttribute("URI", referenceData.uri());
            root.appendChild(reference);

            if (!referenceData.transforms().isEmpty()) {
                Element transformsElem = document.createElementNS(DS_NS, qName("Transforms"));
                for (Transform t : referenceData.transforms()) {
                    Element transformElem = document.createElementNS(DS_NS, qName("Transform"));
                    transformElem.setAttribute("Algorithm", t.uri());
                    if (XPATH_URI.equals(t.uri()) && t.xpathExpression() != null) {
                        Element xpathElem = document.createElementNS(DS_NS, qName("XPath"));
                        xpathElem.setTextContent(t.xpathExpression());
                        transformElem.appendChild(xpathElem);
                    }
                    transformsElem.appendChild(transformElem);
                }
                reference.appendChild(transformsElem);
            }

            Element digestMethod = document.createElementNS(DS_NS, qName("DigestMethod"));
            digestMethod.setAttribute("Algorithm", referenceData.digestMethodUri());
            reference.appendChild(digestMethod);

            Element digestValue = document.createElementNS(DS_NS, qName("DigestValue"));
            digestValue.setTextContent(referenceData.digestValue());
            reference.appendChild(digestValue);
        }

        return root;
    }
}
