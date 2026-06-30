package com.truongnq.xmlkit.core;

import com.truongnq.xmlkit.model.CanonicalizationMethod;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public final class SignedInfoBuilder {
    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    private final ReferenceBuilder referenceBuilder;
    private final CanonicalizationEngine canonicalizationEngine;

    private final String prefix;

    public SignedInfoBuilder(DigestEngine digestEngine, String prefix) {
        this(new ReferenceBuilder(digestEngine, new CanonicalizationEngine(), prefix), new CanonicalizationEngine(), prefix);
    }

    public SignedInfoBuilder(ReferenceBuilder referenceBuilder, CanonicalizationEngine canonicalizationEngine, String prefix) {
        this.referenceBuilder = referenceBuilder;
        this.canonicalizationEngine = canonicalizationEngine;
        this.prefix = prefix;
    }

    private String qName(String localName) {
        return prefix != null && !prefix.isEmpty() ? prefix + ":" + localName : localName;
    }

    public SignedInfoData build(
        Document document,
        Node payloadNode,
        SignatureType signatureType,
        DigestAlgorithm digestAlgorithm,
        CanonicalizationMethod canonicalizationMethod,
        String referenceId
    ) {
        ReferenceData referenceData = referenceBuilder.build(
            document,
            payloadNode,
            signatureType,
            digestAlgorithm,
            canonicalizationMethod,
            referenceId
        );

        Element signedInfoElement = buildSignedInfoElement(
            document,
            canonicalizationMethod,
            digestAlgorithm,
            referenceData
        );
        byte[] canonicalizedBytes = canonicalizationEngine.canonicalize(signedInfoElement, canonicalizationMethod);

        return new SignedInfoData(
            referenceData.uri(),
            referenceData.digestValue(),
            canonicalizationMethod.uri(),
            referenceData.digestMethodUri(),
            digestAlgorithm.signatureMethodUri(),
            referenceData.transformUris(),
            signedInfoElement,
            canonicalizedBytes
        );
    }

    private Element buildSignedInfoElement(Document document, CanonicalizationMethod canonicalizationMethod, DigestAlgorithm digestAlgorithm, ReferenceData referenceData) {
        Element root = document.createElementNS(DS_NS, qName("SignedInfo"));
        Element canonicalization = document.createElementNS(DS_NS, qName("CanonicalizationMethod"));
        canonicalization.setAttribute("Algorithm", canonicalizationMethod.uri());
        root.appendChild(canonicalization);

        Element signatureMethod = document.createElementNS(DS_NS, qName("SignatureMethod"));
        signatureMethod.setAttribute("Algorithm", digestAlgorithm.signatureMethodUri());
        root.appendChild(signatureMethod);

        Element reference = document.createElementNS(DS_NS, qName("Reference"));
        reference.setAttribute("URI", referenceData.uri());
        root.appendChild(reference);

        if (!referenceData.transformUris().isEmpty()) {
            Element transforms = document.createElementNS(DS_NS, qName("Transforms"));
            for (String transformUri : referenceData.transformUris()) {
                Element transform = document.createElementNS(DS_NS, qName("Transform"));
                transform.setAttribute("Algorithm", transformUri);
                transforms.appendChild(transform);
            }
            reference.appendChild(transforms);
        }

        Element digestMethod = document.createElementNS(DS_NS, qName("DigestMethod"));
        digestMethod.setAttribute("Algorithm", referenceData.digestMethodUri());
        reference.appendChild(digestMethod);

        Element digestValue = document.createElementNS(DS_NS, qName("DigestValue"));
        digestValue.setTextContent(referenceData.digestValue());
        reference.appendChild(digestValue);

        return root;
    }
}
