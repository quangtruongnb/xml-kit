package com.truongnq.xmlkit.profile.xades;

import com.truongnq.xmlkit.api.PreparedSignature;
import com.truongnq.xmlkit.api.ValidationMaterial;
import com.truongnq.xmlkit.core.DigestEngine;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public final class XAdESTBuilder extends AbstractXAdESProfileBuilder {
    private final DigestEngine digestEngine;

    public XAdESTBuilder(DigestEngine digestEngine, String prefix) {
        super(prefix);
        this.digestEngine = digestEngine;
    }

    @Override
    protected void appendUnsignedProperties(
        Document document,
        Element qualifyingProperties,
        PreparedSignature prepared,
        byte[] timestampToken,
        ValidationMaterial validationMaterial
    ) {
        if (timestampToken == null) {
            return;
        }

        Element unsignedProperties = document.createElementNS(XADES_NS, "xades:UnsignedProperties");
        Element unsignedSignatureProperties = document.createElementNS(XADES_NS, "xades:UnsignedSignatureProperties");
        unsignedSignatureProperties.appendChild(buildTimestamp(document, digestEngine.base64(timestampToken)));
        unsignedProperties.appendChild(unsignedSignatureProperties);
        qualifyingProperties.appendChild(unsignedProperties);
    }
}
