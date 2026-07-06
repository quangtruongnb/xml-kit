package com.truongnq.xmlkit.profile.xades;

import com.truongnq.xmlkit.api.PreparedSignature;
import com.truongnq.xmlkit.api.ValidationMaterial;
import com.truongnq.xmlkit.core.DigestEngine;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public final class XAdESXLBuilder extends XAdESCBuilder {
    public XAdESXLBuilder(DigestEngine digestEngine, String prefix) {
        super(digestEngine, prefix);
    }

    @Override
    protected void appendLongTermProperties(
        Document document,
        Element unsignedSignatureProperties,
        PreparedSignature prepared,
        ValidationMaterial validationMaterial
    ) {
        unsignedSignatureProperties.appendChild(buildCertificateValues(document, prepared, validationMaterial));
        unsignedSignatureProperties.appendChild(buildRevocationValues(document, validationMaterial));
    }
}
