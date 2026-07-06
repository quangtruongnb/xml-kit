package com.truongnq.xmlkit.profile.xades;

import com.truongnq.xmlkit.api.PreparedSignature;
import com.truongnq.xmlkit.api.ValidationMaterial;
import com.truongnq.xmlkit.core.DigestEngine;
import java.security.cert.X509Certificate;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class XAdESCBuilder extends AbstractXAdESProfileBuilder {
    public XAdESCBuilder(DigestEngine digestEngine, String prefix) {
        super(digestEngine, prefix);
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
        unsignedSignatureProperties.appendChild(buildCompleteCertificateRefs(document, prepared, validationMaterial));
        unsignedSignatureProperties.appendChild(buildCompleteRevocationRefs(document, validationMaterial));
        appendLongTermProperties(document, unsignedSignatureProperties, prepared, validationMaterial);
        unsignedProperties.appendChild(unsignedSignatureProperties);
        qualifyingProperties.appendChild(unsignedProperties);
    }

    protected void appendLongTermProperties(
        Document document,
        Element unsignedSignatureProperties,
        PreparedSignature prepared,
        ValidationMaterial validationMaterial
    ) {
    }

    protected Element buildCompleteCertificateRefs(
        Document document,
        PreparedSignature prepared,
        ValidationMaterial validationMaterial
    ) {
        Element completeCertificateRefs = super.buildCompleteCertificateRefs(document, prepared, certificateDigest(prepared.certificate()));
        Element certRefs = (Element) completeCertificateRefs.getFirstChild();
        for (X509Certificate certificate : validationMaterial.additionalCertificates()) {
            certRefs.appendChild(buildCertificateRef(document, certificate, certificateDigest(certificate)));
        }
        return completeCertificateRefs;
    }

}
