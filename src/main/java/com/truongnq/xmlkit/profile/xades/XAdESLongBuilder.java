package com.truongnq.xmlkit.profile.xades;

import com.truongnq.xmlkit.api.PreparedSignature;
import com.truongnq.xmlkit.api.ValidationMaterial;
import com.truongnq.xmlkit.core.DigestEngine;
import com.truongnq.xmlkit.exception.SignatureAssemblyException;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureProfile;
import java.security.cert.X509Certificate;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public final class XAdESLongBuilder extends AbstractXAdESProfileBuilder {
    private final DigestEngine digestEngine;

    public XAdESLongBuilder(DigestEngine digestEngine, String prefix) {
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
        unsignedSignatureProperties.appendChild(buildCompleteCertificateRefs(document, prepared, validationMaterial));
        unsignedSignatureProperties.appendChild(buildCompleteRevocationRefs(document, validationMaterial));

        if (prepared.profile() == SignatureProfile.XADES_X_L) {
            unsignedSignatureProperties.appendChild(buildCertificateValues(document, prepared, validationMaterial));
            unsignedSignatureProperties.appendChild(buildRevocationValues(document, validationMaterial));
        }

        unsignedProperties.appendChild(unsignedSignatureProperties);
        qualifyingProperties.appendChild(unsignedProperties);
    }

    private Element buildCompleteCertificateRefs(
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

    private String certificateDigest(X509Certificate certificate) {
        try {
            return digestEngine.digestBase64(DigestAlgorithm.SHA256, certificate.getEncoded());
        } catch (Exception exception) {
            throw new SignatureAssemblyException("Unable to build XAdES certificate references.", exception);
        }
    }
}
