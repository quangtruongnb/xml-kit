package com.truongnq.xmlkit.profile.xades;

import static com.truongnq.xmlkit.core.XmlDsigConstants.*;

import com.truongnq.xmlkit.api.PreparedSignature;
import com.truongnq.xmlkit.api.ValidationMaterial;
import com.truongnq.xmlkit.core.DigestEngine;
import com.truongnq.xmlkit.core.XmlNaming;
import com.truongnq.xmlkit.exception.SignatureAssemblyException;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.profile.ProfileObjectBuilder;
import java.security.cert.X509Certificate;
import java.util.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

abstract class AbstractXAdESProfileBuilder implements ProfileObjectBuilder {
    protected final DigestEngine digestEngine;
    protected final XmlNaming naming;

    protected AbstractXAdESProfileBuilder(DigestEngine digestEngine, String prefix) {
        this.digestEngine = digestEngine;
        this.naming = new XmlNaming(prefix);
    }

    @Override
    public final Element buildProfileObject(PreparedSignature prepared, byte[] timestampToken, ValidationMaterial validationMaterial) {
        Document document = prepared.document();
        Element object = document.createElementNS(DS_NS, naming.qName("Object"));

        Element qualifyingProperties = document.createElementNS(XADES_NS, "xades:QualifyingProperties");
        if (prepared.signatureId() != null) {
            qualifyingProperties.setAttribute("Target", "#" + prepared.signatureId());
        }
        object.appendChild(qualifyingProperties);

        Element signedProperties = document.createElementNS(XADES_NS, "xades:SignedProperties");
        qualifyingProperties.appendChild(signedProperties);
        Element signedSignatureProperties = document.createElementNS(XADES_NS, "xades:SignedSignatureProperties");
        signedSignatureProperties.appendChild(buildSigningCertificate(document, prepared));
        signedProperties.appendChild(signedSignatureProperties);

        appendUnsignedProperties(document, qualifyingProperties, prepared, timestampToken, validationMaterial);
        return object;
    }

    private Element buildSigningCertificate(Document document, PreparedSignature prepared) {
        String certDigest = certificateDigest(prepared.certificate());
        Element signingCertificate = document.createElementNS(XADES_NS, "xades:SigningCertificate");
        signingCertificate.appendChild(buildCertificateRef(document, prepared.certificate(), certDigest));
        return signingCertificate;
    }

    protected String certificateDigest(X509Certificate certificate) {
        try {
            return digestEngine.digestBase64(DigestAlgorithm.SHA256, certificate.getEncoded());
        } catch (Exception exception) {
            throw new SignatureAssemblyException("Unable to compute certificate digest.", exception);
        }
    }

    protected void appendUnsignedProperties(
        Document document,
        Element qualifyingProperties,
        PreparedSignature prepared,
        byte[] timestampToken,
        ValidationMaterial validationMaterial
    ) {
    }

    protected Element textElement(Document document, String namespace, String qualifiedName, String value) {
        Element element = document.createElementNS(namespace, qualifiedName);
        element.setTextContent(value);
        return element;
    }

    protected Element buildTimestamp(Document document, String encodedTimestamp) {
        Element signatureTimestamp = document.createElementNS(XADES_NS, "xades:SignatureTimeStamp");
        signatureTimestamp.appendChild(textElement(document, XADES_NS, "xades:EncapsulatedTimeStamp", encodedTimestamp));
        return signatureTimestamp;
    }

    protected Element buildCompleteCertificateRefs(Document document, PreparedSignature prepared, String certificateDigest) {
        Element completeCertificateRefs = document.createElementNS(XADES_NS, "xades:CompleteCertificateRefs");
        Element certRefs = document.createElementNS(XADES_NS, "xades:CertRefs");
        certRefs.appendChild(buildCertificateRef(document, prepared.certificate(), certificateDigest));
        completeCertificateRefs.appendChild(certRefs);
        return completeCertificateRefs;
    }

    protected Element buildCertificateRef(Document document, X509Certificate certificate, String certificateDigest) {
        Element cert = document.createElementNS(XADES_NS, "xades:Cert");
        Element certDigest = document.createElementNS(XADES_NS, "xades:CertDigest");
        Element digestMethod = document.createElementNS(DS_NS, naming.qName("DigestMethod"));
        digestMethod.setAttribute("Algorithm", DigestAlgorithm.SHA256.uri());
        Element digestValue = textElement(document, DS_NS, naming.qName("DigestValue"), certificateDigest);
        certDigest.appendChild(digestMethod);
        certDigest.appendChild(digestValue);

        Element issuerSerial = document.createElementNS(XADES_NS, "xades:IssuerSerial");
        issuerSerial.appendChild(textElement(
            document,
            DS_NS,
            naming.qName("X509IssuerName"),
            certificate.getIssuerX500Principal().getName()
        ));
        issuerSerial.appendChild(textElement(
            document,
            DS_NS,
            naming.qName("X509SerialNumber"),
            certificate.getSerialNumber().toString()
        ));

        cert.appendChild(certDigest);
        cert.appendChild(issuerSerial);
        return cert;
    }

    protected Element buildCompleteRevocationRefs(Document document, ValidationMaterial validationMaterial) {
        Element completeRevocationRefs = document.createElementNS(XADES_NS, "xades:CompleteRevocationRefs");
        Element crlRefs = document.createElementNS(XADES_NS, "xades:CRLRefs");
        if (validationMaterial.revocationReferenceUris().isEmpty()) {
            crlRefs.appendChild(document.createElementNS(XADES_NS, "xades:CRLRef"));
        } else {
            for (String uri : validationMaterial.revocationReferenceUris()) {
                Element crlRef = document.createElementNS(XADES_NS, "xades:CRLRef");
                crlRef.appendChild(textElement(document, XADES_NS, "xades:URI", uri));
                crlRefs.appendChild(crlRef);
            }
        }
        completeRevocationRefs.appendChild(crlRefs);
        return completeRevocationRefs;
    }

    protected Element buildCertificateValues(Document document, PreparedSignature prepared) {
        try {
            Element certificateValues = document.createElementNS(XADES_NS, "xades:CertificateValues");
            certificateValues.appendChild(textElement(
                document,
                XADES_NS,
                "xades:EncapsulatedX509Certificate",
                Base64.getEncoder().encodeToString(prepared.certificate().getEncoded())
            ));
            return certificateValues;
        } catch (Exception exception) {
            throw new SignatureAssemblyException("Unable to build XAdES certificate values.", exception);
        }
    }

    protected Element buildRevocationValues(Document document, ValidationMaterial validationMaterial) {
        Element revocationValues = document.createElementNS(XADES_NS, "xades:RevocationValues");
        Element crlValues = document.createElementNS(XADES_NS, "xades:CRLValues");
        if (validationMaterial.revocationValues().isEmpty()) {
            crlValues.appendChild(document.createElementNS(XADES_NS, "xades:EncapsulatedCRLValue"));
        } else {
            for (byte[] value : validationMaterial.revocationValues()) {
                crlValues.appendChild(textElement(
                    document,
                    XADES_NS,
                    "xades:EncapsulatedCRLValue",
                    Base64.getEncoder().encodeToString(value)
                ));
            }
        }
        revocationValues.appendChild(crlValues);
        return revocationValues;
    }

    protected Element buildCertificateValues(Document document, PreparedSignature prepared, ValidationMaterial validationMaterial) {
        Element certificateValues = buildCertificateValues(document, prepared);
        for (var certificate : validationMaterial.additionalCertificates()) {
            try {
                certificateValues.appendChild(textElement(
                    document,
                    XADES_NS,
                    "xades:EncapsulatedX509Certificate",
                    Base64.getEncoder().encodeToString(certificate.getEncoded())
                ));
            } catch (Exception exception) {
                throw new SignatureAssemblyException("Unable to build XAdES certificate values.", exception);
            }
        }
        return certificateValues;
    }
}
