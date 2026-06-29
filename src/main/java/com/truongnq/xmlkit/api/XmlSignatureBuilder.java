package com.truongnq.xmlkit.api;

import com.truongnq.xmlkit.core.DigestEngine;
import com.truongnq.xmlkit.core.PlacementResolver;
import com.truongnq.xmlkit.core.SignatureAssembler;
import com.truongnq.xmlkit.core.SignedInfoBuilder;
import com.truongnq.xmlkit.core.XmlSupport;
import com.truongnq.xmlkit.exception.XmlKitException;
import com.truongnq.xmlkit.model.CanonicalizationMethod;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.model.SignatureType;
import java.util.Map;
import org.w3c.dom.Document;

public final class XmlSignatureBuilder {
    private final DigestEngine digestEngine = new DigestEngine();
    private final PlacementResolver placementResolver = new PlacementResolver();
    private final SignedInfoBuilder signedInfoBuilder = new SignedInfoBuilder(digestEngine);
    private final SignatureAssembler signatureAssembler = new SignatureAssembler(digestEngine);

    private Document document;
    private SignatureType signatureType = SignatureType.ENVELOPED;
    private SignatureProfile profile = SignatureProfile.XMLDSIG;
    private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
    private CanonicalizationMethod canonicalizationMethod = CanonicalizationMethod.C14N_INCLUSIVE;
    private String placementXPath;
    private Map<String, String> placementNamespaces = Map.of();

    private XmlSignatureBuilder(Document document) {
        this.document = document;
    }

    public static XmlSignatureBuilder forDocument(Document document) {
        return new XmlSignatureBuilder(document);
    }

    public XmlSignatureBuilder signatureType(SignatureType signatureType) {
        this.signatureType = signatureType;
        return this;
    }

    public XmlSignatureBuilder profile(SignatureProfile profile) {
        this.profile = profile;
        return this;
    }

    public XmlSignatureBuilder digestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
        return this;
    }

    public XmlSignatureBuilder canonicalizationMethod(CanonicalizationMethod canonicalizationMethod) {
        this.canonicalizationMethod = canonicalizationMethod;
        return this;
    }

    public XmlSignatureBuilder placementXPath(String placementXPath) {
        this.placementXPath = placementXPath;
        return this;
    }

    public XmlSignatureBuilder placementNamespaces(Map<String, String> placementNamespaces) {
        this.placementNamespaces = Map.copyOf(placementNamespaces);
        return this;
    }

    public SigningRequest prepare() {
        if (document == null) {
            throw new XmlKitException("Document is required.");
        }
        if (placementXPath == null || placementXPath.isBlank()) {
            throw new XmlKitException("Placement XPath is required.");
        }

        Document workingDocument = XmlSupport.cloneDocument(document);
        var placementTarget = placementResolver.resolve(workingDocument, placementXPath, placementNamespaces);
        var signedInfo = signedInfoBuilder.build(workingDocument, signatureType, digestAlgorithm, canonicalizationMethod);
        byte[] digestToSign = digestEngine.digest(digestAlgorithm, signedInfo.bytes());

        PreparedSignature prepared = new PreparedSignature(
            workingDocument,
            placementTarget,
            signatureType,
            profile,
            digestAlgorithm,
            canonicalizationMethod,
            signedInfo
        );

        if (profile.requiresTimestamp()) {
            return new ExtendedSigningRequest(prepared, signatureAssembler, digestEngine, digestToSign);
        }
        return new SigningRequest(prepared, signatureAssembler, digestToSign);
    }
}
