package com.truongnq.xmlkit.api;

import com.truongnq.xmlkit.core.DigestEngine;
import com.truongnq.xmlkit.core.PlacementResolver;
import com.truongnq.xmlkit.core.ReferenceBuilder;
import com.truongnq.xmlkit.core.SignatureAssembler;
import com.truongnq.xmlkit.core.SignedInfoBuilder;
import com.truongnq.xmlkit.core.XmlSupport;
import com.truongnq.xmlkit.exception.XmlKitException;
import com.truongnq.xmlkit.model.CanonicalizationMethod;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.model.SignatureType;
import java.security.cert.X509Certificate;
import java.util.Map;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public final class XmlSignatureBuilder {
    private final DigestEngine digestEngine = new DigestEngine();
    private final PlacementResolver placementResolver = new PlacementResolver();

    private Document document;
    private SignatureType signatureType = SignatureType.DETACHED;
    private SignatureProfile profile = SignatureProfile.XMLDSIG;
    private String prefix = "ds";
    private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
    private CanonicalizationMethod canonicalizationMethod = CanonicalizationMethod.C14N_EXCLUSIVE;
    private X509Certificate certificate;
    private String placementXPath;
    private String targetXPath;
    private Map<String, String> placementNamespaces = Map.of();
    private Map<String, String> targetNamespaces = Map.of();
    private String referenceId;

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

    public XmlSignatureBuilder prefix(String prefix) {
        this.prefix = prefix;
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

    public XmlSignatureBuilder certificate(X509Certificate certificate) {
        this.certificate = certificate;
        return this;
    }

    public XmlSignatureBuilder placementXPath(String placementXPath) {
        this.placementXPath = placementXPath;
        return this;
    }

    public XmlSignatureBuilder placementXPath(String placementXPath, Map<String, String> placementNamespaces) {
        this.placementXPath = placementXPath;
        this.placementNamespaces = Map.copyOf(placementNamespaces);
        return this;
    }

    public XmlSignatureBuilder targetXPath(String targetXPath) {
        this.targetXPath = targetXPath;
        return this;
    }

    public XmlSignatureBuilder targetXPath(String targetXPath, Map<String, String> targetNamespaces) {
        this.targetXPath = targetXPath;
        this.targetNamespaces = Map.copyOf(targetNamespaces);
        return this;
    }

    public XmlSignatureBuilder referenceId(String referenceId) {
        this.referenceId = referenceId;
        return this;
    }

    public SigningRequest prepare() {
        if (document == null) {
            throw new XmlKitException("Document is required.");
        }
        if (placementXPath == null || placementXPath.isBlank()) {
            throw new XmlKitException("Placement XPath is required.");
        }
        if (certificate == null) {
            throw new XmlKitException("Certificate is required.");
        }

        Document workingDocument = XmlSupport.cloneDocument(document);
        var placementTarget = placementResolver.resolve(workingDocument, placementXPath, placementNamespaces);
        validatePlacementTarget(placementTarget);
        Node payloadNode = resolvePayloadNode(workingDocument, placementTarget);
        var signedInfoBuilder = new SignedInfoBuilder(digestEngine, prefix);
        var signatureAssembler = new SignatureAssembler(digestEngine, prefix);
        var signedInfo = signedInfoBuilder.build(
                workingDocument,
                payloadNode,
                signatureType,
                digestAlgorithm,
                canonicalizationMethod,
                referenceId);
        byte[] digestToSign = digestEngine.digest(digestAlgorithm, signedInfo.canonicalizedBytes());

        PreparedSignature prepared = new PreparedSignature(
                workingDocument,
                placementTarget,
                signatureType,
                profile,
                digestAlgorithm,
                canonicalizationMethod,
                certificate,
                signedInfo);

        if (profile.requiresTimestamp()) {
            return new ExtendedSigningRequest(prepared, signatureAssembler, digestEngine, digestToSign);
        }
        return new SigningRequest(prepared, signatureAssembler, digestToSign);
    }

    private void validatePlacementTarget(Node placementTarget) {
        if (!(placementTarget instanceof Element)) {
            throw new XmlKitException("Placement XPath must resolve to an element node.");
        }
    }

    private Node resolvePayloadNode(Document workingDocument, Node placementTarget) {
        Node targetNode = targetXPath != null && !targetXPath.isBlank()
                ? placementResolver.resolve(workingDocument, targetXPath, targetNamespaces)
                : null;

        if (targetNode != null) {
            validateTargetNode(targetNode);
        }

        Node nodeToSign = targetNode != null ? targetNode : switch (signatureType) {
            case DETACHED -> placementTarget;
            case ENVELOPED, ENVELOPING -> workingDocument.getDocumentElement();
        };

        if (signatureType == SignatureType.DETACHED) {
            return prepareDetachedPayloadNode(nodeToSign);
        }
        return nodeToSign;
    }

    private void validateTargetNode(Node targetNode) {
        if (!(targetNode instanceof Element)) {
            throw new XmlKitException("Target XPath must resolve to an element node.");
        }
    }

    private Node prepareDetachedPayloadNode(Node placementTarget) {
        if (placementTarget instanceof Element element && !element.hasAttribute("Id")) {
            String id = referenceId != null ? referenceId : "id-" + java.util.UUID.randomUUID().toString();
            element.setAttribute("Id", id);
        }
        return placementTarget;
    }
}
