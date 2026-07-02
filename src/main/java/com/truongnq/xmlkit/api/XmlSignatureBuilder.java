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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
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
    private Map<String, String> placementNamespaces = Map.of();
    private List<XPathLocation> targetXPaths = List.of();

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

    public XmlSignatureBuilder placementXPath(XPathLocation location) {
        if (location != null) {
            this.placementXPath = location.expression();
            this.placementNamespaces = location.namespaces();
        }
        return this;
    }

    public XmlSignatureBuilder targetXPaths(List<XPathLocation> locations) {
        this.targetXPaths = locations == null ? List.of() : List.copyOf(locations);
        return this;
    }

    public XmlSignatureBuilder addTargetXPath(XPathLocation location) {
        if (location != null) {
            List<XPathLocation> updated = new ArrayList<>(targetXPaths);
            updated.add(location);
            this.targetXPaths = List.copyOf(updated);
        }
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
        List<Node> payloadTargets = resolvePayloadTargets(workingDocument, placementTarget);
        List<String> referenceIds = referenceIdsFor(payloadTargets);
        var signedInfoBuilder = new SignedInfoBuilder(digestEngine, prefix);
        var signatureAssembler = new SignatureAssembler(digestEngine, prefix);
        var signedInfo = signedInfoBuilder.build(
                workingDocument,
                payloadTargets,
                signatureType,
                digestAlgorithm,
                canonicalizationMethod,
                referenceIds);
        byte[] digestToSign = digestEngine.digest(digestAlgorithm, signedInfo.canonicalizedBytes());

        PreparedSignature prepared = new PreparedSignature(
                workingDocument,
                placementTarget,
                List.copyOf(payloadTargets),
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

    private List<Node> resolvePayloadTargets(Document workingDocument, Node placementTarget) {
        if (signatureType == SignatureType.ENVELOPED && targetXPaths.size() > 1) {
            throw new XmlKitException("Multiple target XPath expressions are not supported for enveloped signatures.");
        }

        List<Node> resolvedTargets = new ArrayList<>();
        IdentityHashMap<Node, Boolean> seenTargets = new IdentityHashMap<>();
        for (XPathLocation location : targetXPaths) {
            Node targetNode = placementResolver.resolve(workingDocument, location.expression(), location.namespaces());
            validateTargetNode(targetNode);
            if (seenTargets.put(targetNode, Boolean.TRUE) != null) {
                throw new XmlKitException("Target XPath expressions must resolve to distinct element nodes.");
            }
            resolvedTargets.add(targetNode);
        }

        if (resolvedTargets.isEmpty()) {
            resolvedTargets.add(switch (signatureType) {
                case DETACHED -> placementTarget;
                case ENVELOPED, ENVELOPING -> workingDocument.getDocumentElement();
            });
        }

        if (signatureType == SignatureType.DETACHED) {
            prepareDetachedPayloadNodes(resolvedTargets);
        }
        return List.copyOf(resolvedTargets);
    }

    private void validateTargetNode(Node targetNode) {
        if (!(targetNode instanceof Element)) {
            throw new XmlKitException("Target XPath must resolve to an element node.");
        }
    }

    private void prepareDetachedPayloadNodes(List<Node> payloadTargets) {
        for (int index = 0; index < payloadTargets.size(); index++) {
            Node payloadTarget = payloadTargets.get(index);
            if (payloadTarget instanceof Element element && !element.hasAttribute("Id")) {
                String configuredReferenceId = index < targetXPaths.size() ? targetXPaths.get(index).referenceId()
                        : null;
                String id = configuredReferenceId != null ? configuredReferenceId
                        : "id-" + java.util.UUID.randomUUID().toString();
                element.setAttribute("Id", id);
            }
        }
    }

    private String referenceIdFor(Node payloadTarget) {
        if (payloadTarget instanceof Element element && element.hasAttribute("Id")) {
            return element.getAttribute("Id");
        }
        return null;
    }

    private List<String> referenceIdsFor(List<Node> payloadTargets) {
        List<String> referenceIds = new ArrayList<>(payloadTargets.size());
        for (int index = 0; index < payloadTargets.size(); index++) {
            String configuredReferenceId = index < targetXPaths.size() ? targetXPaths.get(index).referenceId() : null;
            referenceIds.add(
                    configuredReferenceId != null ? configuredReferenceId : referenceIdFor(payloadTargets.get(index)));
        }
        return referenceIds;
    }
}
