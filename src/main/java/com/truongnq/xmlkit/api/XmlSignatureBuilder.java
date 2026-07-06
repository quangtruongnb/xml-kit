package com.truongnq.xmlkit.api;

import static com.truongnq.xmlkit.core.XmlDsigConstants.*;

import com.truongnq.xmlkit.core.TransformEngine;
import com.truongnq.xmlkit.core.DigestEngine;
import com.truongnq.xmlkit.core.PlacementResolver;
import com.truongnq.xmlkit.core.ReferenceData;
import com.truongnq.xmlkit.core.SignatureAssembler;
import com.truongnq.xmlkit.core.SignedInfoBuilder;
import com.truongnq.xmlkit.core.XmlNaming;
import com.truongnq.xmlkit.core.XmlSupport;
import com.truongnq.xmlkit.exception.XmlKitException;
import com.truongnq.xmlkit.model.CanonicalizationMethod;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.model.SignatureType;
import com.truongnq.xmlkit.model.Transform;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public final class XmlSignatureBuilder {

    private final DigestEngine digestEngine = new DigestEngine();
    private final TransformEngine transformEngine = new TransformEngine();
    private final PlacementResolver placementResolver = new PlacementResolver();

    private Document document;
    private SignatureType signatureType = SignatureType.DETACHED;
    private SignatureProfile profile = SignatureProfile.XMLDSIG;
    private String prefix = "ds";
    private DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
    private CanonicalizationMethod canonicalizationMethod = CanonicalizationMethod.C14N_EXCLUSIVE;
    private X509Certificate certificate;
    private Selector placementSelector;
    private List<TargetReference> targets = List.of();
    private String signatureId;
    private List<SignatureObject> signatureObjects = List.of();

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

    public XmlSignatureBuilder placementSelector(Selector selector) {
        this.placementSelector = selector;
        return this;
    }

    public XmlSignatureBuilder targets(List<TargetReference> targets) {
        this.targets = targets == null ? List.of() : List.copyOf(targets);
        return this;
    }

    public XmlSignatureBuilder addTarget(Selector selector) {
        return addTarget(selector, null);
    }

    public XmlSignatureBuilder addTarget(Selector selector, ReferenceOptions options) {
        if (selector != null) {
            List<TargetReference> updated = new ArrayList<>(targets);
            updated.add(TargetReference.of(selector, options));
            this.targets = List.copyOf(updated);
        }
        return this;
    }

    public XmlSignatureBuilder signatureId(String signatureId) {
        this.signatureId = signatureId;
        return this;
    }

    public XmlSignatureBuilder addSignatureObject(SignatureObject signatureObject) {
        if (signatureObject != null) {
            List<SignatureObject> updated = new ArrayList<>(signatureObjects);
            updated.add(signatureObject);
            this.signatureObjects = List.copyOf(updated);
        }
        return this;
    }

    public SigningRequest prepare() {
        if (document == null) {
            throw new XmlKitException("Document is required.");
        }
        if (placementSelector == null
                || placementSelector.expression() == null
                || placementSelector.expression().isBlank()) {
            throw new XmlKitException("Placement selector is required.");
        }
        if (certificate == null) {
            throw new XmlKitException("Certificate is required.");
        }

        Document workingDocument = XmlSupport.cloneDocument(document);
        var placementTarget = placementResolver.resolve(
                workingDocument,
                placementSelector.expression(),
                placementSelector.namespaces());
        validatePlacementTarget(placementTarget);
        List<Node> payloadTargets = resolvePayloadTargets(workingDocument, placementTarget);
        List<String> referenceIds = referenceIdsFor(payloadTargets);
        List<List<Transform>> referenceTransformUris = referenceTransformsFor(payloadTargets);
        String resolvedSignatureId = resolveSignatureId();
        List<SignatureObject> resolvedObjects = resolveSignatureObjects();
        List<ReferenceData> additionalReferences = buildAdditionalReferences(resolvedObjects, resolvedSignatureId);
        var signedInfoBuilder = new SignedInfoBuilder(digestEngine, transformEngine, prefix);
        var signatureAssembler = new SignatureAssembler(digestEngine, prefix);
        var signedInfo = signedInfoBuilder.build(
                workingDocument,
                payloadTargets,
                signatureType,
                digestAlgorithm,
                canonicalizationMethod,
                referenceIds,
                referenceTransformUris,
                additionalReferences);
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
                signedInfo,
                resolvedSignatureId,
                resolvedObjects);

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
        if (signatureType == SignatureType.ENVELOPED && targets.size() > 1) {
            throw new XmlKitException("Multiple target XPath expressions are not supported for enveloped signatures.");
        }

        List<Node> resolvedTargets = new ArrayList<>();
        IdentityHashMap<Node, Boolean> seenTargets = new IdentityHashMap<>();
        for (TargetReference target : targets) {
            Selector selector = target.selector();
            Node targetNode = placementResolver.resolve(workingDocument, selector.expression(), selector.namespaces());
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
                ReferenceOptions options = configuredReferenceOptionsFor(index);
                String configuredReferenceId = options != null ? options.referenceId() : null;
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
            ReferenceOptions options = configuredReferenceOptionsFor(index);
            String configuredReferenceId = options != null ? options.referenceId() : null;
            referenceIds.add(
                    configuredReferenceId != null ? configuredReferenceId : referenceIdFor(payloadTargets.get(index)));
        }
        return referenceIds;
    }

    private List<List<Transform>> referenceTransformsFor(List<Node> payloadTargets) {
        List<List<Transform>> referenceTransforms = new ArrayList<>(payloadTargets.size());
        for (int index = 0; index < payloadTargets.size(); index++) {
            ReferenceOptions options = configuredReferenceOptionsFor(index);
            List<Transform> transforms = options != null ? options.transforms() : null;
            validateConfiguredTransforms(transforms);
            referenceTransforms.add(transforms);
        }
        return referenceTransforms;
    }

    private ReferenceOptions configuredReferenceOptionsFor(int index) {
        return index < targets.size() ? targets.get(index).options() : null;
    }

    private void validateConfiguredTransforms(List<Transform> transforms) {
        if (signatureType == SignatureType.ENVELOPED
                && transforms != null
                && transforms.stream().noneMatch(t -> ENVELOPED_SIGNATURE_URI.equals(t.uri()))) {
            throw new XmlKitException(
                    "Enveloped signatures must include the enveloped-signature transform when custom transforms are provided.");
        }
    }

    private String resolveSignatureId() {
        if (signatureId != null) {
            return signatureId;
        }
        boolean hasProperties = signatureObjects.stream().anyMatch(SignatureObject::isProperties);
        return hasProperties ? "id-" + java.util.UUID.randomUUID().toString() : null;
    }

    private List<SignatureObject> resolveSignatureObjects() {
        List<SignatureObject> resolved = new ArrayList<>(signatureObjects.size());
        for (SignatureObject obj : signatureObjects) {
            String objId = obj.id();
            if (objId == null && obj.includeInSignedInfo()) {
                objId = "id-" + java.util.UUID.randomUUID().toString();
            }
            resolved.add(new SignatureObject(
                    obj.content(), obj.properties(), objId,
                    obj.includeInSignedInfo(), obj.transforms()));
        }
        return List.copyOf(resolved);
    }

    private List<ReferenceData> buildAdditionalReferences(List<SignatureObject> resolvedObjects, String resolvedSignatureId) {
        XmlNaming naming = new XmlNaming(prefix);
        List<ReferenceData> additionalReferences = new ArrayList<>();
        for (SignatureObject obj : resolvedObjects) {
            if (!obj.includeInSignedInfo()) {
                continue;
            }
            Element tempObject = buildTemporaryObjectElement(obj, resolvedSignatureId, naming);
            List<Transform> transforms = obj.transforms() != null ? obj.transforms() : List.of();
            byte[] canonicalized = transformEngine.transform(tempObject, transforms);
            String digest = digestEngine.digestBase64(digestAlgorithm, canonicalized);
            additionalReferences.add(new ReferenceData(
                    "#" + obj.id(), digestAlgorithm.uri(), digest, transforms));
        }
        return additionalReferences;
    }

    private Element buildTemporaryObjectElement(SignatureObject obj, String resolvedSignatureId, XmlNaming naming) {
        Document tempDoc = XmlSupport.newDocument();
        Element signature = tempDoc.createElementNS(DS_NS, naming.qName("Signature"));
        signature.setAttribute(naming.xmlnsAttribute(), DS_NS);
        tempDoc.appendChild(signature);
        String targetUri = resolvedSignatureId != null ? "#" + resolvedSignatureId : "";
        Element object = SignatureAssembler.buildObjectElement(tempDoc, obj, targetUri, prefix);
        signature.appendChild(object);
        return object;
    }
}
