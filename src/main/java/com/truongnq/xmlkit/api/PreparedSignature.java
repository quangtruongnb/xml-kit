package com.truongnq.xmlkit.api;

import com.truongnq.xmlkit.core.SignedInfoData;
import com.truongnq.xmlkit.model.CanonicalizationMethod;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.model.SignatureType;
import java.security.cert.X509Certificate;
import java.util.List;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

public record PreparedSignature(
    Document document,
    Node placementTarget,
    List<Node> payloadTargets,
    SignatureType signatureType,
    SignatureProfile profile,
    DigestAlgorithm digestAlgorithm,
    CanonicalizationMethod canonicalizationMethod,
    X509Certificate certificate,
    SignedInfoData signedInfo,
    String signatureId,
    List<SignatureObject> signatureObjects
) {
}
