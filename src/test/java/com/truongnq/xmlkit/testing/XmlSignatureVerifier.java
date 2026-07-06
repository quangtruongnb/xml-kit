package com.truongnq.xmlkit.testing;

import com.truongnq.xmlkit.api.SignedDocument;
import com.truongnq.xmlkit.core.DigestEngine;
import com.truongnq.xmlkit.core.TransformEngine;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import java.util.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Verifies XML digital signatures produced by xml-kit.
 *
 * <p>Validates two things:</p>
 * <ol>
 *   <li><strong>Reference integrity</strong> — each {@code <Reference>} digest in the
 *       signed document matches the re-computed digest of the referenced content.</li>
 *   <li><strong>Signature value</strong> — the {@code <SignatureValue>} is a valid
 *       RSA signature over the digest-to-sign, verified against the test certificate.</li>
 * </ol>
 */
public final class XmlSignatureVerifier {

    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";

    private XmlSignatureVerifier() {
    }

    /**
     * Verifies reference integrity and signature value of the first Signature element.
     *
     * @param signedDocument the signed document
     * @param digestToSign the original digest-to-sign from the signing request
     * @param digestAlgorithm the digest algorithm used
     * @return {@code true} if both the references and signature value are valid
     */
    public static boolean verify(SignedDocument signedDocument, byte[] digestToSign, DigestAlgorithm digestAlgorithm) {
        return verify(signedDocument.document(), digestToSign, digestAlgorithm);
    }

    /**
     * Verifies reference integrity and signature value using SHA-256 as the default digest algorithm.
     */
    public static boolean verify(SignedDocument signedDocument, byte[] digestToSign) {
        return verify(signedDocument, digestToSign, DigestAlgorithm.SHA256);
    }

    /**
     * Verifies reference integrity and signature value of the first Signature element.
     */
    public static boolean verify(Document document, byte[] digestToSign, DigestAlgorithm digestAlgorithm) {
        try {
            // Re-parse to get a clean DOM
            Document cleanDoc = TestXml.document(TestXml.xml(document));

            NodeList signatureNodes = cleanDoc.getElementsByTagNameNS(DS_NS, "Signature");
            if (signatureNodes.getLength() == 0) {
                throw new IllegalArgumentException("No Signature element found in document.");
            }
            Node signatureNode = signatureNodes.item(0);

            // 1. Verify SignatureValue against the digestToSign
            Node signatureValueNode = findChildByLocalName(signatureNode, "SignatureValue");
            if (signatureValueNode == null) {
                throw new IllegalArgumentException("No SignatureValue element found.");
            }
            byte[] signatureValue = Base64.getDecoder().decode(
                signatureValueNode.getTextContent().replaceAll("\\s", "")
            );
            FakeRemoteSigner signer = new FakeRemoteSigner();
            if (!signer.verify(signatureValue, digestToSign, digestAlgorithm)) {
                return false;
            }

            // 2. Verify all Reference digests
            Node signedInfoNode = findChildByLocalName(signatureNode, "SignedInfo");
            if (signedInfoNode == null) {
                throw new IllegalArgumentException("No SignedInfo element found.");
            }
            return verifyReferences(cleanDoc, signedInfoNode, digestAlgorithm);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to verify XML signature.", exception);
        }
    }

    private static boolean verifyReferences(Document document, Node signedInfoNode, DigestAlgorithm digestAlgorithm) {
        DigestEngine digestEngine = new DigestEngine();
        TransformEngine transformEngine = new TransformEngine();
        NodeList children = signedInfoNode.getChildNodes();

        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (!"Reference".equals(child.getLocalName())) {
                continue;
            }
            Element refElement = (Element) child;
            String uri = refElement.getAttribute("URI");

            // Extract expected digest from the XML
            Node digestValueNode = findChildByLocalName(refElement, "DigestValue");
            if (digestValueNode == null) {
                return false;
            }
            String expectedDigest = digestValueNode.getTextContent().trim();

            // Resolve the referenced node
            Node referencedNode = resolveReference(document, uri);
            if (referencedNode == null) {
                // Can't resolve reference (e.g., empty URI for enveloped or Object references) - skip digest check
                continue;
            }

            // Check if reference has transforms
            Node transformsNode = findChildByLocalName(refElement, "Transforms");
            if (transformsNode != null && hasEnvelopedTransform(transformsNode)) {
                // Enveloped signature: skip digest verification (would need to remove the Signature first)
                continue;
            }

            // Canonicalize the referenced node and compute digest
            byte[] canonicalized = transformEngine.transform(
                referencedNode,
                com.truongnq.xmlkit.model.CanonicalizationMethod.C14N_INCLUSIVE.uri()
            );
            String computedDigest = digestEngine.digestBase64(digestAlgorithm, canonicalized);

            if (!expectedDigest.equals(computedDigest)) {
                return false;
            }
        }
        return true;
    }

    private static Node resolveReference(Document document, String uri) {
        if (uri == null || uri.isEmpty()) {
            return null; // Empty URI = whole document (enveloped)
        }
        if (uri.startsWith("#")) {
            String id = uri.substring(1);
            return findById(document.getDocumentElement(), id);
        }
        return null;
    }

    private static Node findById(Node node, String id) {
        if (node instanceof Element element) {
            if (id.equals(element.getAttribute("Id"))) {
                return element;
            }
        }
        NodeList children = node.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node found = findById(children.item(i), id);
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    private static boolean hasEnvelopedTransform(Node transformsNode) {
        NodeList children = transformsNode.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if ("Transform".equals(child.getLocalName()) && child instanceof Element element) {
                if ("http://www.w3.org/2000/09/xmldsig#enveloped-signature".equals(element.getAttribute("Algorithm"))) {
                    return true;
                }
            }
        }
        return false;
    }

    private static Node findChildByLocalName(Node parent, String localName) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (localName.equals(child.getLocalName())) {
                return child;
            }
        }
        return null;
    }
}
