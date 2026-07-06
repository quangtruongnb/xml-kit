package com.truongnq.xmlkit.core;

import static com.truongnq.xmlkit.core.XmlDsigConstants.*;

import com.truongnq.xmlkit.model.Transform;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.signature.XMLSignatureNodeInput;
import org.apache.xml.security.transforms.Transforms;

public final class TransformEngine {

    static {
        Init.init();
    }

    public byte[] transform(Node node, String uri) {
        return transform(node, List.of(Transform.of(uri)));
    }

    public byte[] transform(Node node, List<Transform> transformList) {
        try {
            Document doc = node instanceof Document ? (Document) node : node.getOwnerDocument();
            XMLSignatureInput input = new XMLSignatureNodeInput(node);

            boolean needsEnvelopedContext = transformList != null
                    && transformList.stream().anyMatch(t -> ENVELOPED_SIGNATURE_URI.equals(t.uri()));

            Transforms transforms = new Transforms(doc);
            if (transformList != null) {
                for (Transform transform : transformList) {
                    if (XPATH_URI.equals(transform.uri()) && transform.xpathExpression() != null) {
                        Element xpathElem = doc.createElementNS(DS_NS, "ds:XPath");
                        xpathElem.setTextContent(transform.xpathExpression());
                        transforms.addTransform(transform.uri(), xpathElem);
                    } else {
                        transforms.addTransform(transform.uri());
                    }
                }
            }

            // The enveloped-signature transform walks up the parent chain from the
            // <Transform> element looking for a <Signature> ancestor.  When we build
            // a Transforms object with `new Transforms(doc)`, its element is detached
            // so the walk always fails.  Fix: parent the Transforms element under a
            // temporary Signature element so the search succeeds.
            if (needsEnvelopedContext) {
                Element tempSignature = doc.createElementNS(DS_NS, "ds:Signature");
                tempSignature.appendChild(transforms.getElement());
                // Attach the temporary Signature to the document so the transform
                // can resolve the input node within the same document tree.
                Element root = doc.getDocumentElement();
                if (root != null) {
                    root.appendChild(tempSignature);
                }
                try {
                    XMLSignatureInput result = transforms.performTransforms(input);
                    return result.getBytes();
                } finally {
                    if (tempSignature.getParentNode() != null) {
                        tempSignature.getParentNode().removeChild(tempSignature);
                    }
                }
            }

            XMLSignatureInput result = transforms.performTransforms(input);
            return result.getBytes();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to transform XML node for digest", e);
        }
    }
}
