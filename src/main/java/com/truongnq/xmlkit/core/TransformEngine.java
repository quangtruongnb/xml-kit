package com.truongnq.xmlkit.core;

import com.truongnq.xmlkit.exception.CanonicalizationException;
import com.truongnq.xmlkit.model.Transform;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.xml.crypto.Data;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.TransformService;
import javax.xml.crypto.dsig.dom.DOMSignContext;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.signature.XMLSignatureNodeInput;
import org.apache.xml.security.transforms.Transforms;

public final class TransformEngine {
    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String XPATH_URI = "http://www.w3.org/TR/1999/REC-xpath-19991116";
    private static final String ENVELOPED_SIGNATURE_URI = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    private static final String C14N_INCLUSIVE_URI = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

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
    
    // public byte[] transform(Node node, List<Transform> transforms) {
    //     Node detachedNode = XmlSupport.detach(node);
    //     if (detachedNode instanceof Element element) {
    //         applyAncestorNamespaces(node, element);
    //     }
    //     byte[] initial = XmlSupport.toXml(detachedNode).getBytes(StandardCharsets.UTF_8);

    //     if (transforms.isEmpty()) {
    //         return initial;
    //     }

    //     Data current = new OctetStreamData(new ByteArrayInputStream(initial));
    //     for (Transform t : transforms) {
    //         current = applyToData(current, t);
    //     }
    //     return toBytes(current);
    // }

    private Data applyToData(Data data, Transform transform) {
        try {
            TransformService ts = TransformService.getInstance(transform.uri(), "DOM");
            ts.init(new DOMStructure(buildParamElement(transform)), new DOMCryptoContext() {});
            return ts.transform(data, new DOMCryptoContext() {});
        } catch (Exception e) {
            throw new CanonicalizationException("Unable to apply transform: " + transform.uri(), e);
        }
    }

    private Element buildParamElement(Transform transform) {
        Document paramDoc = XmlSupport.newDocument();
        Element parent = paramDoc.createElement("parent");
        paramDoc.appendChild(parent);
        if (XPATH_URI.equals(transform.uri()) && transform.xpathExpression() != null) {
            Element xpathElem = paramDoc.createElementNS(DS_NS, "ds:XPath");
            xpathElem.setAttribute("xmlns:ds", DS_NS);
            xpathElem.setTextContent(transform.xpathExpression());
            parent.appendChild(xpathElem);
        }
        return parent;
    }

    private byte[] toBytes(Data data) {
        if (data instanceof OctetStreamData osd) {
            try {
                return osd.getOctetStream().readAllBytes();
            } catch (IOException e) {
                throw new CanonicalizationException("Unable to read transform output.", e);
            }
        }
        // NodeSetData without a following C14N: serialize with inclusive C14N
        try {

            TransformService c14n = TransformService.getInstance(C14N_INCLUSIVE_URI, "DOM");
            Document dummyDoc = XmlSupport.newDocument();
            Element dummyElem = dummyDoc.createElement("dummy");
            dummyDoc.appendChild(dummyElem);
            c14n.init(new DOMStructure(dummyElem), new DOMCryptoContext() {});
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            c14n.transform(data, new DOMCryptoContext() {}, baos);
            return baos.toByteArray();
        } catch (Exception e) {
            throw new CanonicalizationException("Unable to serialize node set.", e);
        }
    }


    private void applyAncestorNamespaces(Node originalNode, Element detachedRoot) {
        Map<String, String> namespaces = new LinkedHashMap<>();

        Node cursor = originalNode;
        while (cursor != null && cursor.getNodeType() == Node.ELEMENT_NODE) {
            Element element = (Element) cursor;
            for (int index = 0; index < element.getAttributes().getLength(); index++) {
                Node attribute = element.getAttributes().item(index);
                String name = attribute.getNodeName();
                if ("xmlns".equals(name) || name.startsWith("xmlns:")) {
                    namespaces.putIfAbsent(name, attribute.getNodeValue());
                }
            }
            cursor = cursor.getParentNode();
        }

        for (Map.Entry<String, String> entry : namespaces.entrySet()) {
            if (!detachedRoot.hasAttribute(entry.getKey())) {
                detachedRoot.setAttribute(entry.getKey(), entry.getValue());
            }
        }
    }
}
