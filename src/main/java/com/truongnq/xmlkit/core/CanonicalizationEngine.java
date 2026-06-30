package com.truongnq.xmlkit.core;

import com.truongnq.xmlkit.model.CanonicalizationMethod;
import java.util.LinkedHashMap;
import java.util.Map;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public final class CanonicalizationEngine {
    public byte[] canonicalize(Node node, CanonicalizationMethod canonicalizationMethod) {
        Node detachedNode = XmlSupport.detach(node);
        if (detachedNode instanceof Element element && canonicalizationMethod == CanonicalizationMethod.C14N_INCLUSIVE) {
            applyAncestorNamespaces(node, element);
        }
        
        try {
            javax.xml.crypto.dsig.TransformService ts = javax.xml.crypto.dsig.TransformService.getInstance(canonicalizationMethod.uri(), "DOM");
            javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            org.w3c.dom.Document dummyDoc = dbf.newDocumentBuilder().newDocument();
            org.w3c.dom.Element dummyElem = dummyDoc.createElement("dummy");
            dummyDoc.appendChild(dummyElem);
            ts.init(new javax.xml.crypto.dom.DOMStructure(dummyElem), new javax.xml.crypto.dom.DOMCryptoContext() {});
            
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            byte[] input = XmlSupport.toXml(detachedNode).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            javax.xml.crypto.OctetStreamData data = new javax.xml.crypto.OctetStreamData(new java.io.ByteArrayInputStream(input));
            
            ts.transform(data, new javax.xml.crypto.dom.DOMCryptoContext() {}, baos);
            return baos.toByteArray();
        } catch (Exception e) {
            throw new com.truongnq.xmlkit.exception.CanonicalizationException("Unable to canonicalize node.", e);
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
