package com.truongnq.xmlkit.core;

import com.truongnq.xmlkit.exception.CanonicalizationException;
import com.truongnq.xmlkit.exception.SignatureAssemblyException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

public final class XmlSupport {
    private XmlSupport() {
    }

    public static Document newDocument() {
        try {
            var factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            return factory.newDocumentBuilder().newDocument();
        } catch (Exception exception) {
            throw new SignatureAssemblyException("Unable to create XML document.", exception);
        }
    }

    public static Document cloneDocument(Document document) {
        Document clone = newDocument();
        clone.appendChild(clone.importNode(document.getDocumentElement(), true));
        return clone;
    }

    public static Node detach(Node node) {
        Document detachedDocument = newDocument();
        Node detachedNode = detachedDocument.importNode(node, true);
        detachedDocument.appendChild(detachedNode);
        return detachedNode;
    }

    public static String toXml(Node node) {
        try {
            var transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "no");
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(node), new StreamResult(writer));
            return writer.toString();
        } catch (Exception exception) {
            throw new CanonicalizationException("Unable to serialize XML node.", exception);
        }
    }
}
