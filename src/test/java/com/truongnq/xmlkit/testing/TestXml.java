package com.truongnq.xmlkit.testing;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public final class TestXml {
    private TestXml() {
    }

    public static Document document(String xml) {
        try {
            var factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            return factory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
        } catch (Exception exception) {
            throw new IllegalArgumentException("Unable to parse test XML", exception);
        }
    }

    public static List<String> childNames(Document document, String expression) {
        try {
            var xpath = XPathFactory.newInstance().newXPath();
            Node node = (Node) xpath.evaluate(expression, document, XPathConstants.NODE);
            NodeList children = node.getChildNodes();
            List<String> names = new ArrayList<>();
            for (int index = 0; index < children.getLength(); index++) {
                Node child = children.item(index);
                if (child.getNodeType() == Node.ELEMENT_NODE) {
                    names.add(child.getLocalName() == null ? child.getNodeName() : child.getLocalName());
                }
            }
            return names;
        } catch (Exception exception) {
            throw new IllegalArgumentException("Unable to inspect child names", exception);
        }
    }

    public static String xml(Document document) {
        try {
            var transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "no");
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(document), new StreamResult(writer));
            return writer.toString();
        } catch (Exception exception) {
            throw new IllegalArgumentException("Unable to render test XML", exception);
        }
    }
}
