package com.truongnq.xmlkit.core;

import com.truongnq.xmlkit.exception.PlacementResolutionException;
import com.truongnq.xmlkit.exception.XmlKitException;
import java.util.Iterator;
import java.util.Map;
import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public final class PlacementResolver {
    public Node resolve(Document document, String expression, Map<String, String> namespaces) {
        try {
            var xpath = XPathFactory.newInstance().newXPath();
            xpath.setNamespaceContext(new MapNamespaceContext(namespaces));
            NodeList nodes = (NodeList) xpath.evaluate(expression, document, XPathConstants.NODESET);
            if (nodes.getLength() != 1) {
                throw new PlacementResolutionException(expression, nodes.getLength());
            }
            return nodes.item(0);
        } catch (PlacementResolutionException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new XmlKitException("Failed to resolve placement XPath '" + expression + "'.", exception);
        }
    }

    private static final class MapNamespaceContext implements NamespaceContext {
        private final Map<String, String> namespaces;

        private MapNamespaceContext(Map<String, String> namespaces) {
            this.namespaces = namespaces;
        }

        @Override
        public String getNamespaceURI(String prefix) {
            if (prefix == null) {
                return XMLConstants.NULL_NS_URI;
            }
            return namespaces.getOrDefault(prefix, XMLConstants.NULL_NS_URI);
        }

        @Override
        public String getPrefix(String namespaceURI) {
            return namespaces.entrySet().stream()
                .filter(entry -> entry.getValue().equals(namespaceURI))
                .map(Map.Entry::getKey)
                .findFirst()
                .orElse(null);
        }

        @Override
        public Iterator<String> getPrefixes(String namespaceURI) {
            return namespaces.entrySet().stream()
                .filter(entry -> entry.getValue().equals(namespaceURI))
                .map(Map.Entry::getKey)
                .iterator();
        }
    }
}
