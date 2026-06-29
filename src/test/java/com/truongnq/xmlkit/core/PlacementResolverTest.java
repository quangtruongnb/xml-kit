package com.truongnq.xmlkit.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.truongnq.xmlkit.exception.PlacementResolutionException;
import com.truongnq.xmlkit.testing.TestXml;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

class PlacementResolverTest {
    private final PlacementResolver resolver = new PlacementResolver();

    @Test
    void resolvesExactlyOneNode() {
        Document document = TestXml.document("<root><slot/></root>");

        Node node = resolver.resolve(document, "//slot", Map.of());

        assertEquals("slot", node.getNodeName());
    }

    @Test
    void resolvesWithCallerSuppliedNamespaces() {
        Document document = TestXml.document("<root xmlns='urn:test'><slot/></root>");

        Node node = resolver.resolve(document, "//t:slot", Map.of("t", "urn:test"));

        assertEquals("slot", node.getLocalName());
    }

    @Test
    void failsWhenXPathMatchesNothing() {
        Document document = TestXml.document("<root><slot/></root>");

        assertThrows(PlacementResolutionException.class, () -> resolver.resolve(document, "//missing", Map.of()));
    }

    @Test
    void failsWhenXPathMatchesMultipleNodes() {
        Document document = TestXml.document("<root><slot/><slot/></root>");

        assertThrows(PlacementResolutionException.class, () -> resolver.resolve(document, "//slot", Map.of()));
    }
}
