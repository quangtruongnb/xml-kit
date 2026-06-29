package com.truongnq.xmlkit.api;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.Test;

class XmlSignatureBuilderBootstrapTest {
    @Test
    void builderClassExists() {
        assertDoesNotThrow(() -> Class.forName("com.truongnq.xmlkit.api.XmlSignatureBuilder"));
    }
}
