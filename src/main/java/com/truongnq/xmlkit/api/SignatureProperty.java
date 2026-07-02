package com.truongnq.xmlkit.api;

import org.w3c.dom.Node;

public record SignatureProperty(
        String id,
        Node content
) {
    public SignatureProperty {
        if (content == null) {
            throw new IllegalArgumentException("content is required");
        }
    }

    public static SignatureProperty of(String id, Node content) {
        return new SignatureProperty(id, content);
    }
}
