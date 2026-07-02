package com.truongnq.xmlkit.api;

public record TargetReference(
        Selector selector,
        ReferenceOptions options
) {
    public TargetReference {
        if (selector == null) {
            throw new IllegalArgumentException("selector is required");
        }
    }

    public static TargetReference of(Selector selector) {
        return new TargetReference(selector, null);
    }

    public static TargetReference of(Selector selector, ReferenceOptions options) {
        return new TargetReference(selector, options);
    }
}
