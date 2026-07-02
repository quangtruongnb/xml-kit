package com.truongnq.xmlkit.api;

import java.util.ArrayList;
import java.util.List;
import org.w3c.dom.Node;

public record SignatureObject(
        Node content,
        List<SignatureProperty> properties,
        String id,
        boolean includeInSignedInfo,
        List<String> transformUris
) {
    public SignatureObject {
        properties = properties != null ? List.copyOf(properties) : List.of();
        transformUris = transformUris != null ? List.copyOf(transformUris) : null;
        if (content == null && properties.isEmpty()) {
            throw new IllegalArgumentException("Either content or properties must be provided.");
        }
    }

    public boolean isProperties() {
        return !properties.isEmpty();
    }

    public static Builder builder(Node content) {
        return new Builder(content);
    }

    public static PropertiesBuilder signatureProperties() {
        return new PropertiesBuilder();
    }

    public static class Builder {
        private final Node content;
        private String id;
        private boolean includeInSignedInfo = false;
        private List<String> transformUris;

        private Builder(Node content) {
            if (content == null) {
                throw new IllegalArgumentException("content is required");
            }
            this.content = content;
        }

        public Builder id(String id) {
            this.id = id;
            return this;
        }

        public Builder includeInSignedInfo(boolean includeInSignedInfo) {
            this.includeInSignedInfo = includeInSignedInfo;
            return this;
        }

        public Builder transformUris(List<String> transformUris) {
            this.transformUris = transformUris;
            return this;
        }

        public SignatureObject build() {
            return new SignatureObject(content, List.of(), id, includeInSignedInfo, transformUris);
        }
    }

    public static class PropertiesBuilder {
        private String id;
        private boolean includeInSignedInfo = false;
        private List<String> transformUris;
        private final List<SignatureProperty> properties = new ArrayList<>();

        private PropertiesBuilder() {
        }

        public PropertiesBuilder id(String id) {
            this.id = id;
            return this;
        }

        public PropertiesBuilder addProperty(String propertyId, Node content) {
            properties.add(SignatureProperty.of(propertyId, content));
            return this;
        }

        public PropertiesBuilder includeInSignedInfo(boolean includeInSignedInfo) {
            this.includeInSignedInfo = includeInSignedInfo;
            return this;
        }

        public PropertiesBuilder transformUris(List<String> transformUris) {
            this.transformUris = transformUris;
            return this;
        }

        public SignatureObject build() {
            return new SignatureObject(null, properties, id, includeInSignedInfo, transformUris);
        }
    }
}
