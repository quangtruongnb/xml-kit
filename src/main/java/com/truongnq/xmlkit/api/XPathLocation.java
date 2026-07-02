package com.truongnq.xmlkit.api;

import java.util.Map;
import java.util.List;

public record XPathLocation(
        String expression,
        Map<String, String> namespaces,
        String referenceId,
        List<String> transformUris
) {
    public XPathLocation {
        namespaces = namespaces != null ? Map.copyOf(namespaces) : Map.of();
        transformUris = transformUris != null ? List.copyOf(transformUris) : null;
    }

    public static Builder builder(String expression) {
        return new Builder(expression);
    }

    public static class Builder {
        private final String expression;
        private Map<String, String> namespaces = Map.of();
        private String referenceId;
        private List<String> transformUris;

        private Builder(String expression) {
            this.expression = expression;
        }

        public Builder namespaces(Map<String, String> namespaces) {
            this.namespaces = namespaces;
            return this;
        }

        public Builder referenceId(String referenceId) {
            this.referenceId = referenceId;
            return this;
        }

        public Builder transformUris(List<String> transformUris) {
            this.transformUris = transformUris;
            return this;
        }

        public XPathLocation build() {
            return new XPathLocation(expression, namespaces, referenceId, transformUris);
        }
    }
}
