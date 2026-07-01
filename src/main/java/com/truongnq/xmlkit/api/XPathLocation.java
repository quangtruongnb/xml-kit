package com.truongnq.xmlkit.api;

import java.util.Map;

public record XPathLocation(
        String expression,
        Map<String, String> namespaces,
        String referenceId
) {
    public XPathLocation {
        namespaces = namespaces != null ? Map.copyOf(namespaces) : Map.of();
    }

    public static Builder builder(String expression) {
        return new Builder(expression);
    }

    public static class Builder {
        private final String expression;
        private Map<String, String> namespaces = Map.of();
        private String referenceId;

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

        public XPathLocation build() {
            return new XPathLocation(expression, namespaces, referenceId);
        }
    }
}
