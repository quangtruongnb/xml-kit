package com.truongnq.xmlkit.api;

import java.util.Map;

public record Selector(
        String expression,
        Map<String, String> namespaces
) {
    public Selector {
        namespaces = namespaces != null ? Map.copyOf(namespaces) : Map.of();
    }

    public static Builder builder(String expression) {
        return new Builder(expression);
    }

    public static class Builder {
        private final String expression;
        private Map<String, String> namespaces = Map.of();

        private Builder(String expression) {
            this.expression = expression;
        }

        public Builder namespaces(Map<String, String> namespaces) {
            this.namespaces = namespaces;
            return this;
        }

        public Selector build() {
            return new Selector(expression, namespaces);
        }
    }
}
