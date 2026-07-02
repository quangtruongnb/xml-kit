package com.truongnq.xmlkit.api;

import java.util.List;

public record ReferenceOptions(
        String referenceId,
        List<String> transformUris
) {
    public ReferenceOptions {
        transformUris = transformUris != null ? List.copyOf(transformUris) : null;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String referenceId;
        private List<String> transformUris;

        private Builder() {
        }

        public Builder referenceId(String referenceId) {
            this.referenceId = referenceId;
            return this;
        }

        public Builder transformUris(List<String> transformUris) {
            this.transformUris = transformUris;
            return this;
        }

        public ReferenceOptions build() {
            return new ReferenceOptions(referenceId, transformUris);
        }
    }
}
