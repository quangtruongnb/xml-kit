package com.truongnq.xmlkit.api;

import com.truongnq.xmlkit.model.Transform;
import java.util.List;

public record ReferenceOptions(
        String referenceId,
        List<Transform> transforms
) {
    public ReferenceOptions {
        transforms = transforms != null ? List.copyOf(transforms) : null;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String referenceId;
        private List<Transform> transforms;

        private Builder() {
        }

        public Builder referenceId(String referenceId) {
            this.referenceId = referenceId;
            return this;
        }

        public Builder transforms(List<Transform> transforms) {
            this.transforms = transforms;
            return this;
        }

        public ReferenceOptions build() {
            return new ReferenceOptions(referenceId, transforms);
        }
    }
}
