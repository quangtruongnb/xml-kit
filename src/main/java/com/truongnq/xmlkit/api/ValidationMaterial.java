package com.truongnq.xmlkit.api;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public record ValidationMaterial(
    List<X509Certificate> additionalCertificates,
    List<String> revocationReferenceUris,
    List<byte[]> revocationValues
) {
    public ValidationMaterial {
        additionalCertificates = List.copyOf(additionalCertificates);
        revocationReferenceUris = List.copyOf(revocationReferenceUris);
        revocationValues = revocationValues.stream().map(byte[]::clone).toList();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static ValidationMaterial empty() {
        return builder().build();
    }

    public static final class Builder {
        private final List<X509Certificate> additionalCertificates = new ArrayList<>();
        private final List<String> revocationReferenceUris = new ArrayList<>();
        private final List<byte[]> revocationValues = new ArrayList<>();

        public Builder additionalCertificates(List<X509Certificate> certificates) {
            this.additionalCertificates.addAll(certificates);
            return this;
        }

        public Builder revocationReferenceUris(List<String> uris) {
            this.revocationReferenceUris.addAll(uris);
            return this;
        }

        public Builder revocationValues(List<byte[]> values) {
            values.forEach(value -> this.revocationValues.add(value.clone()));
            return this;
        }

        public ValidationMaterial build() {
            return new ValidationMaterial(additionalCertificates, revocationReferenceUris, revocationValues);
        }
    }
}
