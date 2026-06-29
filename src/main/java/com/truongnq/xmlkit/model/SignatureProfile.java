package com.truongnq.xmlkit.model;

public enum SignatureProfile {
    XMLDSIG(false),
    XADES_BES(false),
    XADES_T(true),
    XADES_C(true),
    XADES_X_L(true);

    private final boolean timestampRequired;

    SignatureProfile(boolean timestampRequired) {
        this.timestampRequired = timestampRequired;
    }

    public boolean requiresTimestamp() {
        return timestampRequired;
    }
}
