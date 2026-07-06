package com.truongnq.xmlkit.core;

import org.w3c.dom.Element;

public record SignedInfoData(
    java.util.List<ReferenceData> references,
    String canonicalizationMethodUri,
    String signatureMethodUri,
    Element element,
    byte[] canonicalizedBytes
) {
    public SignedInfoData {
        canonicalizedBytes = canonicalizedBytes.clone();
    }

    @Override
    public byte[] canonicalizedBytes() {
        return canonicalizedBytes.clone();
    }
}
