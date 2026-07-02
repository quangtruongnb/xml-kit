package com.truongnq.xmlkit.core;

import org.w3c.dom.Element;

public record SignedInfoData(
    java.util.List<ReferenceData> references,
    String canonicalizationMethodUri,
    String signatureMethodUri,
    Element element,
    byte[] canonicalizedBytes
) {
}
