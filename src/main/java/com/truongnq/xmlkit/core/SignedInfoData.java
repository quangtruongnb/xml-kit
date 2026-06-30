package com.truongnq.xmlkit.core;

import java.util.List;
import org.w3c.dom.Element;

public record SignedInfoData(
    String referenceUri,
    String referenceDigestValue,
    String canonicalizationMethodUri,
    String digestMethodUri,
    String signatureMethodUri,
    List<String> transformUris,
    Element element,
    byte[] canonicalizedBytes
) {
}
