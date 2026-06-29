package com.truongnq.xmlkit.core;

import java.nio.charset.StandardCharsets;

public record SignedInfoData(
    String referenceUri,
    String referenceDigestValue,
    String canonicalizationMethodUri,
    String digestMethodUri,
    String signatureMethodUri
) {
    public byte[] bytes() {
        return xml().getBytes(StandardCharsets.UTF_8);
    }

    public String xml() {
        return """
            <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
              <ds:CanonicalizationMethod Algorithm="%s"/>
              <ds:SignatureMethod Algorithm="%s"/>
              <ds:Reference URI="%s">
                <ds:DigestMethod Algorithm="%s"/>
                <ds:DigestValue>%s</ds:DigestValue>
              </ds:Reference>
            </ds:SignedInfo>
            """.formatted(canonicalizationMethodUri, signatureMethodUri, referenceUri, digestMethodUri, referenceDigestValue);
    }
}
