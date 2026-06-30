package com.truongnq.xmlkit.model;

public enum DigestAlgorithm {
    SHA256("SHA-256", "http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
    SHA384("SHA-384", "http://www.w3.org/2001/04/xmldsig-more#sha384", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"),
    SHA512("SHA-512", "http://www.w3.org/2001/04/xmlenc#sha512", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");

    private final String jcaName;
    private final String uri;
    private final String signatureMethodUri;

    DigestAlgorithm(String jcaName, String uri, String signatureMethodUri) {
        this.jcaName = jcaName;
        this.uri = uri;
        this.signatureMethodUri = signatureMethodUri;
    }

    public String jcaName() {
        return jcaName;
    }

    public String uri() {
        return uri;
    }

    public String signatureMethodUri() {
        return signatureMethodUri;
    }
}
