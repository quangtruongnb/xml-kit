package com.truongnq.xmlkit.model;

public enum DigestAlgorithm {
    SHA256("SHA-256", "http://www.w3.org/2001/04/xmlenc#sha256"),
    SHA384("SHA-384", "http://www.w3.org/2001/04/xmldsig-more#sha384"),
    SHA512("SHA-512", "http://www.w3.org/2001/04/xmlenc#sha512");

    private final String jcaName;
    private final String uri;

    DigestAlgorithm(String jcaName, String uri) {
        this.jcaName = jcaName;
        this.uri = uri;
    }

    public String jcaName() {
        return jcaName;
    }

    public String uri() {
        return uri;
    }
}
