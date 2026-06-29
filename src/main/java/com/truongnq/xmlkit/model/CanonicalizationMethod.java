package com.truongnq.xmlkit.model;

public enum CanonicalizationMethod {
    C14N_INCLUSIVE("http://www.w3.org/TR/2001/REC-xml-c14n-20010315"),
    C14N_EXCLUSIVE("http://www.w3.org/2001/10/xml-exc-c14n#");

    private final String uri;

    CanonicalizationMethod(String uri) {
        this.uri = uri;
    }

    public String uri() {
        return uri;
    }
}
