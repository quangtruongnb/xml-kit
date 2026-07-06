package com.truongnq.xmlkit.model;

public record Transform(String uri, String xpathExpression) {
    private static final String XPATH_URI = "http://www.w3.org/TR/1999/REC-xpath-19991116";

    public static Transform of(String uri) {
        return new Transform(uri, null);
    }

    public static Transform xpath(String expression) {
        return new Transform(XPATH_URI, expression);
    }
}
