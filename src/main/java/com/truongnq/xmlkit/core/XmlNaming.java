package com.truongnq.xmlkit.core;

public record XmlNaming(String prefix) {
    public String qName(String localName) {
        return prefix != null && !prefix.isEmpty() ? prefix + ":" + localName : localName;
    }

    public String xmlnsAttribute() {
        return prefix != null && !prefix.isEmpty() ? "xmlns:" + prefix : "xmlns";
    }
}
