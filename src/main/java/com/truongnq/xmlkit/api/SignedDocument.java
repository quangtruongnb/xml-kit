package com.truongnq.xmlkit.api;

import com.truongnq.xmlkit.core.XmlSupport;
import org.w3c.dom.Document;

public final class SignedDocument {
    private final Document document;
    private final String xml;

    public SignedDocument(Document document) {
        this.document = document;
        this.xml = XmlSupport.toXml(document);
    }

    public Document document() {
        return document;
    }

    public String xml() {
        return xml;
    }
}
