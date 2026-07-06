package com.truongnq.xmlkit.api;

import com.truongnq.xmlkit.core.XmlSupport;
import org.w3c.dom.Document;

public final class SignedDocument {
    private final Document document;

    public SignedDocument(Document document) {
        this.document = document;
    }

    public Document document() {
        return document;
    }

    public String xml() {
        return XmlSupport.toXml(document);
    }
}
