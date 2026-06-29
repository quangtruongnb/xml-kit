package com.truongnq.xmlkit.exception;

public class XmlKitException extends RuntimeException {
    public XmlKitException(String message) {
        super(message);
    }

    public XmlKitException(String message, Throwable cause) {
        super(message, cause);
    }
}
