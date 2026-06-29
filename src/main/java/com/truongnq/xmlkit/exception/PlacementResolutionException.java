package com.truongnq.xmlkit.exception;

public final class PlacementResolutionException extends XmlKitException {
    public PlacementResolutionException(String expression, int matchCount) {
        super("Placement XPath '" + expression + "' resolved to " + matchCount + " nodes.");
    }
}
