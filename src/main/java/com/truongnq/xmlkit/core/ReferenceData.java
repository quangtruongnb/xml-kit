package com.truongnq.xmlkit.core;

import java.util.List;

public record ReferenceData(
    String uri,
    String digestMethodUri,
    String digestValue,
    List<String> transformUris
) {
}
