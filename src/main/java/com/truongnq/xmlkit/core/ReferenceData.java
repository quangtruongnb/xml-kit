package com.truongnq.xmlkit.core;

import com.truongnq.xmlkit.model.Transform;
import java.util.List;

public record ReferenceData(
    String uri,
    String digestMethodUri,
    String digestValue,
    List<Transform> transforms
) {
}
