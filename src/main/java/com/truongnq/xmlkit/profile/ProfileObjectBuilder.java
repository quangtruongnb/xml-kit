package com.truongnq.xmlkit.profile;

import com.truongnq.xmlkit.api.PreparedSignature;
import com.truongnq.xmlkit.api.ValidationMaterial;
import org.w3c.dom.Element;

public interface ProfileObjectBuilder {
    Element buildProfileObject(PreparedSignature prepared, byte[] timestampToken, ValidationMaterial validationMaterial);
}
