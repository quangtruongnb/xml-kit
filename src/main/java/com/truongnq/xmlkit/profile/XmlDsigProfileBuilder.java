package com.truongnq.xmlkit.profile;

import com.truongnq.xmlkit.api.PreparedSignature;
import com.truongnq.xmlkit.api.ValidationMaterial;
import org.w3c.dom.Element;

public final class XmlDsigProfileBuilder implements ProfileObjectBuilder {
    @Override
    public Element buildProfileObject(PreparedSignature prepared, byte[] timestampToken, ValidationMaterial validationMaterial) {
        return null;
    }
}
