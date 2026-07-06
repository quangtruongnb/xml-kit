package com.truongnq.xmlkit.profile;

import com.truongnq.xmlkit.core.DigestEngine;
import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.profile.xades.XAdESBESBuilder;
import com.truongnq.xmlkit.profile.xades.XAdESCBuilder;
import com.truongnq.xmlkit.profile.xades.XAdESTBuilder;
import com.truongnq.xmlkit.profile.xades.XAdESXLBuilder;

public final class ProfileObjectBuilderFactory {
    private final DigestEngine digestEngine;
    private final String prefix;

    public ProfileObjectBuilderFactory(DigestEngine digestEngine, String prefix) {
        this.digestEngine = digestEngine;
        this.prefix = prefix;
    }

    public ProfileObjectBuilder forProfile(SignatureProfile profile) {
        return switch (profile) {
            case XMLDSIG -> new XmlDsigProfileBuilder();
            case XADES_BES -> new XAdESBESBuilder(digestEngine, prefix);
            case XADES_T -> new XAdESTBuilder(digestEngine, prefix);
            case XADES_C -> new XAdESCBuilder(digestEngine, prefix);
            case XADES_X_L -> new XAdESXLBuilder(digestEngine, prefix);
        };
    }
}
