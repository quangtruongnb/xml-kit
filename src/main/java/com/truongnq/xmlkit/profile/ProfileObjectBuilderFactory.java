package com.truongnq.xmlkit.profile;

import com.truongnq.xmlkit.core.DigestEngine;
import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.profile.xades.XAdESBESBuilder;
import com.truongnq.xmlkit.profile.xades.XAdESLongBuilder;
import com.truongnq.xmlkit.profile.xades.XAdESTBuilder;

public final class ProfileObjectBuilderFactory {
    private final XmlDsigProfileBuilder xmlDsigProfileBuilder;
    private final XAdESBESBuilder xadesbesBuilder;
    private final XAdESTBuilder xadestBuilder;
    private final XAdESLongBuilder xadesLongBuilder;

    public ProfileObjectBuilderFactory(DigestEngine digestEngine, String prefix) {
        this.xmlDsigProfileBuilder = new XmlDsigProfileBuilder();
        this.xadesbesBuilder = new XAdESBESBuilder(prefix);
        this.xadestBuilder = new XAdESTBuilder(digestEngine, prefix);
        this.xadesLongBuilder = new XAdESLongBuilder(digestEngine, prefix);
    }

    public ProfileObjectBuilder forProfile(SignatureProfile profile) {
        return switch (profile) {
            case XMLDSIG -> xmlDsigProfileBuilder;
            case XADES_BES -> xadesbesBuilder;
            case XADES_T -> xadestBuilder;
            case XADES_C, XADES_X_L -> xadesLongBuilder;
        };
    }
}
