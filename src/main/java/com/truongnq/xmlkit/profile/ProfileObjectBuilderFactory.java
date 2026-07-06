package com.truongnq.xmlkit.profile;

import com.truongnq.xmlkit.core.DigestEngine;
import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.profile.xades.XAdESBESBuilder;
import com.truongnq.xmlkit.profile.xades.XAdESCBuilder;
import com.truongnq.xmlkit.profile.xades.XAdESTBuilder;
import com.truongnq.xmlkit.profile.xades.XAdESXLBuilder;

public final class ProfileObjectBuilderFactory {
    private final XmlDsigProfileBuilder xmlDsigProfileBuilder;
    private final XAdESBESBuilder xadesbesBuilder;
    private final XAdESTBuilder xadestBuilder;
    private final XAdESCBuilder xadesCBuilder;
    private final XAdESXLBuilder xadesXLBuilder;

    public ProfileObjectBuilderFactory(DigestEngine digestEngine, String prefix) {
        this.xmlDsigProfileBuilder = new XmlDsigProfileBuilder();
        this.xadesbesBuilder = new XAdESBESBuilder(digestEngine, prefix);
        this.xadestBuilder = new XAdESTBuilder(digestEngine, prefix);
        this.xadesCBuilder = new XAdESCBuilder(digestEngine, prefix);
        this.xadesXLBuilder = new XAdESXLBuilder(digestEngine, prefix);
    }

    public ProfileObjectBuilder forProfile(SignatureProfile profile) {
        return switch (profile) {
            case XMLDSIG -> xmlDsigProfileBuilder;
            case XADES_BES -> xadesbesBuilder;
            case XADES_T -> xadestBuilder;
            case XADES_C -> xadesCBuilder;
            case XADES_X_L -> xadesXLBuilder;
        };
    }
}
