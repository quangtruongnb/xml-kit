package com.truongnq.xmlkit.api;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.model.SignatureType;
import com.truongnq.xmlkit.testing.TestXml;
import org.junit.jupiter.api.Test;

class XadesSigningFlowTest {
    @Test
    void extendedRequestExposesSignatureValueDigestAndTimestampCompletion() {
        ExtendedSigningRequest request = (ExtendedSigningRequest) XmlSignatureBuilder.forDocument(
                TestXml.document("<root><slot/></root>"))
            .signatureType(SignatureType.ENVELOPED)
            .profile(SignatureProfile.XADES_T)
            .placementXPath("//slot")
            .prepare();

        assertTrue(request.getSignatureValueDigest(new byte[] {9, 8, 7}).length > 0);

        SignedDocument signed = request.complete(new byte[] {9, 8, 7}, new byte[] {7, 8, 9});

        assertTrue(signed.xml().contains("UnsignedProperties"));
        assertTrue(signed.xml().contains("EncapsulatedTimeStamp"));
    }
}
