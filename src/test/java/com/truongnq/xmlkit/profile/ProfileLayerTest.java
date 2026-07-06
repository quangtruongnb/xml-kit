package com.truongnq.xmlkit.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.truongnq.xmlkit.api.PreparedSignature;
import com.truongnq.xmlkit.api.ValidationMaterial;
import com.truongnq.xmlkit.core.DigestEngine;
import com.truongnq.xmlkit.core.SignedInfoBuilder;
import com.truongnq.xmlkit.core.XmlSupport;
import com.truongnq.xmlkit.model.CanonicalizationMethod;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import com.truongnq.xmlkit.model.SignatureProfile;
import com.truongnq.xmlkit.model.SignatureType;
import com.truongnq.xmlkit.testing.FakeRemoteSigner;
import com.truongnq.xmlkit.testing.TestXml;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

class ProfileLayerTest {
    private final DigestEngine digestEngine = new DigestEngine();
    private final SignedInfoBuilder signedInfoBuilder = new SignedInfoBuilder(digestEngine, "ds");
    private final ProfileObjectBuilderFactory factory = new ProfileObjectBuilderFactory(digestEngine, "ds");

    @Test
    void selectsXmlDsigBuilderForXmlDsigProfile() {
        assertInstanceOf(XmlDsigProfileBuilder.class, factory.forProfile(SignatureProfile.XMLDSIG));
    }

    @Test
    void selectsBesBuilderForXadesBesProfile() {
        assertInstanceOf(com.truongnq.xmlkit.profile.xades.XAdESBESBuilder.class, factory.forProfile(SignatureProfile.XADES_BES));
    }

    @Test
    void selectsTBuilderForXadesTProfile() {
        assertInstanceOf(com.truongnq.xmlkit.profile.xades.XAdESTBuilder.class, factory.forProfile(SignatureProfile.XADES_T));
    }

    @Test
    void selectsCBuilderForXadesCProfile() {
        assertInstanceOf(com.truongnq.xmlkit.profile.xades.XAdESCBuilder.class, factory.forProfile(SignatureProfile.XADES_C));
    }

    @Test
    void selectsXLBuilderForXadesXLProfile() {
        assertInstanceOf(com.truongnq.xmlkit.profile.xades.XAdESXLBuilder.class, factory.forProfile(SignatureProfile.XADES_X_L));
    }

    @Test
    void besBuilderCreatesQualifyingPropertiesObject() {
        Element object = factory.forProfile(SignatureProfile.XADES_BES)
            .buildProfileObject(newDocument(SignatureProfile.XADES_BES), null, ValidationMaterial.empty());
        String xml = XmlSupport.toXml(object);

        assertNotNull(object);
        assertEquals("Object", object.getLocalName());
        assertTrue(xml.contains("QualifyingProperties"));
        assertTrue(xml.contains("SignedSignatureProperties"));
        assertTrue(xml.contains("SigningCertificate"));
        assertTrue(xml.contains("CertDigest"));
    }

    @Test
    void tBuilderAddsUnsignedPropertiesWithTimestamp() {
        Element object = factory.forProfile(SignatureProfile.XADES_T)
            .buildProfileObject(newDocument(SignatureProfile.XADES_T), new byte[] {1, 2, 3}, ValidationMaterial.empty());
        String xml = XmlSupport.toXml(object);

        assertTrue(xml.contains("UnsignedProperties"));
        assertTrue(xml.contains("EncapsulatedTimeStamp"));
    }

    @Test
    void longBuilderAddsCertificateRefsAndEmbeddedValuesByProfile() {
        Element cObject = factory.forProfile(SignatureProfile.XADES_C)
            .buildProfileObject(newDocument(SignatureProfile.XADES_C), new byte[] {1, 2, 3}, ValidationMaterial.empty());
        Element xlObject = factory.forProfile(SignatureProfile.XADES_X_L)
            .buildProfileObject(newDocument(SignatureProfile.XADES_X_L), new byte[] {1, 2, 3}, ValidationMaterial.empty());
        String cXml = XmlSupport.toXml(cObject);
        String xlXml = XmlSupport.toXml(xlObject);

        assertTrue(cXml.contains("CompleteCertificateRefs"));
        assertTrue(cXml.contains("CompleteRevocationRefs"));
        assertTrue(xlXml.contains("CertificateValues"));
        assertTrue(xlXml.contains("RevocationValues"));
    }

    private PreparedSignature newDocument(SignatureProfile profile) {
        Document document = TestXml.document("<root><slot/></root>");
        return new PreparedSignature(
            document,
            document.getDocumentElement(),
            List.of(document.getDocumentElement()),
            SignatureType.ENVELOPED,
            profile,
            DigestAlgorithm.SHA256,
            CanonicalizationMethod.C14N_INCLUSIVE,
            FakeRemoteSigner.certificate(),
            signedInfoBuilder.build(
                document,
                List.of(document.getDocumentElement()),
                SignatureType.ENVELOPED,
                DigestAlgorithm.SHA256,
                CanonicalizationMethod.C14N_INCLUSIVE,
                Collections.singletonList(null),
                Collections.singletonList(null),
                null
            ),
            null,
            List.of()
        );
    }
}
