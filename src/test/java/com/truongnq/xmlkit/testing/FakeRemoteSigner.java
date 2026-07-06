package com.truongnq.xmlkit.testing;

import com.truongnq.xmlkit.model.DigestAlgorithm;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public final class FakeRemoteSigner {
    private static final String CERTIFICATE_PEM = """
        -----BEGIN CERTIFICATE-----
        MIIDDzCCAfegAwIBAgIUMu9LlVyenzrAT9cIyJ2seKgUZvMwDQYJKoZIhvcNAQEL
        BQAwFzEVMBMGA1UEAwwMeG1sLWtpdC10ZXN0MB4XDTI2MDYzMDAxNDkzN1oXDTM2
        MDYyNzAxNDkzN1owFzEVMBMGA1UEAwwMeG1sLWtpdC10ZXN0MIIBIjANBgkqhkiG
        9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnbTsxOPJ7m+nne8clctXCchCRvBLoRzDTFPM
        Nj7+XHDlfDI9gr74hAl9SEr3m8clyD0SrtSJIdcszQmrXoY4WN5Ibe3P1WwsTVrU
        n1AlyIiQcRxyI06JotaDP2laJPy7B0Q55KWIm6fleJl9Rq/KucZZ7KBwTggR1z/+
        yFz2f2sqNAvI8SxchZu+i7pfhRy32PtJbR/l0rkfS8UHWrnYy1MpLH/nGY1M/p8D
        9wayFd1b3dgcYQp/hYbtVq91mXUMGfL9S+VHGuvH/TQhN11Gv7Cb+Z3cW8dSJgRv
        DyzOirbTM5jj3KpV1IhC3xiJBvDH1xVYZqkgnWyAoxD54LsGAQIDAQABo1MwUTAd
        BgNVHQ4EFgQUkHV9zVegHutA+OSlO8Oq2lE/YsswHwYDVR0jBBgwFoAUkHV9zVeg
        HutA+OSlO8Oq2lE/YsswDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
        AQEAUqyPrnm1UHnsu4Tkoc2jZOVjtO2sivJ7Ccny7lSmykGv/tV6ouGqZaxpQ76f
        F5syxhHc0XA6vX0gwHs/iyMf7GeGZ1W1vF6qgND3eyQDzWBoEBLhW0vt0IOOKalq
        v/56j6OflqVKpTMa43axmz2qrBSm9O0nLuNnSH3D9xseM94EijH1p+uEm2lI2R/j
        jb+j+ApdAyAKTDNnMzvfc559DYFdkNiLsEEAjzjp8O10mfRTvEDqAFuzRK5b4aY1
        Bm2iK+slYnuV+wiAGtf848yJcVsLM19tZdI3y5mCeMocXgSmBnaNVHcVE3aoBs1Q
        fTGnYCNdP+GVGouffDuAS/z7Zw==
        -----END CERTIFICATE-----
        """;
    private static final String PRIVATE_KEY_PEM = """
        -----BEGIN PRIVATE KEY-----
        MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCdtOzE48nub6ed
        7xyVy1cJyEJG8EuhHMNMU8w2Pv5ccOV8Mj2CvviECX1ISvebxyXIPRKu1Ikh1yzN
        CatehjhY3kht7c/VbCxNWtSfUCXIiJBxHHIjTomi1oM/aVok/LsHRDnkpYibp+V4
        mX1Gr8q5xlnsoHBOCBHXP/7IXPZ/ayo0C8jxLFyFm76Lul+FHLfY+0ltH+XSuR9L
        xQdaudjLUyksf+cZjUz+nwP3BrIV3Vvd2BxhCn+Fhu1Wr3WZdQwZ8v1L5Uca68f9
        NCE3XUa/sJv5ndxbx1ImBG8PLM6KttMzmOPcqlXUiELfGIkG8MfXFVhmqSCdbICj
        EPnguwYBAgMBAAECggEACiQQVjLIO9RN2hp+OJBMPFKhFxBW6fkVrSqgRtwIctJG
        92mq9JAqHndrvm0k/I0y5pbYGjThd93EbDoocloSyn10o9j3FHlcZJb9dXHBFDgv
        2DjPir9Um2DMLL+DWT3acEOuA1VfnOllbeVUyGmqZrAUp+IYhp6p4wZNmv2wqLhr
        XiHOp/w50SNih8K+eM+UNo+YMy+NHaKEiKAwXzcT2d1xjTMTcecevGrA6vjaIqYw
        /dMi6KL/ASgrR4o0tI+QoQqCWKEcM2siL2v9eXVuKHwUzRqWAfzH4zX9FuucCsz9
        n8wUyAEJFQ+13S6VWzl9N+VyiEU90/nfQog82zgoDwKBgQDOC2XXdz2c47cokEAp
        0YbEShN+6RCM4aZB5y6IpnxGGQUImnvDNfQjArgxD9uLz/E0eKSlnjRwT0P05+es
        j+E2E3uL5eB2tCzB21UsjY9+XXK5YXdxHhFpPSZjNvEn3njwpD2YYpeXbOsdKP0E
        ypK33aAL2whqF9Lqkv55F+GFpwKBgQDD8VZOWf8pkvoudbRz1S0PLgEwG+8C7qVT
        rgc2R1VfNNVoJHh5FByAchYlYmYO0xRrwWhugMoIcH9tnK+nVjRCMzBGJeRyK47N
        7Wo5waxausbac/tXmExEdONAltDuHgem9ZefV/wZl0hou4RnpUHhCKKPakfx3ntK
        CwpeoxBcFwKBgAndndi9SuPyO1jj306hS7SmX1yaSEKWo2FQcnf0kMrCc+0/iGGG
        edQbUzp2Ker93+zFQgz0EEq4YOafHAa1NPFj6Wx/a0oDwojduaxScuZ4DwA1XIS8
        DdVeKjJh9RYVnvDWzGQ5hEyp2HAjAEp0cKYBJKKssDB0R5MXyrt9mzzNAoGAEOhH
        MTWUzeqPyeiALKqNW8z1b0hJxHABNgpDNwzKsg9mBrl258OzfeXaQVmPQuI11eJ3
        d2mHhVjntfaaNY87rSarmLH2V1+oz94Xl2o9zApn1DvDyVgr5JBNd6pL1vAiauaw
        MaCu8SpbpiXgE+1vlNJg7I0YLierbcUsHORnKfsCgYBGbqVEJLTTBkgYZgO0nwoi
        YbKkEJjulZrG6hiPtyUG8HayN8AcLTBT9+ujWoeCsv2IY485m+JKhAFCUE0GadLR
        RLeBOrviJG2q6gVnx+8yl92TRG+rmC9QJjXRC9bivZc4PVTFmy2F0eC3fLoUvcLN
        Awd4+9bH2izS3EgaXFh9Og==
        -----END PRIVATE KEY-----
        """;

    private static final X509Certificate CERTIFICATE = parseCertificate();
    private static final PrivateKey PRIVATE_KEY = parsePrivateKey();

    private static final byte[] SHA256_DIGEST_INFO_PREFIX = new byte[] {
        0x30, 0x31, 0x30, 0x0d,
        0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20
    };
    private static final byte[] SHA384_DIGEST_INFO_PREFIX = new byte[] {
        0x30, 0x41, 0x30, 0x0d,
        0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30
    };
    private static final byte[] SHA512_DIGEST_INFO_PREFIX = new byte[] {
        0x30, 0x51, 0x30, 0x0d,
        0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40
    };

    private byte[] lastDigestToSign;

    public static X509Certificate certificate() {
        return CERTIFICATE;
    }

    public static PrivateKey privateKey() {
        return PRIVATE_KEY;
    }

    public byte[] sign(byte[] digestToSign, DigestAlgorithm hashAlgo) {
        try {
            lastDigestToSign = digestToSign.clone();
            Signature signature = Signature.getInstance("NONEwithRSA");
            signature.initSign(PRIVATE_KEY);
            signature.update(wrapForRsaSign(digestToSign, hashAlgo));
            return signature.sign();
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to sign test digest.", exception);
        }
    }

    public byte[] lastDigestToSign() {
        return lastDigestToSign == null ? null : lastDigestToSign.clone();
    }

    public boolean verify(byte[] signatureValue, byte[] digestToVerify, DigestAlgorithm hashAlgo) {
        try {
            Signature verifier = Signature.getInstance("NONEwithRSA");
            verifier.initVerify(CERTIFICATE.getPublicKey());
            verifier.update(wrapForRsaSign(digestToVerify, hashAlgo));
            return verifier.verify(signatureValue);
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to verify test signature.", exception);
        }
    }

    // NONEwithRSA does not hash or wrap anything for us. It expects the caller
    // to provide the full PKCS#1 v1.5 DigestInfo payload:
    //   SEQUENCE {
    //     AlgorithmIdentifier(<hash OID>, NULL),
    //     OCTET STRING(<digest bytes>)
    //   }
    // These prefix constants are the DER-encoded bytes for that structure up to
    // the start of the digest value, so wrapping is just prefix + digest.
    private static byte[] wrapForRsaSign(byte[] digest, DigestAlgorithm hashAlgo) {
        byte[] digestInfoPrefix = switch (hashAlgo) {
            case SHA256 -> SHA256_DIGEST_INFO_PREFIX;
            case SHA384 -> SHA384_DIGEST_INFO_PREFIX;
            case SHA512 -> SHA512_DIGEST_INFO_PREFIX;
        };
        byte[] digestInfo = new byte[digestInfoPrefix.length + digest.length];
        System.arraycopy(digestInfoPrefix, 0, digestInfo, 0, digestInfoPrefix.length);
        System.arraycopy(digest, 0, digestInfo, digestInfoPrefix.length, digest.length);
        return digestInfo;
    }

    private static X509Certificate parseCertificate() {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(CERTIFICATE_PEM.getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to parse test certificate.", exception);
        }
    }

    private static PrivateKey parsePrivateKey() {
        try {
            String pemBody = PRIVATE_KEY_PEM
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
            byte[] encoded = Base64.getDecoder().decode(pemBody);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to parse test private key.", exception);
        }
    }
}
