package com.truongnq.xmlkit.testing;

import com.truongnq.xmlkit.model.DigestAlgorithm;
import java.security.Signature;

public final class FakeRemoteSigner {
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

    public byte[] sign(byte[] digestToSign, DigestAlgorithm hashAlgo) {
        try {
            lastDigestToSign = digestToSign.clone();
            Signature signature = Signature.getInstance("NONEwithRSA");
            signature.initSign(TestCertificates.privateKey());
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
            verifier.initVerify(TestCertificates.certificate().getPublicKey());
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
}
