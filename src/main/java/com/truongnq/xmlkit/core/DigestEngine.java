package com.truongnq.xmlkit.core;

import com.truongnq.xmlkit.exception.XmlKitException;
import com.truongnq.xmlkit.model.DigestAlgorithm;
import java.security.MessageDigest;
import java.util.Base64;

public final class DigestEngine {
    public byte[] digest(DigestAlgorithm algorithm, byte[] input) {
        try {
            return MessageDigest.getInstance(algorithm.jcaName()).digest(input);
        } catch (Exception exception) {
            throw new XmlKitException("Unable to compute digest with " + algorithm.jcaName() + ".", exception);
        }
    }

    public String digestBase64(DigestAlgorithm algorithm, byte[] input) {
        return Base64.getEncoder().encodeToString(digest(algorithm, input));
    }

    public String base64(byte[] input) {
        return Base64.getEncoder().encodeToString(input);
    }
}
