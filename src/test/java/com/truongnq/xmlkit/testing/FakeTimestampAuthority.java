package com.truongnq.xmlkit.testing;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class FakeTimestampAuthority {
    private byte[] lastDigest;

    public byte[] timestamp(byte[] digest) {
        this.lastDigest = digest.clone();
        return ("timestamp-token:" + Base64.getEncoder().encodeToString(digest))
            .getBytes(StandardCharsets.US_ASCII);
    }

    public byte[] lastDigest() {
        return lastDigest == null ? null : lastDigest.clone();
    }
}
