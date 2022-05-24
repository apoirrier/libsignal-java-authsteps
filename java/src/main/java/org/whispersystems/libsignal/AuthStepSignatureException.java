package org.whispersystems.libsignal;

public class AuthStepSignatureException extends RuntimeException {
    private final String name;
    private final IdentityKey key;

    public AuthStepSignatureException(String name, IdentityKey key) {
        this.name = name;
        this.key = key;
    }

    public IdentityKey getSignatureKey() {
        return key;
    }

    public String getName() {
        return name;
    }
}
