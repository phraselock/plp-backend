package plp.psono;

/**
 * Immutable configuration for a single Psono server instance.
 * Can be shared across multiple {@link PsonoConfig} / {@link PsonoRestrictedClient} / {@link PsonoUnrestrictedClient} instances
 * that use different API keys on the same server.
 *
 * <p>Use {@link Builder} to construct an instance.</p>
 */
public final class PsonoServerConfig {

    private final String serverUrl;
    private final String serverPublicKey;
    private final String serverSignature;

    private PsonoServerConfig(Builder b) {
        this.serverUrl       = b.serverUrl;
        this.serverPublicKey = b.serverPublicKey;
        this.serverSignature = b.serverSignature;
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    public String getServerUrl()       { return serverUrl; }
    public String getServerPublicKey() { return serverPublicKey; }
    public String getServerSignature() { return serverSignature; }

    // ── Builder ───────────────────────────────────────────────────────────────

    public static Builder builder() { return new Builder(); }

    public static final class Builder {

        private String serverUrl;
        private String serverPublicKey;
        private String serverSignature;

        private Builder() {}

        public Builder serverUrl(String v)       { this.serverUrl       = v; return this; }
        public Builder serverPublicKey(String v) { this.serverPublicKey = v; return this; }
        public Builder serverSignature(String v) { this.serverSignature = v; return this; }

        public PsonoServerConfig build() {
            if (serverUrl       == null) throw new IllegalStateException("serverUrl is required");
            if (serverPublicKey == null) throw new IllegalStateException("serverPublicKey is required");
            if (serverSignature == null) throw new IllegalStateException("serverSignature is required");
            return new PsonoServerConfig(this);
        }
    }
}
