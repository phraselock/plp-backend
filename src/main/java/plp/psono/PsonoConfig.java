package plp.psono;

/**
 * Immutable configuration for {@link PsonoRestrictedClient} and {@link PsonoUnrestrictedClient}: combines a shared
 * {@link PsonoServerConfig} with API-key-specific credentials.
 *
 * <p>Example – one server, multiple API keys:</p>
 * <pre>{@code
 * PsonoServerConfig server = PsonoServerConfig.builder()
 *     .serverUrl("https://…")
 *     .serverPublicKey("…")
 *     .serverSignature("…")
 *     .build();
 *
 * PsonoConfig cfg1 = PsonoConfig.builder().server(server).apiKeyId("…")…build();
 * PsonoConfig cfg2 = PsonoConfig.builder().server(server).apiKeyId("…")…build();
 * }</pre>
 */
public final class PsonoConfig {

    // ── Composed server config ────────────────────────────────────────────────

    private final PsonoServerConfig server;

    // ── API-key-specific fields ───────────────────────────────────────────────

    private final String apiKeyId;
    private final String apiKeyPrivateKey;
    private final String apiKeySecretKey;

    // ── Optional fields (with defaults) ──────────────────────────────────────

    private final String deviceDescription;

    // ── Constructor (private – use Builder) ───────────────────────────────────

    private PsonoConfig(Builder b) {
        this.server            = b.server;
        this.apiKeyId          = b.apiKeyId;
        this.apiKeyPrivateKey  = b.apiKeyPrivateKey;
        this.apiKeySecretKey   = b.apiKeySecretKey;
        this.deviceDescription = b.deviceDescription;
    }

    // ── Accessors – server (delegated) ────────────────────────────────────────

    public PsonoServerConfig getServer()       { return server; }
    public String getServerUrl()               { return server.getServerUrl(); }
    public String getServerPublicKey()         { return server.getServerPublicKey(); }
    public String getServerSignature()         { return server.getServerSignature(); }

    // ── Accessors – API key ───────────────────────────────────────────────────

    public String getApiKeyId()          { return apiKeyId; }
    public String getApiKeyPrivateKey()  { return apiKeyPrivateKey; }
    public String getApiKeySecretKey()   { return apiKeySecretKey; }
    public String getDeviceDescription() { return deviceDescription; }

    // ── Builder ───────────────────────────────────────────────────────────────

    public static Builder builder() { return new Builder(); }

    public static final class Builder {

        // Required
        private PsonoServerConfig server;
        private String apiKeyId;
        private String apiKeyPrivateKey;
        private String apiKeySecretKey;

        // Optional
        private String deviceDescription = "Phraselock Bridge";

        private Builder() {}

        public Builder server(PsonoServerConfig v)  { this.server           = v; return this; }
        public Builder apiKeyId(String v)           { this.apiKeyId          = v; return this; }
        public Builder apiKeyPrivateKey(String v)   { this.apiKeyPrivateKey  = v; return this; }
        public Builder apiKeySecretKey(String v)    { this.apiKeySecretKey   = v; return this; }
        public Builder deviceDescription(String v)  { this.deviceDescription = v; return this; }

        public PsonoConfig build() {
            if (server           == null) throw new IllegalStateException("server is required");
            if (apiKeyId         == null) throw new IllegalStateException("apiKeyId is required");
            if (apiKeyPrivateKey == null) throw new IllegalStateException("apiKeyPrivateKey is required");
            if (apiKeySecretKey  == null) throw new IllegalStateException("apiKeySecretKey is required");
            return new PsonoConfig(this);
        }
    }
}
