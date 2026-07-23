package plp.psono;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.interfaces.SecretBox;
import com.goterl.lazysodium.interfaces.Sign;
import com.goterl.lazysodium.utils.Key;
import com.goterl.lazysodium.utils.KeyPair;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ipoxo.plcore.lib.Log;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class PsonoRestrictedClient {

    // ── Endpoints ─────────────────────────────────────────────────────────────

    private static final String ENDPOINT_LOGIN          = "/api-key/login/";
    private static final String ENDPOINT_SECRET_LIST    = "/api-key/secret/";
    private static final String ENDPOINT_SECRET_ACCESS  = "/api-key-access/secret/";

    // ── Request / response field names ────────────────────────────────────────

    private static final String FIELD_API_KEY_ID                = "api_key_id";
    private static final String FIELD_SESSION_PUBLIC_KEY        = "session_public_key";
    private static final String FIELD_DEVICE_DESCRIPTION        = "device_description";
    private static final String FIELD_INFO                      = "info";
    private static final String FIELD_SIGNATURE                 = "signature";
    private static final String FIELD_SERVER_SESSION_PUBLIC_KEY = "server_session_public_key";
    private static final String FIELD_LOGIN_INFO                = "login_info";
    private static final String FIELD_LOGIN_INFO_NONCE          = "login_info_nonce";
    private static final String FIELD_TOKEN                     = "token";
    private static final String FIELD_SESSION_SECRET_KEY        = "session_secret_key";
    private static final String FIELD_SECRET_ID                 = "secret_id";
    private static final String FIELD_API_KEY_SECRET_KEY        = "api_key_secret_key";
    private static final String FIELD_TEXT                      = "text";
    private static final String FIELD_NONCE                     = "nonce";

    // ── Result map keys (returned to callers) ─────────────────────────────────

    public static final String KEY_SECRET_ID = "secret_id";
    public static final String KEY_NAME      = "name";
    /** Decrypted secret fields as {@code Map<?,?>} — directly serialisable as a JSON object. */
    public static final String KEY_CONTENT   = "content";
    /** Origin metadata as {@code Map<String,Object>} — source, folder_path, type. */
    public static final String KEY_META      = "meta";

    // ── Misc constants ────────────────────────────────────────────────────────

    private static final String HEADER_CONTENT_TYPE = "Content-Type";
    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String MIME_JSON            = "application/json";
    private static final String AUTH_TOKEN_PREFIX    = "Token ";

    // ── State ─────────────────────────────────────────────────────────────────

    private final LazySodiumJava lazySodium;
    private final HttpClient     http;
    private final ObjectMapper   mapper;
    private final PsonoConfig    config;

    private String sessionToken;
    private String sessionSecretKey;   // symmetric transport key (SecretBox)

    // ── Constructor ───────────────────────────────────────────────────────────

    public PsonoRestrictedClient(PsonoConfig config) {
        this.config      = config;
        this.lazySodium  = new LazySodiumJava(new SodiumJava());
        this.http        = HttpClient.newHttpClient();
        this.mapper      = new ObjectMapper();
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    /**
     * Authenticates against the Psono server using the configured API key.
     * Stores the session token and transport key for subsequent calls.
     *
     * @return ok(null) on success, fail(message) on any error
     */
    public PsonoResult<Void> login() {
        try {
            KeyPair sessionKeypair    = lazySodium.cryptoBoxKeypair();
            String  sessionPublicKey  = sessionKeypair.getPublicKey().getAsHexString().toLowerCase();
            String  sessionPrivateKey = sessionKeypair.getSecretKey().getAsHexString().toLowerCase();

            Map<String, String> infoMap = new LinkedHashMap<>();
            infoMap.put(FIELD_API_KEY_ID,         config.getApiKeyId());
            infoMap.put(FIELD_SESSION_PUBLIC_KEY,  sessionPublicKey);
            infoMap.put(FIELD_DEVICE_DESCRIPTION,  config.getDeviceDescription());
            String infoJson = mapper.writeValueAsString(infoMap);

            Map<String, String> body = new LinkedHashMap<>();
            body.put(FIELD_INFO,      infoJson);
            body.put(FIELD_SIGNATURE, signDetached(infoJson));

            HttpResponse<String> resp = rawPost(ENDPOINT_LOGIN, mapper.writeValueAsString(body));
            if (resp.statusCode() != 200)
                return PsonoResult.fail("Login failed (HTTP " + resp.statusCode() + "): " + resp.body());

            Map<?, ?> respMap = mapper.readValue(resp.body(), Map.class);
            KeyPair decryptKp = new KeyPair(
                Key.fromHexString((String) respMap.get(FIELD_SERVER_SESSION_PUBLIC_KEY)),
                Key.fromHexString(sessionPrivateKey)
            );
            byte[] nonce    = Key.fromHexString((String) respMap.get(FIELD_LOGIN_INFO_NONCE)).getAsBytes();
            String decrypted = lazySodium.cryptoBoxOpenEasy(
                (String) respMap.get(FIELD_LOGIN_INFO), nonce, decryptKp);

            Map<?, ?> info = mapper.readValue(decrypted, Map.class);
            sessionToken     = (String) info.get(FIELD_TOKEN);
            sessionSecretKey = (String) info.get(FIELD_SESSION_SECRET_KEY);

            boolean restrictToSecrets   = Boolean.TRUE.equals(info.get("api_key_restrict_to_secrets"));
            boolean allowInsecureAccess = Boolean.TRUE.equals(info.get("api_key_allow_insecure_access"));

            Log.i("Login OK – restrict_to_secrets: " + restrictToSecrets
                + ", allow_insecure: " + allowInsecureAccess);

            // PsonoRestrictedClient requires server-side decryption via /api-key-access/secret/.
            // This only works when both flags are set correctly on the API key in Psono.
            if (!restrictToSecrets)
                return PsonoResult.fail(
                    "API key configuration mismatch: 'Restrict to secrets' is OFF. " +
                    "Use PsonoUnrestrictedClient for this key, or enable the restriction in Psono.");
            if (!allowInsecureAccess)
                return PsonoResult.fail(
                    "API key configuration mismatch: 'Allow insecure access' is OFF. " +
                    "Enable it in Psono for this API key, or use PsonoUnrestrictedClient instead.");

            return PsonoResult.ok(null);

        } catch (Exception e) {
            return PsonoResult.fail("Login error: " + e.getMessage());
        }
    }

    // ── Secret list ───────────────────────────────────────────────────────────

    /**
     * Fetches the list of secrets linked to this API key.
     * Requires a successful {@link #login()} call first.
     *
     * @return ok(list) where each entry has "secret_id", "title", …; or fail(message)
     */
    @SuppressWarnings("unchecked")
    public PsonoResult<List<Map<String, Object>>> fetchLinkedSecrets() {
        try {
            String endpoint = ENDPOINT_SECRET_LIST + config.getApiKeyId() + "/";
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(config.getServerUrl() + endpoint))
                .header(HEADER_CONTENT_TYPE, MIME_JSON)
                .header(HEADER_AUTHORIZATION, AUTH_TOKEN_PREFIX + sessionToken)
                .GET()
                .build();

            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            Log.i("GET " + endpoint + " → " + resp.statusCode());

            if (resp.statusCode() != 200)
                return PsonoResult.fail("fetchLinkedSecrets failed (HTTP " + resp.statusCode() + "): " + resp.body());

            String plain = decryptTransport(resp.body());
            return PsonoResult.ok(mapper.readValue(plain, List.class));

        } catch (Exception e) {
            return PsonoResult.fail("fetchLinkedSecrets error: " + e.getMessage());
        }
    }

    // ── High-level API ────────────────────────────────────────────────────────

    /**
     * Fetches all secrets linked to this API key and returns them in the same
     * structure as {@code PsonoUnrestrictedClient.fetchAllSecrets()}.
     *
     * Each entry contains {@value #KEY_SECRET_ID}, {@value #KEY_NAME},
     * {@value #KEY_CONTENT} (as {@code Map<?,?>}) and {@value #KEY_META}.
     */
    public PsonoResult<List<Map<String, Object>>> fetchAllSecrets() {
        try {
            var linkedResult = fetchLinkedSecrets();
            if (linkedResult.isFailed())
                return PsonoResult.fail(linkedResult.getMessage());

            List<Map<String, Object>> result = new java.util.ArrayList<>();

            for (Map<String, Object> s : linkedResult.getValue()) {
                String secretId = (String) s.get(FIELD_SECRET_ID);
                String title    = (String) s.getOrDefault("title", "");

                var contentResult = fetchSecretContent(secretId);
                if (contentResult.isFailed()) {
                    Log.e("  Could not fetch secret " + secretId + ": " + contentResult.getMessage());
                    continue;
                }

                Map<?, ?> contentMap = mapper.readValue(contentResult.getValue(), Map.class);

                Map<String, Object> meta = new LinkedHashMap<>();
                meta.put("source",      "restricted");
                meta.put("share_name",  "");
                meta.put("share_id",    "");
                meta.put("group_name",  "");
                meta.put("group_id",    "");
                meta.put("folder_path", new java.util.ArrayList<>());
                meta.put("type",        s.getOrDefault("type", ""));

                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put(KEY_SECRET_ID, secretId);
                entry.put(KEY_NAME,      title);
                entry.put(KEY_CONTENT,   contentMap);
                entry.put(KEY_META,      meta);
                result.add(entry);
            }
            return PsonoResult.ok(result);

        } catch (Exception e) {
            return PsonoResult.fail("fetchAllSecrets error: " + e.getMessage());
        }
    }

    // ── Secret content ────────────────────────────────────────────────────────

    /**
     * Reads and decrypts a single secret server-side via the session-less endpoint.
     * The server performs decryption using the api_key_secret_key – no auth header needed.
     * Requires {@code api_key_allow_insecure_access = true} on the API key.
     *
     * @param secretId UUID of the secret to fetch
     * @return ok(json string) with the decrypted secret content; or fail(message)
     */
    public PsonoResult<String> fetchSecretContent(String secretId) {
        try {
            Map<String, String> body = new LinkedHashMap<>();
            body.put(FIELD_API_KEY_ID,         config.getApiKeyId());
            body.put(FIELD_SECRET_ID,          secretId);
            body.put(FIELD_API_KEY_SECRET_KEY, config.getApiKeySecretKey());

            HttpResponse<String> resp = rawPost(ENDPOINT_SECRET_ACCESS, mapper.writeValueAsString(body));
            Log.i("POST " + ENDPOINT_SECRET_ACCESS + " → " + resp.statusCode());

            if (resp.statusCode() != 200)
                return PsonoResult.fail("fetchSecretContent failed (HTTP " + resp.statusCode() + "): " + resp.body());

            return PsonoResult.ok(resp.body());

        } catch (Exception e) {
            return PsonoResult.fail("fetchSecretContent error: " + e.getMessage());
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Decrypts a transport-wrapped response {"text":hex,"nonce":hex} with the session_secret_key. */
    @SuppressWarnings("unchecked")
    private String decryptTransport(String responseJson) throws Exception {
        Map<String, String> wrapped = mapper.readValue(responseJson, Map.class);
        byte[] ct    = Key.fromHexString(wrapped.get(FIELD_TEXT)).getAsBytes();
        byte[] nonce = Key.fromHexString(wrapped.get(FIELD_NONCE)).getAsBytes();
        byte[] sk    = Key.fromHexString(sessionSecretKey).getAsBytes();
        byte[] plain = new byte[ct.length - SecretBox.MACBYTES];
        int r = lazySodium.getSodium().crypto_secretbox_open_easy(plain, ct, ct.length, nonce, sk);
        if (r != 0) throw new RuntimeException("Transport decryption: MAC verification failed");
        return new String(plain, StandardCharsets.UTF_8);
    }

    private HttpResponse<String> rawPost(String endpoint, String jsonBody) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(config.getServerUrl() + endpoint))
            .header(HEADER_CONTENT_TYPE, MIME_JSON)
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Signs a UTF-8 message with the Ed25519 private key (supports 32-byte seed or 64-byte key).
     */
    private String signDetached(String message) {
        byte[] keyBytes = Key.fromHexString(config.getApiKeyPrivateKey()).getAsBytes();
        byte[] sk;
        if (keyBytes.length == Sign.SECRETKEYBYTES) {
            sk = keyBytes;
        } else {
            // 32-byte seed → derive full 64-byte Ed25519 key
            byte[] pk = new byte[Sign.PUBLICKEYBYTES];
            sk = new byte[Sign.SECRETKEYBYTES];
            lazySodium.getSodium().crypto_sign_seed_keypair(pk, sk, keyBytes);
        }
        byte[] sig = new byte[Sign.BYTES];
        byte[] msg = message.getBytes(StandardCharsets.UTF_8);
        lazySodium.getSodium().crypto_sign_detached(sig, null, msg, msg.length, sk);
        return lazySodium.toHexStr(sig);
    }

    public String getToken() { return sessionToken; }

    /** Resets the session — the next call to {@link #login()} starts a new session. */
    public void logout()
    {
        sessionToken     = null;
        sessionSecretKey = null;
    }
}
