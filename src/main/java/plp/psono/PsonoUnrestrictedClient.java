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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Psono client for API keys with {@code restrict_to_secrets = false}.
 *
 * <p>Unlike {@link PsonoRestrictedClient} (which uses server-side decryption via
 * {@code /api-key-access/secret/}), this client performs full client-side
 * decryption following a four-layer key chain:</p>
 * <ol>
 *   <li><b>Transport</b>      – SecretBox({@code session_secret_key}) unwraps every HTTP response</li>
 *   <li><b>User key</b>       – SecretBox({@code api_key_secret_key}) decrypts {@code user.secret_key}
 *       from the login response → {@code userSecretKey}</li>
 *   <li><b>Datastore key</b>  – SecretBox({@code userSecretKey}) decrypts the per-datastore
 *       {@code secret_key} in the datastore envelope → {@code dsKey}</li>
 *   <li><b>Data / Secrets</b> – SecretBox({@code dsKey}) decrypts {@code data} → plaintext tree;
 *       each item's own {@code secret_key} decrypts its individual secret payload</li>
 * </ol>
 *
 * <p>In addition to items stored directly in the user's datastore, this client
 * reads secrets from two additional sources:</p>
 * <ul>
 *   <li><b>Individual shares</b> – secrets that other Psono users have shared
 *       directly with this service account. Accepted shares appear in the datastore
 *       tree via a {@code share_index} (the share key is stored plaintext inside the
 *       encrypted {@code data} blob). Each share is fetched via
 *       {@code GET /share/{id}/} and decrypted with its {@code secret_key}.</li>
 *   <li><b>Group shares</b> – secrets shared with a Psono group that this service
 *       account belongs to. Group membership replaces individual acceptance: the
 *       client fetches all accepted group memberships ({@code GET /group/}),
 *       decrypts the group's symmetric key ({@code group.secret_key}, SecretBox
 *       with {@code userSecretKey}), then fetches each group's share rights
 *       ({@code GET /group/{id}/}) and decrypts every share key with that group key
 *       before reading the share content.</li>
 * </ul>
 *
 * <p>Requires an unrestricted API key (created without
 * "Restrict to secrets" in Psono).</p>
 */
public class PsonoUnrestrictedClient {

    // ── Endpoints ─────────────────────────────────────────────────────────────

    private static final String ENDPOINT_LOGIN       = "/api-key/login/";
    private static final String ENDPOINT_DATASTORE   = "/datastore/";
    private static final String ENDPOINT_SECRET      = "/secret/";
    private static final String ENDPOINT_SHARE       = "/share/";
    private static final String ENDPOINT_SHARE_RIGHT = "/share/right/";
    private static final String ENDPOINT_GROUP       = "/group/";

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
    private static final String FIELD_USER                      = "user";
    private static final String FIELD_USER_SECRET_KEY           = "secret_key";
    private static final String FIELD_USER_SECRET_KEY_NONCE     = "secret_key_nonce";
    private static final String FIELD_TEXT                      = "text";
    private static final String FIELD_NONCE                     = "nonce";
    private static final String FIELD_DATA                      = "data";
    private static final String FIELD_DATA_NONCE                = "data_nonce";
    private static final String FIELD_DS_SECRET_KEY             = "secret_key";
    private static final String FIELD_DS_SECRET_KEY_NONCE       = "secret_key_nonce";
    private static final String FIELD_SECRET_ID                 = "secret_id";
    private static final String FIELD_SECRET_KEY                = "secret_key";
    private static final String FIELD_SHARE_INDEX               = "share_index";
    private static final String FIELD_SHARE_SECRET_KEY          = "secret_key";   // within a share_index entry

    private static final String DATASTORE_TYPE_PASSWORD         = "password";

    private static final Boolean DBG                            = false;
    // ── Result map keys (returned to callers) ─────────────────────────────────

    public static final String KEY_SECRET_ID = "secret_id";
    public static final String KEY_NAME      = "name";
    public static final String KEY_TYPE      = "type";
    /** Decrypted secret fields as {@code Map<?,?>} — direkt als JSON-Objekt serialisierbar. */
    public static final String KEY_CONTENT   = "content";
    /**
     * Origin metadata as a {@code Map<String, Object>} with the following fields:
     * <ul>
     *   <li><b>source</b>      – {@code "datastore"}, {@code "share"}, or {@code "group_share"}</li>
     *   <li><b>share_name</b>  – name of the share; {@code ""} for direct datastore items</li>
     *   <li><b>group_name</b>  – name of the Psono group the share belongs to;
     *       {@code ""} for datastore items and individually accepted shares</li>
     *   <li><b>folder_path</b> – {@code List<String>} of folder names from tree root
     *       to the secret's parent; empty list when at the top level</li>
     *   <li><b>type</b>        – secret type string (e.g. {@code "website_password"})</li>
     * </ul>
     * Serialise with Jackson to get a clean JSON object.
     */
    public static final String KEY_META = "meta";

    // ── Misc constants ────────────────────────────────────────────────────────

    private static final String HEADER_CONTENT_TYPE  = "Content-Type";
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
    private String userSecretKey;      // user's actual datastore key (decrypted from login response)

    // ── Constructor ───────────────────────────────────────────────────────────

    public PsonoUnrestrictedClient(PsonoConfig config) {
        this.config     = config;
        this.lazySodium = new LazySodiumJava(new SodiumJava());
        this.http       = HttpClient.newHttpClient();
        this.mapper     = new ObjectMapper();
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    /**
     * Authenticates against the Psono server.
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
            byte[] nonce     = Key.fromHexString((String) respMap.get(FIELD_LOGIN_INFO_NONCE)).getAsBytes();
            String decrypted = lazySodium.cryptoBoxOpenEasy(
                (String) respMap.get(FIELD_LOGIN_INFO), nonce, decryptKp);

            Map<?, ?> info = mapper.readValue(decrypted, Map.class);
            sessionToken     = (String) info.get(FIELD_TOKEN);
            sessionSecretKey = (String) info.get(FIELD_SESSION_SECRET_KEY);

            boolean restrictToSecrets   = Boolean.TRUE.equals(info.get("api_key_restrict_to_secrets"));
            boolean allowInsecureAccess = Boolean.TRUE.equals(info.get("api_key_allow_insecure_access"));

            if(DBG) Log.i("Login OK – restrict_to_secrets: " + restrictToSecrets
                + ", allow_insecure: " + allowInsecureAccess);

            // PsonoUnrestrictedClient requires full datastore access with client-side decryption.
            // This only works when restrict_to_secrets is OFF on the API key in Psono.
            if (restrictToSecrets)
                return PsonoResult.fail(
                    "API key configuration mismatch: 'Restrict to secrets' is ON. " +
                    "Use PsonoRestrictedClient for this key, or disable the restriction in Psono.");

            // For unrestricted API keys the login response contains the user's
            // datastore key, encrypted with api_key_secret_key (SecretBox).
            // Decrypt it here so it is available for datastore decryption later.
            Map<?, ?> userMap = (Map<?, ?>) info.get(FIELD_USER);
            if (userMap == null) {
                return PsonoResult.fail(
                    "Login response missing 'user' object – " +
                    "is this API key created without 'Restrict to secrets'?");
            }
            if (!userMap.containsKey(FIELD_USER_SECRET_KEY)) {
                return PsonoResult.fail(
                    "Login response user object missing 'secret_key' – " +
                    "is this API key created without 'Restrict to secrets'?");
            }

            userSecretKey = decryptWithKey(
                (String) userMap.get(FIELD_USER_SECRET_KEY),
                (String) userMap.get(FIELD_USER_SECRET_KEY_NONCE),
                config.getApiKeySecretKey()
            );

            return PsonoResult.ok(null);

        } catch (Exception e) {
            return PsonoResult.fail("Login error: " + e.getMessage());
        }
    }

    // ── High-level API ────────────────────────────────────────────────────────

    /**
     * Fetches and decrypts all secrets reachable via this API key's datastore(s).
     *
     * <p>Each entry in the returned list contains:</p>
     * <ul>
     *   <li>{@value #KEY_SECRET_ID} – UUID of the secret</li>
     *   <li>{@value #KEY_NAME}      – display name from the datastore tree</li>
     *   <li>{@value #KEY_CONTENT}   – decrypted credential fields plus an embedded
     *       {@code "meta"} object (serialised JSON string)</li>
     *   <li>{@value #KEY_META}      – the same {@code meta} object as a pre-parsed
     *       {@code Map<String,Object>} for programmatic access without re-parsing</li>
     * </ul>
     *
     * <p>The {@code meta} object contains:
     * {@code source} ("datastore" | "share"), {@code share_name},
     * {@code folder_path} (List&lt;String&gt;), and {@code type}.</p>
     *
     * @return ok(list) on success, fail(message) on any error
     */
    @SuppressWarnings("unchecked")
    public PsonoResult<List<Map<String, Object>>> fetchAllSecrets() {
        try {
            List<Map<String, Object>> refs = loadSecretRefs();
            List<Map<String, Object>> result = new ArrayList<>();

            for (Map<String, Object> ref : refs) {
                String secretId  = (String) ref.get(FIELD_SECRET_ID);
                String secretKey = (String) ref.get(FIELD_SECRET_KEY);
                String name      = (String) ref.getOrDefault("name", "");
                String type      = (String) ref.getOrDefault("type", "");

                PsonoResult<String> contentResult = fetchAndDecryptSecret(secretId, secretKey);
                if (contentResult.isFailed()) {
                    Log.e("  Could not decrypt secret " + secretId + ": " + contentResult.getMessage());
                    continue;
                }

                Map<String, Object> meta        = buildMeta(ref, type);
                Map<?, ?>           contentMap  = mapper.readValue(contentResult.getValue(), Map.class);

                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put(KEY_SECRET_ID, secretId);
                entry.put(KEY_NAME,      name);
                entry.put(KEY_CONTENT,   contentMap);
                entry.put(KEY_META,      meta);
                result.add(entry);
            }
            return PsonoResult.ok(result);

        } catch (Exception e) {
            return PsonoResult.fail("fetchAllSecrets error: " + e.getMessage());
        }
    }

    /**
     * Fetches and decrypts a single secret by its UUID.
     * Traverses all password datastores to locate the matching secret_key.
     *
     * <p>The returned map contains {@value #KEY_SECRET_ID}, {@value #KEY_NAME},
     * {@value #KEY_CONTENT} (with embedded {@code meta}), and {@value #KEY_META}.</p>
     *
     * @param secretId UUID of the secret to fetch
     * @return ok(map) on success, fail(message) if not found or decryption fails
     */
    public PsonoResult<Map<String, Object>> fetchSecretById(String secretId) {
        try {
            List<Map<String, Object>> refs = loadSecretRefs();

            Map<String, Object> ref = refs.stream()
                .filter(r -> secretId.equals(r.get(FIELD_SECRET_ID)))
                .findFirst()
                .orElse(null);

            if (ref == null)
                return PsonoResult.fail("Secret not found in any password datastore: " + secretId);

            PsonoResult<String> contentResult = fetchAndDecryptSecret(
                secretId, (String) ref.get(FIELD_SECRET_KEY));
            if (contentResult.isFailed())
                return PsonoResult.fail(contentResult.getMessage());

            String type = (String) ref.getOrDefault("type", "");
            Map<String, Object> meta       = buildMeta(ref, type);
            Map<?, ?>           contentMap = mapper.readValue(contentResult.getValue(), Map.class);

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put(KEY_SECRET_ID, secretId);
            entry.put(KEY_NAME,      ref.getOrDefault("name", ""));
            entry.put(KEY_CONTENT,   contentMap);
            entry.put(KEY_META,      meta);
            return PsonoResult.ok(entry);

        } catch (Exception e) {
            return PsonoResult.fail("fetchSecretById error: " + e.getMessage());
        }
    }

    // ── Internal steps ────────────────────────────────────────────────────────

    /**
     * Fetches and decrypts all password datastores and returns a flat list of
     * all secret references (each map has at least secret_id, secret_key, name, type).
     * Used by both {@link #fetchAllSecrets()} and {@link #fetchSecretById(String)}.
     */
    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> loadSecretRefs() throws Exception {
        // Step 1: list datastores
        HttpResponse<String> dsListResp = rawGet(ENDPOINT_DATASTORE);
        if (dsListResp.statusCode() != 200)
            throw new RuntimeException("fetchDatastores failed (HTTP " + dsListResp.statusCode() + "): " + dsListResp.body());

        String    dsListPlain   = decryptTransport(dsListResp.body());
        Map<?, ?> dsListWrapper = mapper.readValue(dsListPlain, Map.class);

        Object dsRaw = dsListWrapper.containsKey("datastores")
            ? dsListWrapper.get("datastores")
            : mapper.readValue(dsListPlain, List.class);

        List<Map<String, Object>> datastores = (List<Map<String, Object>>) dsRaw;
        List<Map<String, Object>> allRefs    = new ArrayList<>();

        // Fetch the set of share IDs the user actually has individual read rights to.
        // The server only returns accepted, non-revoked rights → this filters zombie entries
        // that may still linger in the datastore's share_index.
        Set<String> validShareIds = fetchValidShareIds();
        if(DBG) Log.i("Valid individual share rights: " + validShareIds.size() + " share(s)");

        // Single visited-set shared across all datastores and group shares so that
        // a share referenced from multiple places is only fetched and processed once.
        Set<String> visitedShares = new HashSet<>();

        for (Map<String, Object> ds : datastores) {
            String dsId   = (String) ds.get("id");
            String dsType = (String) ds.get("type");
            if(DBG) Log.i("Datastore id=" + dsId + " type=" + dsType);

            if (!DATASTORE_TYPE_PASSWORD.equals(dsType)) {
                if(DBG) Log.i("  → skipped (not a password datastore)");
                continue;
            }

            // Step 2: fetch datastore content
            HttpResponse<String> dsResp = rawGet(ENDPOINT_DATASTORE + dsId + "/");
            if (dsResp.statusCode() != 200) {
                Log.e("  Could not fetch datastore " + dsId
                    + " (HTTP " + dsResp.statusCode() + ") – skipped");
                continue;
            }

            Map<?, ?> dsEnvelope = mapper.readValue(decryptTransport(dsResp.body()), Map.class);

            // Layer 2: per-datastore key
            String dsKey = decryptWithKey(
                (String) dsEnvelope.get(FIELD_DS_SECRET_KEY),
                (String) dsEnvelope.get(FIELD_DS_SECRET_KEY_NONCE),
                userSecretKey
            );

            // Layer 3: datastore content
            String dsContent = decryptWithKey(
                (String) dsEnvelope.get(FIELD_DATA),
                (String) dsEnvelope.get(FIELD_DATA_NONCE),
                dsKey
            );

            Map<String, Object> tree = mapper.readValue(dsContent, Map.class);
            List<Map<String, Object>> refs = new ArrayList<>();
            collectSecretRefs(tree, refs, new ArrayList<>());
            refs.forEach(r -> {
                r.put("_source_type", "datastore");
                r.put("_share_name",  "");
                r.put("_share_id",    "");
                r.put("_group_name",  "");
                r.put("_group_id",    "");
            });

            // Also collect secrets from individually accepted shares (share_index in tree).
            // Share keys are stored plaintext inside the encrypted tree JSON.
            // validShareIds guards against zombie entries in the share_index.
            collectShareRefs(tree, refs, visitedShares, dsId, validShareIds);

            if(DBG) Log.i("  → " + refs.size() + " secret ref(s) found (direct + individual shares)");
            allRefs.addAll(refs);
        }

        // Collect secrets from group shares. Group membership replaces individual acceptance,
        // so these shares are readable without the service account ever accepting them manually.
        collectGroupShareRefs(allRefs, visitedShares, validShareIds);

        return allRefs;
    }

    /**
     * Recursively traverses the datastore tree (folders + items) and collects
     * all entries that carry a {@code secret_id} and {@code secret_key}.
     *
     * <p>Each collected item receives an internal {@code _folder_path} entry
     * (a {@code List<String>}) reflecting its location in the tree.
     * Items marked {@code deleted: true} are skipped (Psono soft-delete).</p>
     *
     * @param node       current tree node (datastore root, folder, or share tree)
     * @param result     accumulator for found secret references
     * @param folderPath immutable path of folder names from the tree root to {@code node}
     */
    @SuppressWarnings("unchecked")
    private void collectSecretRefs(
            Map<?, ?> node,
            List<Map<String, Object>> result,
            List<String> folderPath) {

        List<?> items = (List<?>) node.get("items");
        if (items != null) {
            for (Object itemObj : items) {
                Map<String, Object> item = (Map<String, Object>) itemObj;
                if (Boolean.TRUE.equals(item.get("deleted"))) continue;
                if (item.containsKey(FIELD_SECRET_ID) && item.containsKey(FIELD_SECRET_KEY)) {
                    item.put("_folder_path", new ArrayList<>(folderPath));
                    result.add(item);
                }
            }
        }
        List<?> folders = (List<?>) node.get("folders");
        if (folders != null) {
            for (Object folderObj : folders) {
                Map<?, ?> folder = (Map<?, ?>) folderObj;
                if (Boolean.TRUE.equals(folder.get("deleted"))) continue;
                Object rawName = folder.get("name");
                String folderName = rawName instanceof String ? (String) rawName : "";
                List<String> subPath = new ArrayList<>(folderPath);
                if (!folderName.isBlank()) subPath.add(folderName);
                collectSecretRefs(folder, result, subPath);
            }
        }
    }

    /**
     * Walks the {@code share_index} of a decrypted tree (datastore or share) and
     * collects all secret references found within those shares.
     *
     * <p>Shares are fetched from {@code GET /share/{id}/} and decrypted with the
     * {@code secret_key} stored in the {@code share_index} entry. Two share structures
     * are supported: single-secret shares (credential at the root level) and folder
     * shares (tree with {@code items[]} / {@code folders[]}). The method recurses into
     * nested shares. A visited-set prevents infinite loops from circular references.</p>
     *
     * @param tree          decrypted tree JSON (datastore or share content)
     * @param result        accumulator – secret refs are appended here
     * @param visitedShares set of share IDs already processed (guard against cycles)
     * @param parentId      human-readable source label for debug logging
     * @param validShareIds set of share IDs the user actually has read rights to;
     *                      share_index entries not in this set are skipped as zombies
     */
    @SuppressWarnings("unchecked")
    private void collectShareRefs(
            Map<?, ?> tree,
            List<Map<String, Object>> result,
            Set<String> visitedShares,
            String parentId,
            Set<String> validShareIds) throws Exception {

        Map<?, ?> shareIndex = (Map<?, ?>) tree.get(FIELD_SHARE_INDEX);
        if (shareIndex == null || shareIndex.isEmpty()) return;

        for (Map.Entry<?, ?> entry : shareIndex.entrySet()) {
            String   shareId  = (String) entry.getKey();
            Map<?,?> shareInfo = (Map<?, ?>) entry.getValue();
            String   shareKey = (String) shareInfo.get(FIELD_SHARE_SECRET_KEY);

            // Skip stale share_index entries (zombie shares whose rights were revoked)
            if (!validShareIds.contains(shareId)) {
                if(DBG) Log.i("    → share " + shareId + " not in valid share rights – skipping (zombie)");
                continue;
            }
            if (!visitedShares.add(shareId)) {
                if(DBG) Log.i("    → share " + shareId + " already visited – skipping");
                continue;
            }
            if (shareKey == null || shareKey.isBlank()) {
                Log.e("    → share " + shareId + " has no secret_key – skipping");
                continue;
            }

            if(DBG) Log.i("    → fetching share " + shareId);
            HttpResponse<String> resp = rawGet(ENDPOINT_SHARE + shareId + "/");
            if (resp.statusCode() != 200) {
                Log.e("    → GET /share/" + shareId + "/ failed (HTTP "
                    + resp.statusCode() + ") – skipped");
                continue;
            }

            Map<?, ?> shareEnvelope = mapper.readValue(decryptTransport(resp.body()), Map.class);
            String shareContent = decryptWithKey(
                (String) shareEnvelope.get(FIELD_DATA),
                (String) shareEnvelope.get(FIELD_DATA_NONCE),
                shareKey
            );

            Map<String, Object> shareTree = mapper.readValue(shareContent, Map.class);
            String shareName = (String) shareTree.getOrDefault("name", "");
            if(DBG) Log.i("    → share name: \"" + shareName + "\"");

            int before = result.size();

            // A share can carry its content in two ways:
            //  - Single-secret share: {secret_id, secret_key, type, name, …} at the root level
            //  - Folder share: tree with items[] / folders[] (same structure as a datastore)
            // Both cases can coexist: a folder share may also have a root-level secret.
            // In both cases, honour the soft-delete flag.
            if (shareTree.containsKey(FIELD_SECRET_ID) && shareTree.containsKey(FIELD_SECRET_KEY)
                    && !Boolean.TRUE.equals(shareTree.get("deleted"))) {
                shareTree.put("_source_type", "share");
                shareTree.put("_share_name",  shareName);
                shareTree.put("_share_id",    shareId);
                shareTree.put("_group_name",  "");
                shareTree.put("_group_id",    "");
                shareTree.put("_folder_path", new ArrayList<>());
                result.add(shareTree);
            }

            int beforeItems = result.size();
            collectSecretRefs(shareTree, result, new ArrayList<>());
            result.subList(beforeItems, result.size()).forEach(r -> {
                r.putIfAbsent("_source_type", "share");
                r.putIfAbsent("_share_name",  shareName);
                r.putIfAbsent("_share_id",    shareId);
                r.putIfAbsent("_group_name",  "");
                r.putIfAbsent("_group_id",    "");
            });

            if(DBG) Log.i("    → " + (result.size() - before) + " secret ref(s) in share " + shareId);

            // Recurse: shares can themselves contain nested shares
            collectShareRefs(shareTree, result, visitedShares, "share:" + shareId, validShareIds);
        }
    }

    /** Builds the {@code meta} map from internal tracking fields and the secret type. */
    @SuppressWarnings("unchecked")
    private Map<String, Object> buildMeta(Map<String, Object> ref, String type) {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("source",      ref.getOrDefault("_source_type", "unknown"));
        meta.put("share_name",  ref.getOrDefault("_share_name",  ""));
        meta.put("share_id",    ref.getOrDefault("_share_id",    ""));
        meta.put("group_name",  ref.getOrDefault("_group_name",  ""));
        meta.put("group_id",    ref.getOrDefault("_group_id",    ""));
        meta.put("folder_path", ref.getOrDefault("_folder_path", new ArrayList<>()));
        meta.put("type",        type);
        return meta;
    }

    /*
     * embedMeta() — nicht mehr benötigt, Meta wird nur noch als KEY_META Map geliefert.
     *
    @SuppressWarnings("unchecked")
    private String embedMeta(String contentJson, Map<String, Object> meta) {
        try {
            Map<String, Object> contentMap = mapper.readValue(contentJson, LinkedHashMap.class);
            contentMap.put("meta", meta);
            return mapper.writeValueAsString(contentMap);
        } catch (Exception e) {
            return contentJson;
        }
    }
    */

    /**
     * Fetches all accepted group memberships and collects secrets from every share
     * granted to those groups.
     *
     * <p>Group shares bypass the individual share-acceptance step: belonging to a group
     * is the implicit acceptance. The decryption chain is:</p>
     * <ol>
     *   <li>Decrypt the group's symmetric key:
     *       {@code SecretBox.open(group.secret_key, group.secret_key_nonce, userSecretKey)}</li>
     *   <li>For each group share right ({@code GET /group/{id}/}):
     *       {@code SecretBox.open(right.key, right.key_nonce, groupSecretKey)}</li>
     *   <li>Fetch and decrypt the share content, then collect its secrets.</li>
     * </ol>
     *
     * <p>The {@code visitedShares} set is shared with the individual-share pass so that a
     * share appearing in both paths is only processed once.</p>
     *
     * @param result        accumulator – secret refs are appended here
     * @param visitedShares shared visited-set (prevents processing a share more than once)
     * @param validShareIds set of individually accepted share IDs, used for zombie filtering
     *                      when recursing into nested {@code share_index} entries
     */
    @SuppressWarnings("unchecked")
    private void collectGroupShareRefs(
            List<Map<String, Object>> result,
            Set<String> visitedShares,
            Set<String> validShareIds) throws Exception {

        HttpResponse<String> groupListResp = rawGet(ENDPOINT_GROUP);
        if (groupListResp.statusCode() != 200) {
            Log.e("GET /group/ failed (HTTP " + groupListResp.statusCode() + ") – skipping group shares");
            return;
        }

        Map<?, ?> groupWrapper = mapper.readValue(decryptTransport(groupListResp.body()), Map.class);
        List<?> groups = (List<?>) groupWrapper.get("groups");
        if (groups == null || groups.isEmpty()) {
            if(DBG) Log.i("No group memberships found");
            return;
        }

        if(DBG) Log.i("Group memberships: " + groups.size() + " group(s)");

        for (Object groupObj : groups) {
            Map<?, ?> group    = (Map<?, ?>) groupObj;
            String    groupId  = String.valueOf(group.get("group_id"));
            Object    rawGName = group.get("name");
            String    groupName = rawGName instanceof String ? (String) rawGName : "";

            if (!Boolean.TRUE.equals(group.get("accepted"))) {
                if(DBG) Log.i("  Group \"" + groupName + "\" (" + groupId + ") – not accepted, skipping");
                continue;
            }

            String encSecretKey      = (String) group.get("secret_key");
            String encSecretKeyNonce = (String) group.get("secret_key_nonce");
            if (encSecretKey == null || encSecretKeyNonce == null) {
                Log.e("  Group \"" + groupName + "\" (" + groupId + ") – missing secret_key, skipping");
                continue;
            }

            // Decrypt the group's symmetric key (stored encrypted with userSecretKey)
            String groupSecretKey;
            try {
                groupSecretKey = decryptWithKey(encSecretKey, encSecretKeyNonce, userSecretKey);
            } catch (Exception e) {
                Log.e("  Group \"" + groupName + "\" (" + groupId + ") – could not decrypt group secret_key: " + e.getMessage());
                continue;
            }

            if(DBG) Log.i("  Group \"" + groupName + "\" (" + groupId + ") – fetching share rights");
            HttpResponse<String> groupDetailResp = rawGet(ENDPOINT_GROUP + groupId + "/");
            if (groupDetailResp.statusCode() != 200) {
                Log.e("  GET /group/" + groupId + "/ failed (HTTP " + groupDetailResp.statusCode() + ") – skipping");
                continue;
            }

            Map<?, ?> groupDetail    = mapper.readValue(decryptTransport(groupDetailResp.body()), Map.class);
            List<?>   groupShareRights = (List<?>) groupDetail.get("group_share_rights");
            if (groupShareRights == null || groupShareRights.isEmpty()) {
                if(DBG) Log.i("  → no share rights in this group");
                continue;
            }

            if(DBG) Log.i("  → " + groupShareRights.size() + " group share right(s)");

            for (Object rightObj : groupShareRights) {
                Map<?, ?> right   = (Map<?, ?>) rightObj;
                String    shareId = String.valueOf(right.get("share_id"));

                if (!Boolean.TRUE.equals(right.get("read"))) {
                    if(DBG) Log.i("    → share " + shareId + " – no read right, skipping");
                    continue;
                }
                if (!visitedShares.add(shareId)) {
                    Log.i("    → share " + shareId + " already visited – skipping");
                    continue;
                }

                String encShareKey      = (String) right.get("key");
                String encShareKeyNonce = (String) right.get("key_nonce");
                if (encShareKey == null || encShareKeyNonce == null) {
                    Log.e("    → share " + shareId + " – missing key fields, skipping");
                    continue;
                }

                // Decrypt the share key with the group's symmetric key
                String shareKey;
                try {
                    shareKey = decryptWithKey(encShareKey, encShareKeyNonce, groupSecretKey);
                } catch (Exception e) {
                    Log.e("    → share " + shareId + " – could not decrypt share key: " + e.getMessage());
                    continue;
                }

                if(DBG) Log.i("    → fetching share " + shareId + " (group: \"" + groupName + "\")");
                HttpResponse<String> shareResp = rawGet(ENDPOINT_SHARE + shareId + "/");
                if (shareResp.statusCode() != 200) {
                    Log.e("    → GET /share/" + shareId + "/ failed (HTTP " + shareResp.statusCode() + ") – skipped");
                    continue;
                }

                Map<?, ?> shareEnvelope = mapper.readValue(decryptTransport(shareResp.body()), Map.class);
                String shareContent;
                try {
                    shareContent = decryptWithKey(
                        (String) shareEnvelope.get(FIELD_DATA),
                        (String) shareEnvelope.get(FIELD_DATA_NONCE),
                        shareKey
                    );
                } catch (Exception e) {
                    Log.e("    → share " + shareId + " – could not decrypt share content: " + e.getMessage());
                    continue;
                }

                Map<String, Object> shareTree = mapper.readValue(shareContent, Map.class);
                Object rawSName = shareTree.get("name");
                String shareName = rawSName instanceof String ? (String) rawSName : "";
                if(DBG)  Log.i("    → share name: \"" + shareName + "\"");

                int before = result.size();

                // Single-secret share: credential at root level
                if (shareTree.containsKey(FIELD_SECRET_ID) && shareTree.containsKey(FIELD_SECRET_KEY)
                        && !Boolean.TRUE.equals(shareTree.get("deleted"))) {
                    shareTree.put("_source_type", "group_share");
                    shareTree.put("_share_name",  shareName);
                    shareTree.put("_share_id",    shareId);
                    shareTree.put("_group_name",  groupName);
                    shareTree.put("_group_id",    groupId);
                    shareTree.put("_folder_path", new ArrayList<>());
                    result.add(shareTree);
                }

                // Folder share: collect items within the tree
                int beforeItems = result.size();
                collectSecretRefs(shareTree, result, new ArrayList<>());
                result.subList(beforeItems, result.size()).forEach(r -> {
                    r.putIfAbsent("_source_type", "group_share");
                    r.putIfAbsent("_share_name",  shareName);
                    r.putIfAbsent("_share_id",    shareId);
                    r.putIfAbsent("_group_name",  groupName);
                    r.putIfAbsent("_group_id",    groupId);
                });

                if(DBG) Log.i("    → " + (result.size() - before) + " secret ref(s) from share " + shareId);

                // Recurse into nested shares (shares within shares)
                collectShareRefs(shareTree, result, visitedShares, "group-share:" + shareId, validShareIds);
            }
        }
    }

    /**
     * Returns the set of share IDs the authenticated user has active read rights to.
     *
     * <p>Calls {@code GET /share/right/} which the server filters to accepted,
     * non-revoked rights only. Any share_index entry whose ID is absent from this
     * set is a zombie (rights were revoked after acceptance) and should be ignored.</p>
     */
    @SuppressWarnings("unchecked")
    private Set<String> fetchValidShareIds() throws Exception {
        HttpResponse<String> resp = rawGet(ENDPOINT_SHARE_RIGHT);
        if (resp.statusCode() != 200)
            throw new RuntimeException(
                "GET /share/right/ failed (HTTP " + resp.statusCode() + "): " + resp.body());

        String    plain   = decryptTransport(resp.body());
        Map<?, ?> wrapper = mapper.readValue(plain, Map.class);

        List<?> rights = (List<?>) wrapper.get("share_rights");
        Set<String> ids = new HashSet<>();
        if (rights != null) {
            for (Object r : rights) {
                Map<?, ?> right = (Map<?, ?>) r;
                if (Boolean.TRUE.equals(right.get("read"))) {
                    ids.add((String) right.get("share_id"));
                }
            }
        }
        return ids;
    }

    /**
     * Fetches a single secret from the server and decrypts it with the given secret key.
     */
    @SuppressWarnings("unchecked")
    private PsonoResult<String> fetchAndDecryptSecret(String secretId, String secretKey) {
        try {
            HttpResponse<String> resp = rawGet(ENDPOINT_SECRET + secretId + "/");
            if (resp.statusCode() != 200)
                return PsonoResult.fail("HTTP " + resp.statusCode() + ": " + resp.body());

            Map<?, ?> envelope = mapper.readValue(decryptTransport(resp.body()), Map.class);
            String content = decryptWithKey(
                (String) envelope.get(FIELD_DATA),
                (String) envelope.get(FIELD_DATA_NONCE),
                secretKey
            );
            return PsonoResult.ok(content);

        } catch (Exception e) {
            return PsonoResult.fail(e.getMessage());
        }
    }

    // ── Crypto helpers ────────────────────────────────────────────────────────

    /** Decrypts the transport envelope {"text":hex,"nonce":hex} with the session_secret_key. */
    @SuppressWarnings("unchecked")
    private String decryptTransport(String responseJson) throws Exception {
        Map<String, String> wrapped = mapper.readValue(responseJson, Map.class);
        return decryptWithKey(wrapped.get(FIELD_TEXT), wrapped.get(FIELD_NONCE), sessionSecretKey);
    }

    /** Generic NaCl SecretBox decryption: hex ciphertext + hex nonce → UTF-8 plaintext. */
    private String decryptWithKey(String hexCiphertext, String hexNonce, String hexKey) throws Exception {
        byte[] ct    = Key.fromHexString(hexCiphertext).getAsBytes();
        byte[] nonce = Key.fromHexString(hexNonce).getAsBytes();
        byte[] sk    = Key.fromHexString(hexKey).getAsBytes();
        byte[] plain = new byte[ct.length - SecretBox.MACBYTES];
        int r = lazySodium.getSodium().crypto_secretbox_open_easy(plain, ct, ct.length, nonce, sk);
        if (r != 0) throw new RuntimeException("Decryption failed: MAC verification error");
        return new String(plain, StandardCharsets.UTF_8);
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────

    private HttpResponse<String> rawGet(String endpoint) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(config.getServerUrl() + endpoint))
            .header(HEADER_CONTENT_TYPE,  MIME_JSON)
            .header(HEADER_AUTHORIZATION, AUTH_TOKEN_PREFIX + sessionToken)
            .GET()
            .build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> rawPost(String endpoint, String jsonBody) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(config.getServerUrl() + endpoint))
            .header(HEADER_CONTENT_TYPE, MIME_JSON)
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }

    /** Signs a UTF-8 message with the Ed25519 private key (supports 32-byte seed or 64-byte key). */
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

    /** Setzt die Session zurück. Der nächste Aufruf von {@link #login()} startet eine neue Session. */
    public void logout() {
        sessionToken     = null;
        sessionSecretKey = null;
        userSecretKey    = null;
    }
}
