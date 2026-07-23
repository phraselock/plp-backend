package plp.processor;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ipoxo.lib.AESPlnk;
import com.ipoxo.lib.PeerCom;
import com.ipoxo.lib.PhraseX;
import com.ipoxo.plcore.ctap2ecc.CTAP2EccJava;
import com.ipoxo.plcore.lib.Configuration;
import com.ipoxo.plcore.lib.DDXMLElement;
import com.ipoxo.plcore.lib.FCOEM;
import com.ipoxo.plcore.lib.Log;
import org.json.JSONObject;
import org.linguafranca.pwdb.Database;
import org.linguafranca.pwdb.Entry;
import org.linguafranca.pwdb.Group;
import org.linguafranca.pwdb.kdbx.KdbxCreds;
import org.linguafranca.pwdb.kdbx.jackson.JacksonDatabase;
import org.linguafranca.pwdb.kdbx.jackson.JacksonEntry;
import plp.handler.MqttService;
import plp.lib.Redis;
import plp.provider.RestResponse;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * BES module for KeePass KDBX4 integration.
 *
 * Reads credentials from a .kdbx file (version 4).
 * Configuration via keepass.properties (next to JAR or in resources).
 *
 * Result format per entry:
 *   secret_id  — UUID of the KeePass entry
 *   name       — title of the entry
 *   content    — map with username, password, url, notes
 *   meta       — source, folder_path, type
 */
public class BESKeePass extends BESCore
{
  private static final String PROPERTIES = "keepass.properties";

  // ── Result keys ──────────────────────────────────────────────────────────

  public static final String KEY_SECRET_ID = "secret_id";
  public static final String KEY_NAME      = "name";
  public static final String KEY_CONTENT   = "content";
  public static final String KEY_META      = "meta";

  // ── Singleton ─────────────────────────────────────────────────────────────

  private static BESKeePass instance;

  public static synchronized BESKeePass getInstance()
  {
    if (instance == null) instance = new BESKeePass();
    return instance;
  }

  // ── In-memory cache ───────────────────────────────────────────────────────

  private Database<?, ?, ?, ?>      cachedDb;
  private KdbxCreds                 cachedCreds;
  private List<Map<String, Object>> cachedList;
  private String                    cachedFilePath;
  private String                    cachedPassword;


  /** Returns the service UUID from keepass.properties. */
  public String getServiceUuid()
  {
    return config != null ? config.getProperty("service.uuid", "") : "";
  }

  private BESKeePass() {}

  // ── Initialization ────────────────────────────────────────────────────────

  /**
   * Loads the database into RAM, starts the FileWatcher, and subscribes the MQTT topic.
   * Must be called after MqttService.connect().
   */
  public void initialize(MqttService mqtt) throws Exception
  {
    config         = loadConfig();
    cachedFilePath = required(config, "keepass.file");
    cachedPassword = required(config, "keepass.password");

    // Load database once
    loadDatabase();

    // Start FileWatcher — reacts to external changes
    startFileWatcher(Path.of(cachedFilePath));

    // ── Register topic once the connection is established ─────────────────
    String serviceUuid = config.getProperty("service.uuid", "");
    if (!serviceUuid.isBlank())
    {
      String topicBase = PeerCom.pfxBES + serviceUuid;
      mqtt.registerOnConnectedListener(m ->
      {
        try
        {
          m.subscribe(topicBase + "/#");
          m.registerTopicHandler(topicBase, this::onMqttMessage);
          Log.i("[BESKeePass] Topic registriert: " + topicBase + "/#");
        }
        catch (Exception e)
        {
          Log.e("[BESKeePass] Topic-Registrierung failed: " + e.getMessage());
        }
      });
    }
  }

  /** Loads the .kdbx file and builds the cache. */
  private synchronized void loadDatabase()
  {
    try {
      Log.i("[KeePass] Lade Datenbank: " + cachedFilePath);
      try (InputStream is = new FileInputStream(cachedFilePath)) {
        cachedCreds = new KdbxCreds(cachedPassword.getBytes());
        cachedDb = JacksonDatabase.load(cachedCreds, is);
      }
      cachedList = new ArrayList<>();
      collectEntries(cachedDb.getRootGroup(), cachedList);
      Log.i("[KeePass] Cache aktualisiert: " + cachedList.size() + " Einträge");
    } catch (Exception e) {
      Log.e("[BESKeePass] loadDatabase failed: " + e.getMessage());
    }
  }

  /** Watches the .kdbx file and reloads the cache on external changes. */
  private void startFileWatcher(Path dbPath)
  {
    // Resolve symlinks — WatchService requires the real path
    Path realPath;
    try { realPath = dbPath.toRealPath(); }
    catch (Exception e) { realPath = dbPath; }

    Path dir      = realPath.getParent();
    String dbName = realPath.getFileName().toString();

    Log.i("[KeePass] FileWatcher überwacht: " + realPath);

    Thread.ofVirtual().name("keepass-filewatcher").start(() ->
    {
      try (WatchService watcher = FileSystems.getDefault().newWatchService())
      {
        dir.register(watcher, StandardWatchEventKinds.ENTRY_MODIFY);
        Log.i("[KeePass] FileWatcher aktiv für: " + dir);

        while (!Thread.interrupted())
        {
          WatchKey key = watcher.take(); // blocks until event
          for (WatchEvent<?> event : key.pollEvents())
          {
            Path changed = (Path) event.context();
            if (dbName.equals(changed.toString()))
            {
              Log.i("[KeePass] Dateiänderung erkannt — Cache wird neu geladen");
              try { loadDatabase(); }
              catch (Exception e) { Log.e("[KeePass] Reload fehlgeschlagen: " + e.getMessage()); }
            }
          }
          key.reset();
        }
      }
      catch (InterruptedException e) { Thread.currentThread().interrupt(); }
      catch (Exception e) { Log.e("[KeePass] FileWatcher error: " + e.getMessage()); }
    });
  }

  private void requestPeerData(String peerAdrGUID)
  {
    try
    {
      PeerCom.removeSession(peerAdrGUID);
      PeerCom.sessionForPeer(peerAdrGUID).phraseLidx = 0;

      byte[] mqttData = PeerCom.buildPeerDataRequest(peerAdrGUID, getServiceUuid(),PeerCom.MQTT_PEER_DATA_REQUEST_KDBX);

      String topic = PeerCom.pfxPEER + peerAdrGUID;

      send(topic,mqttData);

    } catch (Exception e)
    {
      if (Configuration.DBGEN) Log.d(Configuration.DBGLEVEL,"Exception in sendToPeer: " + e.getMessage());
    }
  }

  public List<String> buildPhraseXExportV030FromKdbx(AESPlnk aes, String besUUID, String  jsonString)
  {
    List<String> credList = new ArrayList<>();

    try {
      ObjectMapper mapper = new ObjectMapper();
      // Parse list
      JsonNode secrets = mapper.readTree(jsonString);
      int cx=0;
      for (JsonNode secret : secrets)
      {
        StringBuilder phraseDump = new StringBuilder();
        phraseDump.append("<PHRASE>");

        String secretId     = secret.path("secret_id").asText();
        String name         = secret.path("name").asText();
        String type         = secret.path("meta").path("type").asText();
        String cat_name     = secret.path("meta").path("group_name").asText();
        String cat_uuid     = secret.path("meta").path("group_id").asText();


        JsonNode content    = secret.path("content");
        if(content!=null && !content.isEmpty())
        {
          String label = "";
          String p1 = "";
          String p2 = "";
          String p3 = "";
          String link = "";
          String txt = "";

          String otp = null;
          JsonNode custom_fields = content.path("custom_fields");
          if(custom_fields!=null && !custom_fields.isEmpty())
          {
            for (JsonNode field : custom_fields)
            {
              if ("otp".equals(field.path("key").asText()))
              {
                String otpFull = field.path("value").asText();
                if(otpFull!=null) {
                  URI uri = new URI(otpFull);
                  String query = uri.getRawQuery(); // "secret=ABCDEFGH&period=30&digits=6&issuer=..."

                  otp = Arrays.stream(query.split("&"))
                    .filter(p -> p.startsWith("secret="))
                    .map(p -> p.split("=", 2)[1])
                    .findFirst()
                    .orElse(null);
                }
              }
            }
          }

          if (type.equals("keepass")) {
            label = name;
            p1 = content.path("username").asText();
            p2 = content.path("password").asText();
            link = content.path("url").asText();
            txt = content.path("notes").asText();
          }

          DDXMLElement p4enc = PhraseX.makeNewP4(aes, p1, p2, p3, link, txt);

          DDXMLElement p4dec = PhraseX.decryptP4ForExport(aes, p4enc);

          if (otp != null) {
            PhraseX.setOTPSecretCode(p4dec, otp);
            PhraseX.setOTPActive(p4dec, true);
            PhraseX.setOTPTimerType(p4dec);
          }

          PhraseX.setBESUUID(p4dec, besUUID);
          PhraseX.setSyncActive(p4dec,true);

          String p4XML = p4dec.XMLString();

          phraseDump.append("<label>" + AESPlnk.b64encode2String(label) + "</label>");
          phraseDump.append(p4XML);
          phraseDump.append("<p5>" + secretId + "</p5>");

          if (cat_name != null && cat_uuid != null) {
            phraseDump.append("<cats>");
            phraseDump.append(String.format("<cat uuid='%s' type='%s' >%s</cat>", cat_uuid, "0", AESPlnk.b64encode2String(cat_name)));
            phraseDump.append("</cats>");
          }

          phraseDump.append("</PHRASE>");

          String exportPlain = null;
          exportPlain = String.format("<root><format>030</format><phraselist>%s</phraselist><credlist>%s</credlist></root>", phraseDump.toString(), "");

          exportPlain = exportPlain.replace("\t", "");
          exportPlain = exportPlain.replace("\r", "");
          exportPlain = exportPlain.replace("\n", "");

          credList.add(exportPlain);
        }
      }

    } catch (Exception e) {
      Log.e("Exception in buildPhraseXExportV030FromKdbx: " + e.getMessage());
    }
    return credList;
  }

  private void sendToPeerPublicData(String peerAdrGUID)
  {
    String sd = MqttService.getInstance().getConfig().getProperty("bes.id.dpriv");
    String sx = MqttService.getInstance().getConfig().getProperty("bes.id.xpubl");
    String sy = MqttService.getInstance().getConfig().getProperty("bes.id.ypubl");

    byte[] d = FCOEM.hexStringToByteArray(sd);
    byte[] x = FCOEM.hexStringToByteArray(sx);
    byte[] y = FCOEM.hexStringToByteArray(sy);

    PeerCom.removeSession(peerAdrGUID);
    PeerCom.sessionForPeer(peerAdrGUID).sessionKey = null;

    JSONObject jsonContent = new JSONObject();
    jsonContent.put("publ_x", sx);
    jsonContent.put("publ_y", sy);
    String contentB64 = AESPlnk.b64encode2String(jsonContent.toString());

    byte[] mqttData = PeerCom.buildPeerDataResponse(peerAdrGUID, PeerCom.MQTT_PEER_DATA_RESPONSE_KDBX,jsonContent);
    if(mqttData!=null) {
      String topic = PeerCom.pfxPEER + peerAdrGUID;
      send(topic, mqttData);
    }
  }

  @Override
  protected void receiveFromPeer(String[] topics, String jsonstr)
  {
    try
    {
      JSONObject jsonObj = new JSONObject(jsonstr);

      String peer = jsonObj.getString("peer");
      String request = jsonObj.getString("request");

      if(request.equalsIgnoreCase(PeerCom.MQTT_FULL_SYNC_REQUEST_KDBX))
      {
        Set<String> peerConfig = Redis.readPeerConfig(peer);
        if(peerConfig!=null && peerConfig.size()>0)
        {
          JSONObject peerDict = new JSONObject(peerConfig.stream().findFirst().orElse(null));
          String payload = PeerCom.getNSStringPayLoad(peerDict, jsonObj);
          ObjectMapper mapperTags = new ObjectMapper();
          List<String> tags = mapperTags.readValue(payload, new TypeReference<List<String>>() {});
          if(tags!=null && tags.size()>0)
          {
            //var result = fetchAllCredentials();
            var result = fetchCredentialsByTags(tags, MatchMode.OR);
            ObjectMapper mapper = new ObjectMapper();
            String response = mapper.writeValueAsString(result);
            if (response != null)
            {
              Properties cfg = config;
              String sUUID = cfg.getProperty("service.uuid", null);
              String sd = MqttService.getInstance().getConfig().getProperty("bes.id.dpriv");

              byte[] iv = CTAP2EccJava.generateRandom(16);
              AESPlnk aes = new AESPlnk(FCOEM.hexStringToByteArray(sd), iv);

              Log.i("MQTT_FULL_SYNC_REQUEST_KDBX payload: " + response);

              PeerCom.sessionForPeer(peer).credList = buildPhraseXExportV030FromKdbx(aes, sUUID, response);
              if (PeerCom.sessionForPeer(peer).credList != null && !PeerCom.sessionForPeer(peer).credList.isEmpty())
              {
                String xmlCred = PeerCom.sessionForPeer(peer).credList.getFirst();
                if (xmlCred != null)
                {
                  //Log.i("MQTT_ENC_PAYLOAD_KDBX payload: " + prettyXml(xmlCred));
                  Log.i("MQTT_ENC_PAYLOAD_KDBX payload: " + xmlCred);
                  byte[] mqttData = PeerCom.buildPayloadTransfer(peer, PeerCom.MQTT_ENC_PAYLOAD_KDBX, xmlCred, getServiceUuid());
                  if (mqttData != null) {
                    String topic = PeerCom.pfxPEER + peer;
                    send(topic, mqttData);
                  }
                  PeerCom.sessionForPeer(peer).credList.removeFirst();
                }
              }
            }
          }
        }
      }
      else if(request.equalsIgnoreCase(PeerCom.MQTT_ACK_PAYLOAD_KDBX))
      {
        if(PeerCom.sessionForPeer(peer).credList!=null && !PeerCom.sessionForPeer(peer).credList.isEmpty())
        {
          String xmlCred = PeerCom.sessionForPeer(peer).credList.getFirst();
          if(xmlCred!=null)
          {
            //Log.i("MQTT_ENC_PAYLOAD_NEXT_KDBX payload: " + prettyXml(xmlCred));
            Log.i("MQTT_ENC_PAYLOAD_NEXT_KDBX payload: " + xmlCred);
            byte[] mqttData = PeerCom.buildPayloadTransfer(peer,PeerCom.MQTT_ENC_PAYLOAD_NEXT_KDBX,xmlCred, getServiceUuid());
            if(mqttData!=null) {
              String topic = PeerCom.pfxPEER + peer;
              send(topic, mqttData);
            }
            PeerCom.sessionForPeer(peer).credList.removeFirst();
          }
        }
        else
        {
          PeerCom.sessionForPeer(peer).credList = null;
        }
      }
      else if(request.equalsIgnoreCase(PeerCom.MQTT_PEER_DATA_RESPONSE_KDBX))
      {
        try {
          String contentB64 = jsonObj.getString("content");
          String content = AESPlnk.b64decode2String(contentB64);
          JSONObject jsonPeerData = new JSONObject(content);
          String x = jsonPeerData.getString("publ_x");
          String y = jsonPeerData.getString("publ_y");
          if(x!=null && y!=null)
          {
            Redis.writePeerConfig(peer,content);
          }
        } catch (Exception ignored) {}
      }
      else if(request.equalsIgnoreCase(PeerCom.MQTT_SKEY_NEGO_REQUEST_KDBX))
      {
        Set<String> peerConfig = Redis.readPeerConfig(peer);
        if(peerConfig!=null && !peerConfig.isEmpty())
        {
          JSONObject peerDict = new JSONObject(peerConfig.stream().findFirst().orElse(null));
          byte[] mqttData = PeerCom.buildSKeyNegotiationResponse(peerDict, jsonObj, getServiceUuid(),PeerCom.MQTT_SKEY_NEGO_RESPONSE_KDBX);
          if(mqttData!=null) {
            String topic = PeerCom.pfxPEER + peer;
            send(topic, mqttData);
          }
        }
        else
        {
          requestPeerData(peer);
        }
      }
    } catch (Exception e) {
      Log.e("Exception in receiveFromPeer: " + e.getMessage());
    }
  }


  @SuppressWarnings("unchecked")
  private void handleRequest(String[] parts, byte[] payload)
  {
    try
    {
      ObjectMapper mapper = new ObjectMapper();
      Map<String, Object> request = mapper.readValue(payload, Map.class);

      List<String> tags    = (List<String>) request.getOrDefault("tags", new ArrayList<>());
      String       modeStr = (String) request.getOrDefault("mode", "OR");
      String       replyTo = (String) request.get("reply_topic");

      if (replyTo == null || replyTo.isBlank())
      {
        Log.e("[KeePass] Kein reply_topic im Request — ignoriert");
        return;
      }

      MatchMode mode = modeStr.equalsIgnoreCase("AND") ? MatchMode.AND : MatchMode.OR;

      List<Map<String, Object>> credentials = fetchCredentialsByTags(tags, mode);

      byte[] response = mapper.writeValueAsBytes(credentials);
      MqttService.getInstance().send(replyTo, response);

      Log.i("[KeePass] " + credentials.size() + " Credentials gesendet an: " + replyTo);
    }
    catch (Exception e)
    {
      Log.e("[KeePass] handleRequest error: " + e.getMessage());
    }
  }

  /** Forces a cache reload — e.g. after manual intervention. */
  private void handleReload(String[] parts, byte[] payload)
  {
    Log.i("[KeePass] Reload angefordert");
    try { loadDatabase(); }
    catch (Exception e) { Log.e("[KeePass] Reload fehlgeschlagen: " + e.getMessage()); }
  }

  // ── Public API ────────────────────────────────────────────────────────────

  /** Controls how multiple tags are combined. */
  public enum MatchMode
  {
    /** Credential must have ALL specified tags. */
    AND,
    /** Credential must have AT LEAST ONE of the specified tags. */
    OR
  }

  /**
   * Reads all credentials from the configured .kdbx file.
   * Recursively traverses all groups and collects all entries.
   *
   * @return list of credential maps, each with KEY_SECRET_ID, KEY_NAME, KEY_CONTENT, KEY_META
   */
  public synchronized List<Map<String, Object>> fetchAllCredentials() throws Exception
  {
    // Not yet initialized — load directly (fallback for tests without initialize())
    if (cachedList == null)
    {
      config         = loadConfig();
      cachedFilePath = required(config, "keepass.file");
      cachedPassword = required(config, "keepass.password");
      loadDatabase();
    }
    return new ArrayList<>(cachedList); // defensive copy
  }

  /**
   * Finds a single credential by its UUID.
   *
   * @param secretId UUID of the entry to find
   * @return the credential map, or null if not found
   */
  public Map<String, Object> fetchCredentialById(String secretId) throws Exception
  {
    return fetchAllCredentials().stream()
      .filter(e -> secretId.equals(e.get(KEY_SECRET_ID)))
      .findFirst()
      .orElse(null);
  }

  /**
   * Filters credentials by a list of tags.
   *
   * @param tags      list of tags to search for (case-insensitive)
   * @param matchMode AND = all tags must be present, OR = at least one tag
   * @return filtered list of credential maps
   */
  @SuppressWarnings("unchecked")
  public List<Map<String, Object>> fetchCredentialsByTags(List<String> tags, MatchMode matchMode) throws Exception
  {
    if (tags == null || tags.isEmpty())
      return fetchAllCredentials();

    List<String> normalizedTags = tags.stream()
      .map(String::toLowerCase)
      .toList();

    List<Map<String, Object>> all = fetchAllCredentials();
    List<Map<String, Object>> result = new ArrayList<>();

    for (Map<String, Object> credential : all)
    {
      Map<String, Object> content = (Map<String, Object>) credential.get(KEY_CONTENT);
      List<String> credTags = content != null
        ? ((List<String>) content.getOrDefault("tags", new ArrayList<>()))
            .stream().map(String::toLowerCase).toList()
        : new ArrayList<>();

      boolean matches = matchMode == MatchMode.AND
        ? credTags.containsAll(normalizedTags)
        : normalizedTags.stream().anyMatch(credTags::contains);

      if (matches) result.add(credential);
    }

    Log.i("[KeePass] fetchCredentialsByTags(" + matchMode + ", " + tags + ") → " + result.size() + " Treffer");
    return result;
  }

  /**
   * Creates an entry with the given UUID (if it does not yet exist) or updates an
   * existing entry — fields are written individually, i.e. only fields present in
   * the patch are changed, all others remain unchanged.
   *
   * If no entry with this UUID exists, a new entry is created — provided "name"
   * (title) is specified in the patch. New entries always land in the root group
   * (the group structure on the smartphone usually differs from the one in .kdbx,
   * so no group assignment is performed when writing).
   *
   * Sequence: create lock file → backup → write to temp file → atomic rename → delete lock.
   *
   * Supported fields in patch:
   *   name                  — title (required for new entries)
   *   content.username, content.password, content.url, content.notes
   *   content.tags          — List<String>, additively merged with existing tags
   *   content.custom_fields — [{key, value}, ...]  — existing ones updated, new ones added
   *
   * @param secretId UUID of the entry — supplied by the caller for new entries
   * @param patch    map with "name" and/or "content" (subset of fetchAllCredentials structure)
   * @return true on success, false on error (invalid UUID, entry missing without "name", I/O error)
   */
  @SuppressWarnings("unchecked")
  public synchronized boolean upsertCredentialByUuid(String secretId, Map<String, Object> patch)
  {
    if (cachedDb == null || cachedFilePath == null)
    {
      Log.e("[KeePass] upsertCredentialByUuid: Datenbank nicht geladen — initialize() aufrufen");
      return false;
    }

    JacksonDatabase db = (JacksonDatabase) cachedDb;

    UUID targetUuid;
    try
    {
      targetUuid = UUID.fromString(secretId);
    }
    catch (Exception e)
    {
      Log.e("[KeePass] upsertCredentialByUuid: ungültige UUID: " + secretId);
      return false;
    }

    Path dbPath     = Path.of(cachedFilePath);
    Path lockPath   = Path.of(cachedFilePath + ".lock");
    Path tempPath   = Path.of(cachedFilePath + ".tmp");
    Path backupPath = Path.of(cachedFilePath + "."
      + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"))
      + ".bak");

    // ── Create lock file ──────────────────────────────────────────────────
    if (Files.exists(lockPath))
    {
      Log.e("[KeePass] Lock-File existiert — Datei wird gerade verwendet: " + lockPath);
      return false;
    }
    try { Files.writeString(lockPath, "locked by plp-backend"); }
    catch (Exception e) { Log.e("[KeePass] Lock-File konnte nicht angelegt werden: " + e.getMessage()); return false; }

    try
    {
      // ── Find entry in cached DB object, or create new one ─────────────
      JacksonEntry target = (JacksonEntry) findEntryByUuid(db.getRootGroup(), targetUuid);
      boolean isNew = (target == null);

      if (isNew)
      {
        Object nameObj = patch.get(KEY_NAME);
        String name = nameObj != null ? nameObj.toString() : null;
        if (name == null || name.isBlank())
        {
          Log.e("[KeePass] upsertCredentialByUuid: Eintrag " + secretId
            + " nicht gefunden und kein \"" + KEY_NAME + "\" angegeben — Neuanlage abgebrochen");
          return false;
        }

        target = db.newEntry();
        setEntryUuid(target, targetUuid);
        target.setTitle(name);
        db.getRootGroup().addEntry(target);
      }
      else
      {
        Object nameObj = patch.get(KEY_NAME);
        if (nameObj != null) target.setTitle(nameObj.toString());
      }

      // ── Patch content fields ───────────────────────────────────────────
      Map<String, Object> content = (Map<String, Object>) patch.get(KEY_CONTENT);
      if (content != null)
      {
        if (content.containsKey("username")) target.setUsername((String) content.get("username"));
        if (content.containsKey("password")) target.setPassword((String) content.get("password"));
        if (content.containsKey("url"))      target.setUrl((String) content.get("url"));
        if (content.containsKey("notes"))    target.setNotes((String) content.get("notes"));

        // Tags — merged additively (existing tags are preserved).
        // Comparison is case-insensitive to avoid duplicates like "Shared"/"shared".
        if (content.containsKey("tags"))
        {
          Object tagsObj = content.get("tags");
          List<String> newTags = new ArrayList<>();
          if (tagsObj instanceof List<?> rawList)
          {
            for (Object t : rawList)
              if (t != null && !t.toString().isBlank()) newTags.add(t.toString().trim());
          }

          List<String> mergedTags = getEntryTags(target);
          Set<String> existingLower = new HashSet<>();
          for (String t : mergedTags) existingLower.add(t.toLowerCase());

          for (String tag : newTags)
          {
            if (!existingLower.contains(tag.toLowerCase()))
            {
              mergedTags.add(tag);
              existingLower.add(tag.toLowerCase());
            }
          }

          setEntryTags(target, String.join(";", mergedTags));
        }

        // Custom fields — update existing ones, add new ones
        Object cfRaw = content.get("custom_fields");
        if (cfRaw instanceof List<?> cfList)
        {
          for (Object cfObj : cfList)
          {
            if (cfObj instanceof Map<?, ?> cf)
            {
              String key   = (String) cf.get("key");
              String value = (String) cf.get("value");
              if (key != null && value != null)
                target.setProperty(key, value);
            }
          }
        }
      }

      // ── Backup the original file (if it exists) ────────────────────────
      if (Files.exists(dbPath))
      {
        Files.copy(dbPath, backupPath, StandardCopyOption.REPLACE_EXISTING);
        Log.i("[KeePass] Backup angelegt: " + backupPath.getFileName());
      }

      // ── Write to temp file (cachedDb already modified) ────────────────
      try (OutputStream os = new FileOutputStream(tempPath.toFile()))
      {
        db.save(cachedCreds, os);
      }

      // ── Atomic rename ──────────────────────────────────────────────────
      Files.move(tempPath, dbPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);

      // ── Update cache list (no need to reload the DB object) ───────────
      cachedList = new ArrayList<>();
      collectEntries(db.getRootGroup(), cachedList);

      Log.i("[KeePass] Entry " + secretId + (isNew ? " neu angelegt" : " aktualisiert"));
      return true;
    }
    catch (Exception e)
    {
      Log.e("[KeePass] upsertCredentialByUuid error: " + e.getMessage());
      // Clean up temp file if it exists
      try { Files.deleteIfExists(tempPath); } catch (Exception ignored) {}
      return false;
    }
    finally
    {
      // ── Always remove lock file ────────────────────────────────────────
      try { Files.deleteIfExists(lockPath); }
      catch (Exception e) { Log.e("[KeePass] Lock-File konnte nicht gelöscht werden: " + e.getMessage()); }
    }
  }

  // ── Internal helpers ──────────────────────────────────────────────────────

  /** Recursively traverses all groups and collects entries. */
  @SuppressWarnings("unchecked")
  private void collectEntries(Group<?, ?, ?, ?> group, List<Map<String, Object>> result)
  {
    // Entries in this group
    for (Object entryObj : group.getEntries())
    {
      Entry<?, ?, ?, ?> entry = (Entry<?, ?, ?, ?>) entryObj;

      // Tags — stored in KDBX as a direct field, not as a StringProperty.
      // getProperty("Tags") returns null — access via reflection instead.
      String rawTags = null;
      try
      {
        java.lang.reflect.Field tagsField = entry.getClass().getDeclaredField("tags");
        tagsField.setAccessible(true);
        rawTags = (String) tagsField.get(entry);
      }
      catch (Exception ignored) {}
      List<String> tags = new ArrayList<>();
      if (rawTags != null && !rawTags.isBlank())
      {
        for (String tag : rawTags.split("[,;]"))
        {
          String t = tag.trim();
          if (!t.isEmpty()) tags.add(t);
        }
      }

      // Custom fields — all properties that are not standard KeePass fields
      Set<String> standardFields = Set.of("Title", "UserName", "Password", "URL", "Notes");
      List<Map<String, String>> customFields = new ArrayList<>();
      for (String propName : entry.getPropertyNames())
      {
        if (!standardFields.contains(propName))
        {
          Map<String, String> cf = new LinkedHashMap<>();
          cf.put("key",   propName);
          cf.put("value", entry.getProperty(propName));
          customFields.add(cf);
        }
      }

      Map<String, Object> content = new LinkedHashMap<>();
      content.put("username",      entry.getUsername());
      content.put("password",      entry.getPassword());
      content.put("url",           entry.getUrl());
      content.put("notes",         entry.getNotes());
      content.put("custom_fields", customFields);
      content.put("attachments",   new ArrayList<>());
      content.put("tags",          tags);

      Map<String, Object> meta = new LinkedHashMap<>();
      meta.put("type",      "keepass");
      meta.put("group_name",  group.getName());
      meta.put("group_id",    group.getUuid() != null ? group.getUuid().toString() : "");
      meta.put("folder_path", new ArrayList<>());

      Map<String, Object> item = new LinkedHashMap<>();
      item.put(KEY_SECRET_ID, entry.getUuid().toString());
      item.put(KEY_NAME,      entry.getTitle());
      item.put(KEY_CONTENT,   content);
      item.put(KEY_META,      meta);
      result.add(item);
    }

    // Recurse into subgroups
    for (Object subGroupObj : group.getGroups())
    {
      Group<?, ?, ?, ?> subGroup = (Group<?, ?, ?, ?>) subGroupObj;
      collectEntries(subGroup, result);
    }
  }

  /** Recursively searches for an entry by UUID, returns null if not found. */
  @SuppressWarnings("unchecked")
  private Entry<?, ?, ?, ?> findEntryByUuid(Group<?, ?, ?, ?> group, UUID uuid)
  {
    for (Object entryObj : group.getEntries())
    {
      Entry<?, ?, ?, ?> entry = (Entry<?, ?, ?, ?>) entryObj;
      if (uuid.equals(entry.getUuid())) return entry;
    }
    for (Object subGroupObj : group.getGroups())
    {
      Entry<?, ?, ?, ?> found = findEntryByUuid((Group<?, ?, ?, ?>) subGroupObj, uuid);
      if (found != null) return found;
    }
    return null;
  }

  /**
   * Sets the UUID of a newly created entry via reflection.
   *
   * KeePassJava2 always assigns a random UUID when creating ({@code database.newEntry()})
   * and provides no public setter. Since the caller supplies a predetermined UUID
   * (e.g. generated on the smartphone), the protected field "uuid" is overwritten directly.
   */
  private void setEntryUuid(JacksonEntry entry, UUID uuid) throws Exception
  {
    java.lang.reflect.Field uuidField = JacksonEntry.class.getDeclaredField("uuid");
    uuidField.setAccessible(true);
    uuidField.set(entry, uuid);
  }

  /**
   * Sets the tags of an entry via reflection.
   *
   * KeePassJava2 stores tags in the protected field "tags" as a ";"-separated
   * string (see collectEntries) — no public setter exists.
   */
  private void setEntryTags(JacksonEntry entry, String tags) throws Exception
  {
    java.lang.reflect.Field tagsField = JacksonEntry.class.getDeclaredField("tags");
    tagsField.setAccessible(true);
    tagsField.set(entry, tags);
  }

  /**
   * Reads the current tags of an entry via reflection (same logic as collectEntries).
   * Used for additive tag merging in upsertCredentialByUuid.
   */
  private List<String> getEntryTags(JacksonEntry entry)
  {
    String rawTags = null;
    try
    {
      java.lang.reflect.Field tagsField = JacksonEntry.class.getDeclaredField("tags");
      tagsField.setAccessible(true);
      rawTags = (String) tagsField.get(entry);
    }
    catch (Exception ignored) {}

    List<String> tags = new ArrayList<>();
    if (rawTags != null && !rawTags.isBlank())
    {
      for (String tag : rawTags.split("[,;]"))
      {
        String t = tag.trim();
        if (!t.isEmpty()) tags.add(t);
      }
    }
    return tags;
  }

  // ── Config ────────────────────────────────────────────────────────────────

  private static Properties loadConfig() throws Exception
  {
    Properties props = new Properties();

    // 1. Bundled defaults from JAR
    try (InputStream in = BESKeePass.class.getResourceAsStream("/" + PROPERTIES))
    {
      if (in != null)
      {
        props.load(in);
        Log.i("[KeePass] Config: Bundled defaults geladen");
      }
    }

    // 2. External file overrides defaults
    Path external = resolveExternalConfig();
    if (external != null && Files.exists(external))
    {
      try (InputStream in = Files.newInputStream(external))
      {
        props.load(in);
      }
      Log.i("[KeePass] Config: Externe Datei geladen: " + external.toAbsolutePath());
    }
    else
    {
      Log.i("[KeePass] Config: Keine externe " + PROPERTIES + " gefunden, verwende Bundled Defaults");
    }
    return props;
  }

  // Resolves the external {PROPERTIES} in this order:
  //   1. Next to the JAR:    /opt/plp/{PROPERTIES}
  //   2. Working directory:  ./{PROPERTIES}
  private static Path resolveExternalConfig()
  {
    // 1. Directory of the JAR file
    try
    {
      Path jarLocation = Path.of(
        BESKeePass.class.getProtectionDomain().getCodeSource().getLocation().toURI());
      Path jarDir = Files.isDirectory(jarLocation) ? jarLocation : jarLocation.getParent();
      Path p = jarDir.resolve(PROPERTIES);
      Log.i("[KeePass] Config: Suche neben JAR: " + p.toAbsolutePath());
      if (Files.exists(p)) return p;
    }
    catch (Exception e)
    {
      Log.e("[KeePass] Config: JAR-Pfad konnte nicht ermittelt werden: " + e.getMessage());
    }

    // 2. Working directory as fallback
    Path p = Path.of(PROPERTIES);
    Log.i("[KeePass] Config: Suche im Arbeitsverzeichnis: " + p.toAbsolutePath());
    return p;
  }
}
