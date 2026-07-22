package plp.processor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ipoxo.lib.AESPlnk;
import com.ipoxo.plcore.lib.db.ksAnd;
import com.ipoxo.lib.PeerCom;
import com.ipoxo.lib.PhraseX;
import com.ipoxo.plcore.ctap2ecc.CTAP2EccJava;
import com.ipoxo.plcore.lib.Configuration;
import com.ipoxo.plcore.lib.DDXMLElement;
import com.ipoxo.plcore.lib.FCOEM;
import com.ipoxo.plcore.lib.Log;
import org.jetbrains.annotations.NotNull;
import org.json.JSONObject;
import plp.handler.MqttService;
import plp.lib.Redis;
import plp.provider.CredentialProvider;
import plp.provider.PsonoProvider;
import plp.provider.RestResponse;
import plp.psono.PsonoConfig;
import plp.psono.PsonoServerConfig;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/*
    String d = null;
    String x = null;
    String y = null;

    byte[][] eccKey = CTAP2EccJava.createECCKeyASN();
    d = FCOEM.byteArrayToHexString(eccKey[0]);
    x = FCOEM.byteArrayToHexString(eccKey[1]);
    y = FCOEM.byteArrayToHexString(eccKey[2]);

 */
public class BESPsono extends BESCore
{
  final static String PROPERTIES = "psono.properties";

  // ── Singleton ─────────────────────────────────────────────────────────────

  private static BESPsono instance;

  public static synchronized BESPsono getInstance()
  {
    if (instance == null) instance = new BESPsono();
    return instance;
  }

  // ── Provider-Registry ────────────────────────────────────────────────────

  private final List<CredentialProvider> providers = new ArrayList<>();

  public void registerProvider(CredentialProvider provider)
  {
    providers.add(provider);
    Log.i("[BES] Provider registriert: " + provider.getName());
  }

  /** Liefert den ersten registrierten Provider mit dem gegebenen Namen, oder null. */
  public CredentialProvider getProvider(String name)
  {
    return providers.stream()
      .filter(p -> p.getName().equalsIgnoreCase(name))
      .findFirst()
      .orElse(null);
  }

  /**
   * Returns a pretty-printed JSON representation of the given value.
   * Accepts either a JSON string or an already-parsed object (Map, List, …).
   * Falls back to {@code String.valueOf(value)} if serialisation fails.
   */
  public static String prettyJson(Object value)
  {
    try
    {
      ObjectMapper mapper = new ObjectMapper();
      Object target = (value instanceof String s) ? mapper.readValue(s, Object.class) : value;
      return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(target);
    }
    catch (Exception e)
    {
      return String.valueOf(value);
    }
  }

  /**
   * Gibt einen XML-String formatiert (pretty-printed) zurück.
   * Akzeptiert sowohl einen XML-String als auch ein org.w3c.dom.Document.
   * Fällt auf {@code String.valueOf(value)} zurück wenn Parsing fehlschlägt.
   */
  public static String prettyXml(Object value)
  {
    try
    {
      javax.xml.transform.Source source;

      if (value instanceof String s)
      {
        javax.xml.parsers.DocumentBuilder db =
          javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder();
        org.w3c.dom.Document doc = db.parse(new org.xml.sax.InputSource(new java.io.StringReader(s)));
        source = new javax.xml.transform.dom.DOMSource(doc);
      }
      else if (value instanceof org.w3c.dom.Document doc)
      {
        source = new javax.xml.transform.dom.DOMSource(doc);
      }
      else
      {
        return String.valueOf(value);
      }

      javax.xml.transform.Transformer transformer =
        javax.xml.transform.TransformerFactory.newInstance().newTransformer();
      transformer.setOutputProperty(javax.xml.transform.OutputKeys.INDENT,    "yes");
      transformer.setOutputProperty(javax.xml.transform.OutputKeys.ENCODING,  "UTF-8");
      transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");

      java.io.StringWriter writer = new java.io.StringWriter();
      transformer.transform(source, new javax.xml.transform.stream.StreamResult(writer));
      return writer.toString();
    }
    catch (Exception e)
    {
      return String.valueOf(value);
    }
  }

  /** Liefert die Service-UUID aus psono.properties. */
  public String getServiceUuid()
  {
    return config != null ? config.getProperty("service.uuid", "") : "";
  }

  private BESPsono() {}

  public void initialize(MqttService mqtt) throws Exception
  {
    config = loadConfig();

    // ── PsonoProvider aus psono.properties aufbauen ───────────────────────
    String serverUrl  = required(config, "psono.server.url");
    String serverPubl = required(config, "psono.server.publ");
    String serverSign = required(config, "psono.server.sign");
    String apiKey     = required(config, "psono.api.key");
    String apiPriv    = required(config, "psono.api.priv");
    String apiSecr    = required(config, "psono.api.secr");

    PsonoServerConfig serverConfig = PsonoServerConfig.builder()
      .serverUrl      (serverUrl)
      .serverPublicKey(serverPubl)
      .serverSignature(serverSign)
      .build();

    PsonoConfig psonoConfig = PsonoConfig.builder()
      .server          (serverConfig)
      .apiKeyId        (apiKey)
      .apiKeyPrivateKey(apiPriv)
      .apiKeySecretKey (apiSecr)
      .build();

    registerProvider(new PsonoProvider(psonoConfig));

    // ── Topic registrieren sobald Verbindung steht ────────────────────────
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
          Log.i("[BESPsono] Topic registriert: " + topicBase + "/#");
        }
        catch (Exception e)
        {
          Log.e("[BESPsono] Topic-Registrierung fehlgeschlagen: " + e.getMessage());
        }
      });
    }
  }

  private void requestPeerData(String peerAdrGUID)
  {
    try
    {
      PeerCom.removeSession(peerAdrGUID);
      PeerCom.sessionForPeer(peerAdrGUID).phraseLidx = 0;

      byte[] mqttData = PeerCom.buildPeerDataRequest(peerAdrGUID, getServiceUuid(),PeerCom.MQTT_PEER_DATA_REQUEST_PSONO);

      String topic = PeerCom.pfxPEER + peerAdrGUID;

      send(topic,mqttData);

    } catch (Exception e)
    {
      if (Configuration.DBGEN) Log.d(Configuration.DBGLEVEL,"Exception in sendToPeer: " + e.getMessage());
    }
  }

  public List<String> buildPhraseXExportV030FromPsono(AESPlnk aes, String besUUID, String  jsonString)
  {
    List<String> credList = new ArrayList<>();

    try {
      ObjectMapper mapper = new ObjectMapper();
      // Liste parsen
      JsonNode secrets = mapper.readTree(jsonString);
      int cx=0;
      for (JsonNode secret : secrets)
      {
        StringBuilder phraseDump = new StringBuilder();
        phraseDump.append("<PHRASE>");

        String secretId     = secret.path("secret_id").asText();
        //String name       = secret.get("name").asText();
        String type         = secret.path("meta").path("type").asText();
        String cat_name     = secret.path("meta").path("group_name").asText();
        String cat_uuid     = secret.path("meta").path("group_id").asText();

        JsonNode content    = secret.path("content");
        if(content!=null && !content.isEmpty()) {
          String label = "";
          String p1 = "";
          String p2 = "";
          String p3 = "";
          String link = "";
          String txt = "";

          String otp = null;
          //String fidoToken    = null;  Kommt später wenn wir auch Schreiben nach Psono beherschen
          //String fidoPin      = null;  Kommt später wenn wir auch Schreiben nach Psono beherschen

          if (type.equals("website_password")) {
            label = content.path("website_password_title").asText();
            p1 = content.path("website_password_username").asText();
            p2 = content.path("website_password_password").asText();
            link = content.path("website_password_url").asText();
            otp = content.path("website_password_totp_code").asText();
            txt = content.path("website_password_notes").asText();

          } else if (type.equals("application_password")) {
            label = content.path("application_password_title").asText();
            p1 = content.path("application_password_username").asText();
            p2 = content.path("application_password_password").asText();

            txt = content.path("application_password_notes").asText();
          }

          DDXMLElement p4enc = PhraseX.makeNewP4(aes, p1, p2, p3, link, txt);

          DDXMLElement p4dec = PhraseX.decryptP4ForExport(aes, p4enc);

          if (otp != null) {
            PhraseX.setOTPSecretCode(p4dec, otp);
            PhraseX.setOTPActive(p4enc, true);
            PhraseX.setOTPTimerType(p4enc);
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
      Log.e("Exception in buildPhraseXExportV030FromPsono: " + e.getMessage());
    }
    return credList;
  }

  @Override
  protected void receiveFromPeer(String[] topics, String jsonstr)
  {
    try
    {
      JSONObject jsonObj = new JSONObject(jsonstr);

      String peer = jsonObj.getString("peer");
      String request = jsonObj.getString("request");
      //String version = jsonObj.getString("version");
      //String hash = jsonObj.getString("hash");
      //String signature = jsonObj.getString("signature");
      //String contentb64 = jsonObj.getString("content");
      //Log.i("BES received: " + request + " -> " + prettyJson(jsonstr));

      if(request.equalsIgnoreCase(PeerCom.MQTT_FULL_SYNC_REQUEST_PSONO))
      {
        Set<String> peerConfig = Redis.readPeerConfig(peer);
        if(peerConfig!=null && peerConfig.size()>0) {
          JSONObject peerDict = new JSONObject(peerConfig.stream().findFirst().orElse(null));

          String payload = PeerCom.getNSStringPayLoad(peerDict, jsonObj);
          RestResponse  restResponse = handleFetchAllCredentials();
          //RestResponse  restResponse = handleFetchCredentialById("8c20c52a-4005-41a5-8fff-98f320cff340");
          //RestResponse  restResponse = handleFetchCredentialById("6ef50953-0fad-452a-b38c-9cc109925a8d");
          //RestResponse  restResponse = handleFetchCredentialById("b84d6e1f-7da5-48de-bd4b-903a61a91850");
          if(restResponse!=null)
          {
            Properties cfg = config;
            String sUUID = cfg.getProperty("service.uuid",null);
            String sd = MqttService.getInstance().getConfig().getProperty("bes.id.dpriv");

            byte[] iv = CTAP2EccJava.generateRandom(16);
            AESPlnk aes = new AESPlnk(FCOEM.hexStringToByteArray(sd),iv);

            //Log.i("MQTT_FULL_SYNC_REQUEST_PSONO payload: " + prettyJson(restResponse.body()));
            Log.i("MQTT_FULL_SYNC_REQUEST_PSONO payload: " + restResponse.body());
            PeerCom.sessionForPeer(peer).credList = buildPhraseXExportV030FromPsono(aes, sUUID, restResponse.body());
            if(PeerCom.sessionForPeer(peer).credList!=null && !PeerCom.sessionForPeer(peer).credList.isEmpty())
            {
              String xmlCred = PeerCom.sessionForPeer(peer).credList.getFirst();
              if(xmlCred!=null)
              {
                //Log.i("MQTT_ENC_PAYLOAD_PSONO payload: " + prettyXml(xmlCred));
                Log.i("MQTT_ENC_PAYLOAD_PSONO payload: " + xmlCred);
                byte[] mqttData = PeerCom.buildPayloadTransfer(peer,PeerCom.MQTT_ENC_PAYLOAD_PSONO,xmlCred, getServiceUuid());
                if(mqttData!=null) {
                  String topic = PeerCom.pfxPEER + peer;
                  send(topic, mqttData);
                }
                PeerCom.sessionForPeer(peer).credList.removeFirst();
              }
            }
          }
        }
      }
      else if(request.equalsIgnoreCase(PeerCom.MQTT_ACK_PAYLOAD_PSONO))
      {
        if(PeerCom.sessionForPeer(peer).credList!=null && !PeerCom.sessionForPeer(peer).credList.isEmpty())
        {
          String xmlCred = PeerCom.sessionForPeer(peer).credList.getFirst();
          if(xmlCred!=null)
          {
            //Log.i("MQTT_ENC_PAYLOAD_NEXT_PSONO payload: " + prettyXml(xmlCred));
            Log.i("MQTT_ENC_PAYLOAD_NEXT_PSONO payload: " + xmlCred);
            byte[] mqttData = PeerCom.buildPayloadTransfer(peer,PeerCom.MQTT_ENC_PAYLOAD_NEXT_PSONO,xmlCred, getServiceUuid());
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
      else if(request.equalsIgnoreCase(PeerCom.MQTT_PEER_DATA_RESPONSE_PSONO))
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
      else if(request.equalsIgnoreCase(PeerCom.MQTT_SKEY_NEGO_REQUEST_PSONO))
      {
        Set<String> peerConfig = Redis.readPeerConfig(peer);
        if(peerConfig!=null && !peerConfig.isEmpty())
        {
          JSONObject peerDict = new JSONObject(peerConfig.stream().findFirst().orElse(null));
          byte[] mqttData = PeerCom.buildSKeyNegotiationResponse(peerDict, jsonObj, getServiceUuid(),PeerCom.MQTT_SKEY_NEGO_RESPONSE_PSONO);
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

  private RestResponse handleFetchAllCredentials() throws Exception
  {
    if (providers.isEmpty()) {
      return RestResponse.error(503, "No credential providers registered");
    }
    // Erster Provider — TODO: Provider-Auswahl via Request-Parameter oder Bearer
    var result = providers.get(0).fetchAllCredentials();
    ObjectMapper mapper = new ObjectMapper();
    return RestResponse.ok(mapper.writeValueAsString(result));
  }

  private RestResponse handleFetchCredentialById(String id) throws Exception
  {
    if (providers.isEmpty())
      return RestResponse.error(503, "No credential providers registered");

    var result = providers.get(0).fetchCredentialById(id);
    if (result == null)
      return RestResponse.error(404, "Credential not found: " + id);

    ObjectMapper mapper = new ObjectMapper();
    return RestResponse.ok(mapper.writeValueAsString(List.of(result)));
  }

  // ── Config ────────────────────────────────────────────────────────────────
  @NotNull
  static public Properties loadConfig() throws IOException
  {
    Properties props = new Properties();

    // 1. Bundled defaults from JAR
    try (InputStream in = MqttService.class.getResourceAsStream("/" + PROPERTIES))
    {
      if (in != null)
      {
        props.load(in);
        //Log.i("[MQTT] Config: Bundled defaults loaded");
      }
    }

    // 2. Resolve and load external file (overrides bundled defaults)
    Path external = resolveExternalConfig();
    if (external != null && Files.exists(external))
    {
      try (InputStream in = Files.newInputStream(external))
      {
        props.load(in);
      }
      //Log.i("[MQTT] Config: External file loaded: " + external.toAbsolutePath());
    }
    else
    {
      //Log.i("[MQTT] Config: No external " + PROPERTIES + " found, using bundled defaults only");
    }
    return props;
  }

  // Resolves the external {PROPERTIES} in this order:
  //   1. Next to the JAR:    /opt/plp/{PROPERTIES}
  //   2. Working directory:  ./{PROPERTIES}
  @NotNull
  private static Path resolveExternalConfig()
  {
    // 1. Directory of the JAR file
    try
    {
      Path jarLocation = Path.of(
        MqttService.class.getProtectionDomain().getCodeSource().getLocation().toURI());
      Path jarDir = Files.isDirectory(jarLocation) ? jarLocation : jarLocation.getParent();
      Path p = jarDir.resolve(PROPERTIES);
      //Log.i("[MQTT] Config: Looking next to JAR: " + p.toAbsolutePath());
      if (Files.exists(p)) return p;
    }
    catch (Exception e)
    {
      Log.e("[MQTT] Config: Could not determine JAR path: " + e.getMessage());
    }

    // 2. Working directory as fallback
    Path p = Path.of(PROPERTIES);
    //Log.i("[MQTT] Config: Looking in working directory: " + p.toAbsolutePath());
    return p;
  }
}
