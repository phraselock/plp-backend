package plp.processor;

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
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Set;


public abstract class BESCore
{

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

  // ── Gecachte Config ───────────────────────────────────────────────────────

  protected Properties config;

  public Properties getConfig() { return config; }

  static String required(Properties cfg, String key)
  {
    String value = cfg.getProperty(key);
    if (value == null || value.isBlank())
      throw new IllegalStateException("psono.properties: Pflichtfeld '" + key + "' fehlt");
    return value.trim().replace("\"", ""); // Anführungszeichen entfernen falls vorhanden
  }


  // ── Message handling ──────────────────────────────────────────────────────
  /**
   * Wird vom Consumer-Thread in MqttService aufgerufen.
   * Topic-Struktur: BES-{uuid}/{type}/{...}
   *   parts[0] = root namespace  (z.B. "BES-uuid")
   *   parts[1] = message type    (z.B. "data", "device", "status")
   *   parts[2..n] = weitere Segmente, handler-spezifisch
   */
  public void onMqttMessage(String topic, byte[] payload, int qos)
  {
    String[] parts = topic.split("/");
    dispatch(parts, payload, qos);
  }

  private void dispatch(String[] parts, byte[] payload, int qos)
  {
    if (parts.length >= 1)
    {
      String jsonstr = new String(payload, StandardCharsets.UTF_8);
      receiveFromPeer(parts, jsonstr);
      return;
    }
  }

  protected abstract void receiveFromPeer(String[] topics, String jsonstr);

  /** Sendet eine Message asynchron über MqttService (→ outQueue). */
  public void send(String topic, byte[] payload)
  {
    MqttService.getInstance().send(topic, payload);
  }


}
