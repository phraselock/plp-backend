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
  protected Properties config;

  public Properties getConfig() { return config; }

  static String required(Properties cfg, String key)
  {
    String value = cfg.getProperty(key);
    if (value == null || value.isBlank())
      throw new IllegalStateException("psono.properties: Pflichtfeld '" + key + "' fehlt");
    return value.trim().replace("\"", ""); // strip surrounding quotes if present
  }


  // ── Message handling ──────────────────────────────────────────────────────
  /**
   * Called by the consumer thread in MqttService.
   * Topic structure: BES-{uuid}/{type}/{...}
   *   parts[0] = root namespace  (e.g. "BES-uuid")
   *   parts[1] = message type    (e.g. "data", "device", "status")
   *   parts[2..n] = additional segments, handler-specific
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

  /** Sends a message asynchronously via MqttService (→ outQueue). */
  public void send(String topic, byte[] payload)
  {
    MqttService.getInstance().send(topic, payload);
  }


}
