package plp.handler;

import com.ipoxo.plcore.lib.Log;
import org.eclipse.paho.mqttv5.client.*;
import org.eclipse.paho.mqttv5.client.persist.MemoryPersistence;
import org.eclipse.paho.mqttv5.common.MqttException;
import org.eclipse.paho.mqttv5.common.MqttMessage;
import org.eclipse.paho.mqttv5.common.packet.MqttProperties;
import plp.lib.SslHelper;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;

public class MqttService implements MqttCallback
{
  // Für Tests: jedes TLS-Zertifikat akzeptieren, ohne die Chain zu prüfen.
  // Vor dem Produktiv-Einsatz auf false setzen!
  private static final boolean ACCEPT_ALL_CERTS = true;

  private static MqttService instance;

  /** Eingehende MQTT-Message für die inQueue. */
  public record InMessage(String topic, byte[] payload, int qos) {}

  /** Ausgehende MQTT-Message für die outQueue. */
  public record OutMessage(String topic, byte[] payload) {}

  private static final int QUEUE_CAPACITY = 500;

  private final LinkedBlockingQueue<InMessage>  inQueue  = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
  private final LinkedBlockingQueue<OutMessage> outQueue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);

  /*
  // MessageListener — nicht mehr aktiv, BridgeHandler wurde entfernt
  @FunctionalInterface
  public interface MessageListener
  {
    void onMessage(String topic, byte[] payload, int qos);
  }
  private final List<MessageListener> listeners = new java.util.concurrent.CopyOnWriteArrayList<>();
  public void addMessageListener(MessageListener listener) { listeners.add(listener); }
  */

  // Topic-basiertes Routing — Handler registrieren sich mit ihrem Topic-Präfix
  @FunctionalInterface
  public interface TopicHandler
  {
    void onMessage(String topic, byte[] payload, int qos);
  }

  private final Map<String, TopicHandler> topicHandlers = new java.util.concurrent.ConcurrentHashMap<>();

  /**
   * Registriert einen Handler für einen Topic-Präfix.
   * Eingehende Messages deren Topic mit dem Präfix beginnt werden an diesen Handler gerouted.
   */
  public void registerTopicHandler(String topicPrefix, TopicHandler handler)
  {
    topicHandlers.put(topicPrefix, handler);
    Log.i("[MQTT] TopicHandler registriert für Präfix: " + topicPrefix);
  }

  // ── OnConnectedListener ───────────────────────────────────────────────────

  @FunctionalInterface
  public interface OnConnectedListener
  {
    void onConnected(MqttService mqtt);
  }

  private final List<OnConnectedListener> onConnectedListeners = new java.util.concurrent.CopyOnWriteArrayList<>();

  /**
   * Registriert einen Listener der aufgerufen wird sobald die MQTT-Verbindung steht.
   * Ist bereits verbunden, wird der Listener sofort aufgerufen.
   */
  public void registerOnConnectedListener(OnConnectedListener listener)
  {
    onConnectedListeners.add(listener);
    if (isConnected()) listener.onConnected(this);
  }

  private MqttClient client;
  private String brokerUrl = "(nicht verbunden)";

  // Dynamisch registrierte Topics — werden bei Reconnect erneut abonniert
  private final List<String> subscribedTopics = new java.util.concurrent.CopyOnWriteArrayList<>();
  private MqttConnectionOptions connectOpts;
  private int retryIntervalS = 30;

  // ── Gecachte Config ───────────────────────────────────────────────────────

  private Properties config;

  /** Liefert die gecachte Config — public damit BESxxx darauf zugreifen können. */
  public Properties getConfig() { return config; }

  private MqttService() {}

  public static synchronized MqttService getInstance()
  {
    if (instance == null) instance = new MqttService();
    return instance;
  }

  public void connect() throws Exception
  {
    config = loadConfig();

    brokerUrl          = required(config, "broker.url");
    String clientId    = config.getProperty("client.id", "plp-backend-" + UUID.randomUUID());
    int keepAlive      = Integer.parseInt(config.getProperty("keepalive.seconds", "60"));
    retryIntervalS     = Integer.parseInt(config.getProperty("connect.retry.seconds", "30"));

    connectOpts = new MqttConnectionOptions();
    connectOpts.setAutomaticReconnect(true);
    connectOpts.setCleanStart(true);
    connectOpts.setKeepAliveInterval(keepAlive);

    String username = config.getProperty("auth.username", "").trim();
    String password  = config.getProperty("auth.password", "").trim();
    if (!username.isEmpty())
    {
      connectOpts.setUserName(username);
      connectOpts.setPassword(password.getBytes(StandardCharsets.UTF_8));
    }

    if (brokerUrl.startsWith("ssl://"))
    {
      String clientCert = required(config, "tls.client.cert");
      String clientKey  = required(config, "tls.client.key");

      if (ACCEPT_ALL_CERTS)
      {
        connectOpts.setSocketFactory(SslHelper.buildSocketFactoryTrustAll(clientCert, clientKey));
        connectOpts.setHttpsHostnameVerificationEnabled(false);
        Log.i("[MQTT] TEST_ACCEPT_ALL_CERTS=true — Server-Zertifikat und Hostname werden nicht geprüft!");
      }
      else
      {
        connectOpts.setSocketFactory(SslHelper.buildSocketFactory(clientCert, clientKey));
      }
    }

//    setupPahoLogging_obsolet();

    client = new MqttClient(brokerUrl, clientId, new MemoryPersistence());
    client.setCallback(this);

    connectWithRetry();
    startConsumerThread();
    startSenderThread();
  }

  // ── Config ────────────────────────────────────────────────────────────────

  private static final String PROPERTIES = "mqtt.properties";

  public static Properties loadConfig() throws Exception
  {
    Properties props = new Properties();

    // 1. Bundled defaults from JAR
    try (java.io.InputStream in = MqttService.class.getResourceAsStream("/" + PROPERTIES))
    {
      if (in != null) props.load(in);
    }

    // 2. Externe Datei (neben der JAR) überschreibt Defaults
    java.nio.file.Path external = java.nio.file.Path.of(PROPERTIES);

    if (java.nio.file.Files.exists(external))
    {
      try (java.io.InputStream in = java.nio.file.Files.newInputStream(external))
      {
        props.load(in);
      }
      Log.i("[MQTT] Config geladen: " + external.toAbsolutePath());
    }
    return props;
  }

  /** Consumer-Thread: nimmt Messages aus inQueue und routet sie topic-basiert. */
  private void startConsumerThread()
  {
    Thread.ofVirtual().name("mqtt-consumer").start(() ->
    {
      while (!Thread.interrupted())
      {
        try
        {
          InMessage msg = inQueue.take();

          // Prüfe ob ein registrierter TopicHandler zuständig ist
          TopicHandler handler = topicHandlers.entrySet().stream()
            .filter(e -> msg.topic().startsWith(e.getKey()))
            .map(Map.Entry::getValue)
            .findFirst()
            .orElse(null);

          if (handler != null)
            handler.onMessage(msg.topic(), msg.payload(), msg.qos());
          else
            Log.e("[MQTT] Kein Handler für Topic: " + msg.topic());
        }
        catch (InterruptedException e)
        {
          Thread.currentThread().interrupt();
        }
        catch (Exception e)
        {
          Log.e("[MQTT] Consumer error: " + e.getMessage());
        }
      }
    });
  }

  /** Sender-Thread: nimmt Messages aus outQueue und publiziert sie an den Broker. */
  private void startSenderThread()
  {
    Thread.ofVirtual().name("mqtt-sender").start(() ->
    {
      while (!Thread.interrupted())
      {
        try
        {
          OutMessage msg = outQueue.take();
          publish(msg.topic(), msg.payload(), 1);
        }
        catch (InterruptedException e)
        {
          Thread.currentThread().interrupt();
        }
        catch (Exception e)
        {
          Log.e("[MQTT] Sender error: " + e.getMessage());
        }
      }
    });
  }

  /** Legt eine ausgehende Message in die outQueue. Wird von BES aufgerufen. */
  public void send(String topic, byte[] payload)
  {
    if (!outQueue.offer(new OutMessage(topic, payload)))
    {
      Log.e("[MQTT] outQueue voll – Message verworfen: " + topic);
    }
  }

  private void connectWithRetry()
  {
    Thread.ofVirtual().name("mqtt-connect").start(() ->
    {
      while (!Thread.interrupted())
      {
        try
        {
          client.connect(connectOpts);
          for (String t : subscribedTopics) client.subscribe(t, 1);
          Log.i("[MQTT] Connected: " + brokerUrl + " | keepalive=" + connectOpts.getKeepAliveInterval() + "s");
          return; // Paho handles reconnect from here
        }
        catch (MqttException e)
        {
          Log.e("[MQTT] Connection failed, retry in " + retryIntervalS + "s: " + e.getMessage());
          try { Thread.sleep(retryIntervalS * 1000L); } catch (InterruptedException ie) { return; }
        }
      }
    });
  }

  /** Abonniert ein Topic und merkt es für automatisches Re-Subscribe bei Reconnect. */
  public void subscribe(String topic) throws MqttException
  {
    if (!subscribedTopics.contains(topic))
      subscribedTopics.add(topic);
    client.subscribe(topic, 1);
    Log.i("[MQTT] Subscribed: " + topic);
  }

  public void publish(String topic, byte[] payload, int qos) throws MqttException
  {
    MqttMessage msg = new MqttMessage(payload, qos, false, new MqttProperties());
    client.publish(topic, msg);
  }

  public boolean isConnected()
  {
    return client != null && client.isConnected();
  }

  public String getBrokerUrl()
  {
    return brokerUrl;
  }

  // --- MqttCallback ---

  @Override
  public void connectComplete(boolean reconnect, String serverURI)
  {
    String type = reconnect ? "Reconnected" : "Connected";
    Log.i("[MQTT] " + type + " to " + serverURI);

    // Listener informieren — beim ersten Connect subscriben sie ihre Topics
    if (!reconnect)
      onConnectedListeners.forEach(l -> l.onConnected(this));

    if (reconnect)
    {
      // CleanStart=true clears the session on the broker —
      // re-subscribe to all registered topics after every reconnect
      for (String t : subscribedTopics)
      {
        try
        {
          client.subscribe(t, 1);
          Log.i("[MQTT] Re-subscribed: " + t);
        }
        catch (MqttException e)
        {
          Log.e("[MQTT] Re-subscribe failed for " + t + ": " + e.getMessage());
        }
      }
    }
  }

  @Override
  public void disconnected(MqttDisconnectResponse response)
  {
    Log.e("[MQTT] Connection lost (RC=" + response.getReturnCode() + "): " + response.getException().getMessage());
  }

  @Override
  public void mqttErrorOccurred(MqttException exception)
  {
    Log.e("[MQTT] Error (RC=" + exception.getReasonCode() + "): " + exception.getMessage());
  }

  @Override
  public void messageArrived(String topic, MqttMessage message)
  {
    byte[] payload = message.getPayload();
    //Log.i("[MQTT] Received  | Topic: " + topic + " | " + payload.length + " bytes");

    if (!inQueue.offer(new InMessage(topic, payload, message.getQos())))
    {
      Log.e("[MQTT] inQueue voll – Message verworfen: " + topic);
    }
  }

  @Override
  public void deliveryComplete(IMqttToken token)
  {
    try
    {
      String topics = token.getTopics() != null ? String.join(", ", token.getTopics()) : "?";
      //Log.i("[MQTT] Delivered | Topic: " + topics);
    }
    catch (Exception ignored) {}
  }

  @Override
  public void authPacketArrived(int reasonCode, MqttProperties properties)
  {
    // Enhanced Authentication — not used
  }


  // Enables Paho's internal JUL logging at FINE level.
  // This includes PINGREQ and PINGRESP packets.
  /*
  private static void setupPahoLogging_obsolet()
  {
    java.util.logging.Logger pahoLogger = java.util.logging.Logger.getLogger("org.eclipse.paho");
    if (pahoLogger.getHandlers().length > 0) return;

    pahoLogger.setUseParentHandlers(false);
    pahoLogger.setLevel(Level.FINE);

    StreamHandler handler = new StreamHandler(System.out, new Formatter()
    {
      @Override public String format(LogRecord r)
      {
        String src = r.getSourceClassName();
        src = src.substring(src.lastIndexOf('.') + 1);
        return String.format("[MQTT LOG] |> %-20s |> %s%n", src, r.getMessage());
      }
    });
    handler.setLevel(Level.FINE);
    pahoLogger.addHandler(handler);
  }
  */

  private static String required(Properties cfg, String key)
  {
    String value = cfg.getProperty(key);
    if (value == null || value.isBlank())
      throw new IllegalStateException("mqtt.properties: Pflichtfeld '" + key + "' fehlt");
    return value.trim();
  }
}
