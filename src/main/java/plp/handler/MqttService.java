package plp.handler;

import com.ipoxo.plcore.lib.Log;
import org.eclipse.paho.mqttv5.client.*;
import org.eclipse.paho.mqttv5.client.persist.MemoryPersistence;
import org.eclipse.paho.mqttv5.common.MqttException;
import org.eclipse.paho.mqttv5.common.MqttMessage;
import org.eclipse.paho.mqttv5.common.packet.MqttProperties;
import plp.lib.ConfigPathResolver;
import plp.lib.SslHelper;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;

public class MqttService implements MqttCallback
{
  // For testing: accept any TLS certificate without validating the chain.
  // Set to false before production use!
  private static final boolean ACCEPT_ALL_CERTS = true;

  private static MqttService instance;

  /** Incoming MQTT message for the inQueue. */
  public record InMessage(String topic, byte[] payload, int qos) {}

  /** Outgoing MQTT message for the outQueue. */
  public record OutMessage(String topic, byte[] payload) {}

  private static final int QUEUE_CAPACITY = 500;

  private final LinkedBlockingQueue<InMessage>  inQueue  = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
  private final LinkedBlockingQueue<OutMessage> outQueue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);

  /*
  // MessageListener — no longer active, BridgeHandler was removed
  @FunctionalInterface
  public interface MessageListener
  {
    void onMessage(String topic, byte[] payload, int qos);
  }
  private final List<MessageListener> listeners = new java.util.concurrent.CopyOnWriteArrayList<>();
  public void addMessageListener(MessageListener listener) { listeners.add(listener); }
  */

  // Topic-based routing — handlers register with their topic prefix
  @FunctionalInterface
  public interface TopicHandler
  {
    void onMessage(String topic, byte[] payload, int qos);
  }

  private final Map<String, TopicHandler> topicHandlers = new java.util.concurrent.ConcurrentHashMap<>();

  /**
   * Registers a handler for a topic prefix.
   * Incoming messages whose topic starts with the prefix are routed to this handler.
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
   * Registers a listener that is called once the MQTT connection is established.
   * If already connected, the listener is called immediately.
   */
  public void registerOnConnectedListener(OnConnectedListener listener)
  {
    onConnectedListeners.add(listener);
    if (isConnected()) listener.onConnected(this);
  }

  private MqttClient client;
  private String brokerUrl = "(nicht verbunden)";

  // Dynamically registered topics — re-subscribed on reconnect
  private final List<String> subscribedTopics = new java.util.concurrent.CopyOnWriteArrayList<>();
  private MqttConnectionOptions connectOpts;
  private int retryIntervalS = 30;

  // ── Cached config ─────────────────────────────────────────────────────────

  private Properties config;

  /** Returns the cached config — public so BES classes can access it. */
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

    // 2. External file overrides defaults — searched in this order:
    //      a) next to the JAR        (Linux /opt/plp/ layout)
    //      c) working directory      (fallback / dev)
    java.nio.file.Path external = ConfigPathResolver.resolve(PROPERTIES, MqttService.class);

    if (java.nio.file.Files.exists(external))
    {
      try (java.io.InputStream in = java.nio.file.Files.newInputStream(external))
      {
        props.load(in);
      }
      Log.i("[MQTT] Config loaded: " + external.toAbsolutePath());
    }
    return props;
  }

  /** Consumer thread: takes messages from inQueue and routes them by topic. */
  private void startConsumerThread()
  {
    Thread.ofVirtual().name("mqtt-consumer").start(() ->
    {
      while (!Thread.interrupted())
      {
        try
        {
          InMessage msg = inQueue.take();

          // Check if a registered TopicHandler is responsible
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

  /** Sender thread: takes messages from outQueue and publishes them to the broker. */
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

  /** Puts an outgoing message into the outQueue. Called by BES. */
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

  /** Subscribes to a topic and tracks it for automatic re-subscribe on reconnect. */
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

  public void disconnect()
  {
    if (client == null) return;
    try { client.disconnect(); } catch (MqttException ignored) {}
    try { client.close();      } catch (MqttException ignored) {}
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

    // Notify listeners — on first connect they subscribe their topics
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
