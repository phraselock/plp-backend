package plp.backend;

import com.ipoxo.plcore.lib.Log;
import io.javalin.Javalin;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import plp.handler.ConfigHandler;
import plp.handler.KeePassHandler;
import plp.handler.WebAuthnHandler;
import plp.lib.ConfigPathResolver;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Starts the Javalin web server (HTTP API) with IP allowlist and registers
 * all route handlers. Independent of Psono, KeePass, or other providers.
 */
public class PLPApplication
{
  private static final String PROPERTIES = "application.properties";

  private static final Properties  CONFIG      = loadConfig();
  private static final Set<String> ALLOWED_IPS = parseAllowedIps(CONFIG);
  private static final int         PORT        = Integer.parseInt(CONFIG.getProperty("server.port", "8080"));
  private static final int         MAX_THREADS = Integer.parseInt(CONFIG.getProperty("jetty.maxThreads", "10"));
  private static final int         MIN_THREADS = Integer.parseInt(CONFIG.getProperty("jetty.minThreads", "2"));

  private static Properties loadConfig()
  {
    Properties props = new Properties();

    // 1. Bundled defaults from JAR
    try (InputStream in = PLPApplication.class.getResourceAsStream("/" + PROPERTIES))
    {
      if (in != null) props.load(in);
    }
    catch (IOException e)
    {
      throw new RuntimeException("Failed to load " + PROPERTIES, e);
    }

    // 2. External file overrides defaults — searched in this order:
    //      a) next to the JAR        (Linux /opt/plp/ layout)
    //      c) working directory      (fallback / dev)
    Path external = ConfigPathResolver.resolve(PROPERTIES, PLPApplication.class);

    if (Files.exists(external))
    {
      try (InputStream in = Files.newInputStream(external))
      {
        props.load(in);
      }
      catch (IOException e)
      {
        throw new RuntimeException("Failed to load " + external.toAbsolutePath(), e);
      }
      Log.i("[PLPService] Config geladen: " + external.toAbsolutePath());
    }

    return props;
  }

  private static Set<String> parseAllowedIps(Properties props)
  {
    return Arrays.stream(props.getProperty("allowed.ips", "").split(","))
      .map(String::trim)
      .filter(ip -> !ip.isEmpty())
      .collect(Collectors.toSet());
  }

  /** Controls whether {@code BESPsono} is initialised on startup (application.properties: bes.psono.enabled). */
  public static boolean isPsonoEnabled()
  {
    return Boolean.parseBoolean(CONFIG.getProperty("bes.psono.enabled", "true"));
  }

  /** Controls whether {@code BESKeePass} is initialised on startup (application.properties: bes.keepass.enabled). */
  public static boolean isKeePassEnabled()
  {
    return Boolean.parseBoolean(CONFIG.getProperty("bes.keepass.enabled", "true"));
  }

  private static Javalin web;

  public static void stop()
  {
    if (web != null) web.stop();
  }

  public static void start()
  {
    var threadPool = new QueuedThreadPool(MAX_THREADS, MIN_THREADS, 60_000);
    threadPool.setName("jetty");

    web = Javalin.create(config ->
    {
      config.jetty.threadPool = threadPool;

      config.staticFiles.add(sf ->
      {
        sf.hostedPath = "/phraselock-idp/js";
        sf.directory  = "/public/js";
      });
      config.staticFiles.add(sf ->
      {
        sf.hostedPath = "/phraselock-idp/css";
        sf.directory  = "/public/css";
      });
      config.staticFiles.add(sf ->
      {
        sf.hostedPath = "/img";
        sf.directory  = "/public/img";
      });

      config.routes.before(ctx ->
      {
        if (!ALLOWED_IPS.contains(ctx.ip()))
        {
          ctx.status(403).result("Forbidden");
          ctx.skipRemainingHandlers();
        }
      });

      // Register route handlers
      new WebAuthnHandler().registerRoutes(config);
      new KeePassHandler().registerRoutes(config);
      new ConfigHandler().registerRoutes(config);
    });

    web.start(PORT);
    Log.i("[PLPService] Webserver gestartet auf Port " + PORT);
  }
}
