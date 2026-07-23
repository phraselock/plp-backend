package plp.backend;

import com.ipoxo.plcore.lib.Log;
import io.javalin.Javalin;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import plp.handler.UIHandler;
import plp.handler.WebAuthnHandler;

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
public class PLPService
{
  private static final String PROPERTIES = "service.properties";

  private static final Properties  CONFIG      = loadConfig();
  private static final Set<String> ALLOWED_IPS = parseAllowedIps(CONFIG);
  private static final int         PORT        = Integer.parseInt(CONFIG.getProperty("server.port", "8080"));
  private static final int         MAX_THREADS = Integer.parseInt(CONFIG.getProperty("jetty.maxThreads", "10"));
  private static final int         MIN_THREADS = Integer.parseInt(CONFIG.getProperty("jetty.minThreads", "2"));

  private static Properties loadConfig()
  {
    Properties props = new Properties();

    // 1. Bundled defaults from JAR
    try (InputStream in = PLPService.class.getResourceAsStream("/" + PROPERTIES))
    {
      if (in != null) props.load(in);
    }
    catch (IOException e)
    {
      throw new RuntimeException("Failed to load " + PROPERTIES, e);
    }

    // 2. External file (in working directory) overrides defaults
    Path external = Path.of(PROPERTIES);

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

  /** Controls whether {@code BESPsono} is initialised on startup (service.properties: bes.psono.enabled). */
  public static boolean isPsonoEnabled()
  {
    return Boolean.parseBoolean(CONFIG.getProperty("bes.psono.enabled", "true"));
  }

  /** Controls whether {@code BESKeePass} is initialised on startup (service.properties: bes.keepass.enabled). */
  public static boolean isKeePassEnabled()
  {
    return Boolean.parseBoolean(CONFIG.getProperty("bes.keepass.enabled", "true"));
  }

  public static void start()
  {
    var threadPool = new QueuedThreadPool(MAX_THREADS, MIN_THREADS, 60_000);
    threadPool.setName("jetty");

    var web = Javalin.create(config ->
    {
      config.jetty.threadPool = threadPool;
      config.router.contextPath = "/phraselock-idp";

      config.staticFiles.add(sf ->
      {
        sf.hostedPath = "/js";
        sf.directory  = "/public/js";
      });
      config.staticFiles.add(sf ->
      {
        sf.hostedPath = "/css";
        sf.directory  = "/public/css";
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
      new UIHandler().registerRoutes(config);
      new WebAuthnHandler().registerRoutes(config);
    });

    web.start(PORT);
    Log.i("[PLPService] Webserver gestartet auf Port " + PORT);
  }
}
