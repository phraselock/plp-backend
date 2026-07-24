package plp.handler;

import com.ipoxo.plcore.lib.Log;
import io.javalin.config.JavalinConfig;
import plp.lib.ConfigPathResolver;
import plp.ui.ConfigPage;

import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class ConfigHandler
{
  public void registerRoutes(JavalinConfig config)
  {
    config.routes.get("/admin/config", ctx ->
    {
      ctx.contentType("text/html; charset=UTF-8");
      ctx.result(ConfigPage.renderHub());
    });

    // ── application.properties ────────────────────────────────────────────

    config.routes.get("/admin/appconfig", ctx ->
    {
      ctx.contentType("text/html; charset=UTF-8");
      ctx.result(ConfigPage.renderEditor(
        "Application", "application.properties", "/admin/appconfig", "/admin/appconfig",
        readFile("application.properties"), List.of(), false));
    });

    config.routes.post("/admin/appconfig", ctx ->
    {
      String content = ctx.formParam("content");
      List<String> w = new ArrayList<>();
      boolean saved  = false;

      if (content != null)
      {
        w.addAll(validateApplication(parse(content)));
        writeFile("application.properties", content);
        saved = true;
        Log.i("[ConfigHandler] application.properties saved");
      }

      ctx.contentType("text/html; charset=UTF-8");
      ctx.result(ConfigPage.renderEditor(
        "Application", "application.properties", "/admin/appconfig", "/admin/appconfig",
        content != null ? content : "", w, saved));
    });

    // ── keepass.properties ────────────────────────────────────────────────

    config.routes.get("/admin/keepass", ctx ->
    {
      ctx.contentType("text/html; charset=UTF-8");
      ctx.result(ConfigPage.renderEditor(
        "KeePass", "keepass.properties", "/admin/keepass", "/admin/keepass",
        readFile("keepass.properties"), List.of(), false));
    });

    config.routes.post("/admin/keepass", ctx ->
    {
      String content = ctx.formParam("content");
      List<String> w = new ArrayList<>();
      boolean saved  = false;

      if (content != null)
      {
        w.addAll(validateKeepass(parse(content)));
        writeFile("keepass.properties", content);
        saved = true;
        Log.i("[ConfigHandler] keepass.properties saved");
      }

      ctx.contentType("text/html; charset=UTF-8");
      ctx.result(ConfigPage.renderEditor(
        "KeePass", "keepass.properties", "/admin/keepass", "/admin/keepass",
        content != null ? content : "", w, saved));
    });

    // ── mqtt.properties ───────────────────────────────────────────────────

    config.routes.get("/admin/mqttconfig", ctx ->
    {
      ctx.contentType("text/html; charset=UTF-8");
      ctx.result(ConfigPage.renderEditor(
        "MQTT", "mqtt.properties", "/admin/mqttconfig", "/admin/mqttconfig",
        readFile("mqtt.properties"), List.of(), false));
    });

    config.routes.post("/admin/mqttconfig", ctx ->
    {
      String content = ctx.formParam("content");
      List<String> w = new ArrayList<>();
      boolean saved  = false;

      if (content != null)
      {
        w.addAll(validateMqtt(parse(content)));
        writeFile("mqtt.properties", content);
        saved = true;
        Log.i("[ConfigHandler] mqtt.properties saved");
      }

      ctx.contentType("text/html; charset=UTF-8");
      ctx.result(ConfigPage.renderEditor(
        "MQTT", "mqtt.properties", "/admin/mqttconfig", "/admin/mqttconfig",
        content != null ? content : "", w, saved));
    });
  }

  // ── File I/O ──────────────────────────────────────────────────────────────

  private String readFile(String filename)
  {
    Path path = ConfigPathResolver.resolve(filename, ConfigHandler.class);
    try
    {
      if (Files.exists(path)) return Files.readString(path);
    }
    catch (Exception e) { Log.e("[ConfigHandler] Read failed: " + e.getMessage()); }
    return "";
  }

  private void writeFile(String filename, String content)
  {
    Path path = ConfigPathResolver.resolve(filename, ConfigHandler.class);
    try { Files.writeString(path, content); }
    catch (Exception e) { Log.e("[ConfigHandler] Write failed: " + e.getMessage()); }
  }

  // ── Parsing ───────────────────────────────────────────────────────────────

  private Properties parse(String content)
  {
    Properties p = new Properties();
    try { p.load(new StringReader(content)); }
    catch (Exception ignored) {}
    return p;
  }

  // ── Validation ────────────────────────────────────────────────────────────

  private List<String> validateApplication(Properties p)
  {
    List<String> w = new ArrayList<>();

    String port = p.getProperty("server.port", "").trim();
    if (!port.matches("\\d+") || Integer.parseInt(port) < 1 || Integer.parseInt(port) > 65535)
      w.add("server.port: not a valid port number (1–65535)");

    String ips = p.getProperty("allowed.ips", "").trim();
    if (ips.isBlank())
      w.add("allowed.ips: no IPs configured — all requests will be rejected");

    String store = p.getProperty("peer.config.store", "").trim().toLowerCase();
    if (!store.equals("redis") && !store.equals("sqlite"))
      w.add("peer.config.store: unknown value \"" + store + "\" — expected: redis | sqlite");

    if (p.getProperty("admin.token", "").trim().isEmpty())
      w.add("admin.token: not set — /admin/* routes are unprotected");

    String minT = p.getProperty("jetty.minThreads", "").trim();
    String maxT = p.getProperty("jetty.maxThreads", "").trim();
    if (minT.matches("\\d+") && maxT.matches("\\d+") && Integer.parseInt(minT) > Integer.parseInt(maxT))
      w.add("jetty.minThreads (" + minT + ") > jetty.maxThreads (" + maxT + ")");

    return w;
  }

  private List<String> validateKeepass(Properties p)
  {
    List<String> w = new ArrayList<>();

    String file = p.getProperty("keepass.file", "").trim();
    if (file.isBlank() || file.contains("<") || file.contains("your"))
      w.add("keepass.file: not configured");

    String password = p.getProperty("keepass.password", "").trim();
    if (password.isBlank() || password.contains("<"))
      w.add("keepass.password: not configured");

    String uuid = p.getProperty("service.uuid", "").trim();
    if (!uuid.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"))
      w.add("service.uuid: not a valid UUID");

    return w;
  }

  private List<String> validateMqtt(Properties p)
  {
    List<String> w = new ArrayList<>();

    String url = p.getProperty("broker.url", "").trim();
    if (url.isBlank() || url.contains("<") || url.contains("your"))
      w.add("broker.url: not configured");

    String xpubl = p.getProperty("bes.id.xpubl", "").trim();
    String ypubl = p.getProperty("bes.id.ypubl", "").trim();
    String dpriv = p.getProperty("bes.id.dpriv", "").trim();

    if (!xpubl.matches("[0-9a-fA-F]{64}"))
      w.add("bes.id.xpubl: not a valid 64-character hex value");
    if (!ypubl.matches("[0-9a-fA-F]{64}"))
      w.add("bes.id.ypubl: not a valid 64-character hex value");
    if (!dpriv.matches("[0-9a-fA-F]{64}"))
      w.add("bes.id.dpriv: not a valid 64-character hex value");

    if (url.startsWith("ssl://"))
    {
      if (p.getProperty("tls.client.cert", "").trim().isBlank())
        w.add("SSL connection: tls.client.cert is missing");
      if (p.getProperty("tls.client.key", "").trim().isBlank())
        w.add("SSL connection: tls.client.key is missing");
    }

    return w;
  }
}
