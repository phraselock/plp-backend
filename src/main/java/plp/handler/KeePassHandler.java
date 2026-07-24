package plp.handler;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.qrcode.QRCodeWriter;
import com.ipoxo.plcore.lib.Log;
import io.javalin.config.JavalinConfig;
import org.json.JSONArray;
import org.json.JSONObject;
import plp.lib.ConfigPathResolver;
import plp.lib.KeePassUserStore;
import plp.ui.KeePassPage;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;

public class KeePassHandler
{
  public void registerRoutes(JavalinConfig config)
  {
    // ── Page ────────────────────────────────────────────────────────────────

    config.routes.get("/admin/keepass-user", ctx ->
    {
      Properties mqttCfg    = MqttService.loadConfig();
      Properties keepassCfg = loadKeepassConfig();
      List<KeePassUserStore.User> users = KeePassUserStore.getInstance().findAll();

      KeePassUserStore.User selected = null;
      String selectParam = ctx.queryParam("select");
      if (selectParam != null)
      {
        try { selected = KeePassUserStore.getInstance().findById(Integer.parseInt(selectParam)); }
        catch (NumberFormatException ignored) {}
      }

      ctx.contentType("text/html; charset=UTF-8");
      ctx.result(KeePassPage.render(ctx, mqttCfg, keepassCfg, users, selected));
    });

    // ── Save (upsert) ────────────────────────────────────────────────────────

    config.routes.post("/admin/keepass-user/save", ctx ->
    {
      String name     = ctx.formParam("name");
      String email    = ctx.formParam("email");
      String qrLabel  = ctx.formParam("qr_label");
      String tagsRaw  = ctx.formParam("tags");

      if (name != null && email != null && !email.isBlank())
      {
        String tags = KeePassPage.linesToTags(tagsRaw != null ? tagsRaw : "");
        int id = KeePassUserStore.getInstance().upsert(
          name.trim(), email.trim(), qrLabel != null ? qrLabel.trim() : "", tags);
        Log.i("[KeePassHandler] User saved: " + email);
        ctx.redirect("/admin/keepass-user?select=" + id);
      }
      else
      {
        ctx.redirect("/admin/keepass-user");
      }
    });

    // ── Delete ───────────────────────────────────────────────────────────────

    config.routes.post("/admin/keepass-user/delete", ctx ->
    {
      String idParam = ctx.formParam("id");
      if (idParam != null)
      {
        try
        {
          KeePassUserStore.getInstance().deleteById(Integer.parseInt(idParam));
          Log.i("[KeePassHandler] User deleted: id=" + idParam);
        }
        catch (NumberFormatException ignored) {}
      }
      ctx.redirect("/admin/keepass-user");
    });

    // ── QR code ──────────────────────────────────────────────────────────────

    config.routes.get("/admin/keepass-user/qr.png", ctx ->
    {
      try
      {
        Properties mqttCfg    = MqttService.loadConfig();
        Properties keepassCfg = loadKeepassConfig();

        String name      = ctx.queryParam("name")  != null ? ctx.queryParam("name")  : "";
        String tagsParam = ctx.queryParam("tags")  != null ? ctx.queryParam("tags")  : "";

        List<String> tags = tagsParam.isBlank()
          ? List.of()
          : Arrays.stream(tagsParam.split(","))
              .map(String::trim).filter(t -> !t.isBlank())
              .collect(Collectors.toList());

        JSONObject sign = new JSONObject();
        sign.put("publ_x", mqttCfg.getProperty("bes.id.xpubl", ""));
        sign.put("publ_y", mqttCfg.getProperty("bes.id.ypubl", ""));

        JSONObject bes = new JSONObject();
        bes.put("protokol",     "KDBX_V4");
        bes.put("name",         name);
        bes.put("serveruuid",   keepassCfg.getProperty("service.uuid", ""));
        bes.put("tags",         new JSONArray(tags));
        bes.put("service_sign", sign);

        JSONObject root = new JSONObject();
        root.put("bes", bes);

        Map<EncodeHintType, Object> hints = new HashMap<>();
        hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");

        var matrix = new QRCodeWriter().encode(root.toString(), BarcodeFormat.QR_CODE, 300, 300, hints);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(matrix, "PNG", baos);

        ctx.contentType("image/png");
        ctx.result(baos.toByteArray());
      }
      catch (Exception e)
      {
        Log.e("[KeePassHandler] qr.png: " + e.getMessage());
        ctx.status(500).result(e.getMessage());
      }
    });
  }

  // ── Config ────────────────────────────────────────────────────────────────

  private Properties loadKeepassConfig()
  {
    Properties props = new Properties();
    try (InputStream in = KeePassHandler.class.getResourceAsStream("/keepass.properties"))
    {
      if (in != null) props.load(in);
    }
    catch (Exception ignored) {}

    Path external = ConfigPathResolver.resolve("keepass.properties", KeePassHandler.class);
    try
    {
      if (Files.exists(external))
        try (InputStream in = Files.newInputStream(external)) { props.load(in); }
    }
    catch (Exception ignored) {}

    return props;
  }
}
