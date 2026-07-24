package plp.ui;

import io.javalin.http.Context;
import plp.lib.KeePassUserStore;

import java.util.List;
import java.util.Properties;

import static j2html.TagCreator.*;

public class KeePassPage
{
  private static final String CARD =
    "max-width:1024px;margin:60px auto;padding:30px;" +
    "background:white;border:0.5px solid #c0c0c0;" +
    "border-radius:12px;box-shadow:0 2px 6px rgba(0,0,0,0.1);";

  private static final String FIELD =
    "padding:10px;margin-top:4px;margin-bottom:15px;" +
    "background:#fafafa;border:1px solid #ddd;border-radius:8px;";

  private static final String OK  = "color:#2a7a2a;";
  private static final String ERR = "color:#cc0000;";

  public static String render(
    Context ctx,
    Properties mqtt,
    Properties keepass,
    List<KeePassUserStore.User> users,
    KeePassUserStore.User selected)
  {
    String xpubl = mqtt.getProperty("bes.id.xpubl", "").trim();
    String ypubl = mqtt.getProperty("bes.id.ypubl", "").trim();
    String uuid  = keepass.getProperty("service.uuid", "").trim();

    boolean keysOk = xpubl.length() == 64 && ypubl.length() == 64;
    boolean uuidOk = uuid.length() > 10 && !uuid.contains("x");

    // Form values — pre-filled when a user is selected
    String fId       = selected != null ? String.valueOf(selected.id())       : "";
    String fName     = selected != null ? selected.name()                     : "";
    String fEmail    = selected != null ? selected.email()                    : "";
    String fQrLabel  = selected != null ? selected.qrLabel()                  : "";
    String fTags     = selected != null ? tagsToLines(selected.tags())        : "";

    return document(html(
      head(title("KeePass Users")),
      body()
        .withStyle("font-family:Arial,Helvetica,sans-serif;background-color:#f5f5f5;")
        .with(
          div().withStyle(CARD).with(

            Nav.bar("/keepass-user"),

            h1("KeePass Users").withStyle("text-align:center;margin-bottom:8px;"),

            // ── Status ──────────────────────────────────────────────────────
            div().withStyle(
              "display:flex;gap:24px;justify-content:center;font-size:13px;" +
              "margin-bottom:28px;flex-wrap:wrap;")
              .with(
                span("Signature keys: ").with(
                  span(keysOk ? "OK" : "not configured").withStyle(keysOk ? OK : ERR)),
                span("Service UUID: ").with(
                  span(uuidOk ? "OK" : "not configured").withStyle(uuidOk ? OK : ERR))
              ),

            // ── User table ───────────────────────────────────────────────
            users.isEmpty()
              ? p("No users yet.").withStyle("color:#888;font-size:13px;")
              : table()
                  .withStyle("width:100%;border-collapse:collapse;font-size:13px;margin-bottom:24px;")
                  .with(
                    thead(tr()
                      .withStyle("background:#f0f0f0;text-align:left;")
                      .with(
                        th("Name").withStyle("padding:8px 10px;"),
                        th("Email").withStyle("padding:8px 10px;"),
                        th("Tags").withStyle("padding:8px 10px;"),
                        th("Updated").withStyle("padding:8px 10px;"),
                        th("").withStyle("padding:8px 10px;")
                      )
                    ),
                    tbody().with(
                      each(users, u -> tr()
                        .withStyle(
                          "border-top:1px solid #eee;" +
                          (selected != null && selected.id() == u.id()
                            ? "background:#f5f9ff;" : ""))
                        .attr("data-name",     u.name())
                        .attr("data-qrlabel",  u.qrLabel())
                        .attr("data-tags",     u.tags())
                        .with(
                          td(u.name()).withStyle("padding:8px 10px;"),
                          td(u.email()).withStyle("padding:8px 10px;color:#555;"),
                          td(u.tags().replace(",", ", ")).withStyle("padding:8px 10px;color:#555;"),
                          td(u.updatedAt()).withStyle("padding:8px 10px;color:#aaa;font-size:12px;"),
                          td().withStyle("padding:8px 10px;white-space:nowrap;").with(
                            a("Select").withHref("/keepass-user?select=" + u.id())
                              .withStyle("margin-right:10px;font-size:12px;text-decoration:none;color:#333;"),
                            a("Clone").withHref("#")
                              .attr("onclick", "return cloneRow(this.closest('tr'))")
                              .withStyle("margin-right:10px;font-size:12px;text-decoration:none;color:#555;"),
                            form().withMethod("post").withAction("/keepass-user/delete")
                              .withStyle("display:inline;")
                              .with(
                                input().withType("hidden").withName("id").withValue(String.valueOf(u.id())),
                                button("Delete").withType("submit")
                                  .withStyle("font-size:12px;color:#cc0000;background:none;" +
                                             "border:none;cursor:pointer;padding:0;")
                                  .attr("onclick", "return confirm('Delete " + esc(u.name()) + "?')")
                              )
                          )
                        )
                      )
                    )
                  ),

            div().withStyle("display:flex;justify-content:flex-end;margin-bottom:20px;").with(
              a("+ New User").withHref("/keepass-user")
                .withStyle("font-size:13px;text-decoration:none;color:#333;" +
                           "padding:6px 14px;border:1px solid #bbb;border-radius:6px;")
            ),

            hr().withStyle("margin:0 0 28px 0;"),

            // ── Form ────────────────────────────────────────────────────────
            h3(selected != null ? "Edit User" : "New User")
              .withStyle("margin-top:0;margin-bottom:20px;"),

            form().withMethod("post").withAction("/keepass-user/save").with(

              input().withType("hidden").withName("id").withValue(fId),

              label("Name"),
              input().withType("text").withName("name").withId("f-name")
                .withValue(fName)
                .withPlaceholder("e.g. Max Mustermann")
                .withStyle(FIELD + "width:calc(100% - 22px);display:block;font-size:14px;")
                .attr("oninput", "updatePreview()"),

              label("Email"),
              input().withType("text").withName("email").withId("f-email")
                .withValue(fEmail)
                .withPlaceholder("e.g. max@company.com")
                .withStyle(FIELD + "width:calc(100% - 22px);display:block;font-size:14px;"),

              label("QR Label (name field in QR code)"),
              input().withType("text").withName("qr_label").withId("f-qrlabel")
                .withValue(fQrLabel)
                .withPlaceholder("e.g. KeePass-HMX")
                .withStyle(FIELD + "width:calc(100% - 22px);display:block;font-size:14px;")
                .attr("oninput", "updatePreview()"),

              label("Tags (one per line)"),
              textarea().withName("tags").withId("f-tags")
                .attr("rows", "4")
                .withStyle(FIELD + "width:calc(100% - 22px);display:block;font-size:14px;resize:vertical;")
                .attr("oninput", "updatePreview()")
                .withText(fTags),

              div().withStyle("display:flex;gap:10px;margin-top:4px;").with(
                button("Save").withType("submit")
                  .withStyle("padding:10px 24px;font-size:14px;cursor:pointer;"),
                button("Generate QR Code").withType("button")
                  .attr("onclick", "generateQR()")
                  .withStyle("padding:10px 24px;font-size:14px;cursor:pointer;")
              )
            ),

            // ── JSON preview + QR ──────────────────────────────────────────
            label("JSON Preview").withStyle("display:block;margin-top:24px;"),
            pre().withId("jsonPreview")
              .withStyle(FIELD + "font-size:12px;overflow-x:auto;white-space:pre-wrap;min-height:60px;"),

            div().withStyle("text-align:center;margin-top:16px;").with(
              img().withId("qrImage").withSrc("")
                .withStyle("display:none;border:1px solid #ddd;border-radius:8px;padding:10px;max-width:320px;")
            )
          ),
          script(rawHtml(buildJs(xpubl, ypubl, uuid))),
          Nav.footer()
        )
    ));
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  /** Comma-separated DB value → one tag per line for textarea display. */
  public static String tagsToLines(String tags)
  {
    if (tags == null || tags.isBlank()) return "";
    return tags.replace(",", "\n");
  }

  /** Textarea lines → comma-separated for DB storage. */
  public static String linesToTags(String lines)
  {
    if (lines == null || lines.isBlank()) return "";
    return java.util.Arrays.stream(lines.split("\n"))
      .map(String::trim).filter(s -> !s.isBlank())
      .collect(java.util.stream.Collectors.joining(","));
  }

  private static String esc(String s)
  {
    return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("'", "\\'");
  }

  private static String buildJs(String xpubl, String ypubl, String uuid)
  {
    return
      "var CFG={uuid:\"" + esc(uuid) + "\",x:\"" + esc(xpubl) + "\",y:\"" + esc(ypubl) + "\"};\n" +
      "function updatePreview(){\n" +
      "  var label=document.getElementById('f-qrlabel').value;\n" +
      "  var tagsRaw=document.getElementById('f-tags').value;\n" +
      "  var tags=tagsRaw.split('\\n').map(function(t){return t.trim();}).filter(function(t){return t.length>0;});\n" +
      "  var obj={bes:{protokol:'KDBX_V4',name:label,serveruuid:CFG.uuid,tags:tags,\n" +
      "    service_sign:{publ_x:CFG.x,publ_y:CFG.y}}};\n" +
      "  document.getElementById('jsonPreview').textContent=JSON.stringify(obj,null,2);\n" +
      "}\n" +
      "function generateQR(){\n" +
      "  var label=encodeURIComponent(document.getElementById('f-qrlabel').value);\n" +
      "  var tagsRaw=document.getElementById('f-tags').value;\n" +
      "  var tags=tagsRaw.split('\\n').map(function(t){return t.trim();}).filter(function(t){return t.length>0;});\n" +
      "  var img=document.getElementById('qrImage');\n" +
      "  img.src='/keepass-user/qr.png?name='+label+'&tags='+encodeURIComponent(tags.join(','));\n" +
      "  img.style.display='block';\n" +
      "}\n" +
      "function cloneRow(tr){\n" +
      "  document.getElementById('f-name').value=tr.dataset.name;\n" +
      "  document.getElementById('f-email').value='';\n" +
      "  document.getElementById('f-qrlabel').value=tr.dataset.qrlabel;\n" +
      "  document.getElementById('f-tags').value=tr.dataset.tags.split(',').join('\\n');\n" +
      "  document.querySelector('input[name=\"id\"]').value='';\n" +
      "  updatePreview();\n" +
      "  document.getElementById('f-email').focus();\n" +
      "  return false;\n" +
      "}\n" +
      "updatePreview();\n";
  }
}
