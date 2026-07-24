package plp.ui;

import java.util.List;

import static j2html.TagCreator.*;

public class ConfigPage
{
  private static final String CARD =
    "max-width:1024px;margin:60px auto;padding:30px;" +
    "background:white;border:0.5px solid #c0c0c0;" +
    "border-radius:12px;box-shadow:0 2px 6px rgba(0,0,0,0.1);";

  private static final String FIELD =
    "padding:10px;margin-top:4px;margin-bottom:15px;" +
    "background:#fafafa;border:1px solid #ddd;border-radius:8px;";

  // ── Hub ──────────────────────────────────────────────────────────────────

  public static String renderHub()
  {
    return document(html(
      head(title("Configuration")),
      body()
        .withStyle("font-family:Arial,Helvetica,sans-serif;background-color:#f5f5f5;")
        .with(
          div().withStyle(CARD).with(
            Nav.bar("/config"),
            h1("Configuration")
              .withStyle("text-align:center;margin-bottom:40px;"),
            div().withStyle("display:flex;gap:20px;flex-wrap:wrap;justify-content:center;").with(
              tile("/admin/appconfig", "Application",
                "application.properties",
                "Port, IP allowlist, thread pool, peer config store"),
              tile("/admin/mqttconfig", "MQTT",
                "mqtt.properties",
                "Broker URL, TLS certificates, ECC signature keys"),
              tile("/admin/keepass", "KeePass",
                "keepass.properties",
                "Service UUID, database path, master password"),
              tile("/admin/keepass-user", "KeePass Users",
                "QR code generator",
                "Signature key status, name, tags, generate QR code")
            )
          ),
          Nav.footer()
        )
    ));
  }

  private static j2html.tags.DomContent tile(String href, String title, String sub, String desc)
  {
    return a().withHref(href).withStyle("text-decoration:none;color:inherit;").with(
      div()
        .withStyle(
          "width:260px;padding:24px;border:1px solid #ddd;border-radius:12px;" +
          "background:#fafafa;cursor:pointer;" +
          "box-shadow:0 1px 3px rgba(0,0,0,0.08);")
        .attr("onmouseover", "this.style.boxShadow='0 4px 12px rgba(0,0,0,0.15)'")
        .attr("onmouseout",  "this.style.boxShadow='0 1px 3px rgba(0,0,0,0.08)'")
        .with(
          h2(title).withStyle("margin:0 0 6px 0;font-size:18px;"),
          p(sub).withStyle("margin:0 0 10px 0;font-size:12px;color:#888;font-family:monospace;"),
          p(desc).withStyle("margin:0;font-size:13px;color:#555;")
        )
    );
  }

  // ── Editor ───────────────────────────────────────────────────────────────

  public static String renderEditor(
    String pageTitle,
    String filename,
    String postUrl,
    String currentPath,
    String content,
    List<String> warnings,
    boolean saved)
  {
    return document(html(
      head(title(pageTitle + " — Configuration")),
      body()
        .withStyle("font-family:Arial,Helvetica,sans-serif;background-color:#f5f5f5;")
        .with(
          div().withStyle(CARD).with(
            Nav.bar(currentPath),
            h1(pageTitle)
              .withStyle("text-align:center;margin-bottom:8px;"),
            p(filename)
              .withStyle("text-align:center;font-family:monospace;font-size:13px;color:#888;margin-top:0;margin-bottom:24px;"),

            saved && warnings.isEmpty()
              ? div("Saved successfully.")
                  .withStyle("padding:10px 14px;margin-bottom:20px;border-radius:8px;" +
                             "background:#e8f5e9;border:1px solid #a5d6a7;color:#2e7d32;font-size:14px;")
              : null,

            !warnings.isEmpty()
              ? div().withStyle(
                  "padding:12px 14px;margin-bottom:20px;border-radius:8px;" +
                  "background:#fff8e1;border:1px solid #ffe082;color:#7c5700;font-size:14px;")
                  .with(
                    b(saved ? "Saved — with warnings:" : "Warnings:"),
                    ul().withStyle("margin:8px 0 0 0;padding-left:20px;").with(
                      each(warnings, w -> li(w))
                    )
                  )
              : null,

            form().withMethod("post").withAction(postUrl).with(
              textarea().withName("content")
                .attr("rows", "24")
                .withStyle(
                  FIELD +
                  "width:calc(100% - 22px);display:block;" +
                  "font-family:monospace;font-size:13px;resize:vertical;")
                .withText(content),
              div().withStyle("text-align:center;margin-top:16px;").with(
                button("Save").withType("submit")
                  .withStyle("padding:10px 28px;font-size:14px;cursor:pointer;")
              )
            )
          ),
          Nav.footer()
        )
    ));
  }
}
