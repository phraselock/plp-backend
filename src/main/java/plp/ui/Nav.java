package plp.ui;

import j2html.tags.DomContent;

import static j2html.TagCreator.*;

public class Nav
{
  public static DomContent bar(String currentPath)
  {
    return div().with(

      // ── Nav pills + Logo (same row) ─────────────────────────────────────
      div()
        .withStyle("display:flex;gap:8px;flex-wrap:wrap;margin-bottom:28px;align-items:center;")
        .with(
          tile("/admin/config",       "Config",        currentPath),
          tile("/admin/appconfig",    "Application",   currentPath),
          tile("/admin/mqttconfig",   "MQTT",          currentPath),
          tile("/admin/keepass",      "KeePass",       currentPath),
          tile("/admin/keepass-user", "KeePass Users", currentPath),
          span("UUID")
            .withStyle(
              "padding:4px 14px;border-radius:20px;font-size:12px;cursor:pointer;" +
              "border:1px dashed #aaa;background:#fff;color:#666;margin-left:6px;")
            .attr("onclick", "openUuidModal()"),
          img().withSrc("/admin/img/logo.png")
            .withAlt("iPoxo IT GmbH")
            .withStyle(
              "max-height:48px;max-width:160px;object-fit:contain;" +
              "border-radius:8px;margin-left:auto;")
        ),

      // ── UUID modal ──────────────────────────────────────────────────────
      div().withId("uuid-modal")
        .withStyle(
          "display:none;position:fixed;top:0;left:0;right:0;bottom:0;" +
          "background:rgba(0,0,0,0.4);z-index:1000;" +
          "align-items:center;justify-content:center;")
        .with(
          div()
            .withStyle(
              "background:white;border-radius:12px;padding:28px 32px;" +
              "box-shadow:0 8px 32px rgba(0,0,0,0.2);min-width:440px;")
            .with(
              div()
                .withStyle("display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;")
                .with(
                  h3("UUID Generator").withStyle("margin:0;font-size:16px;"),
                  span("x")
                    .withStyle("cursor:pointer;font-size:20px;color:#999;line-height:1;")
                    .attr("onclick", "closeUuidModal()")
                ),
              div().withId("uuid-display")
                .withStyle(
                  "font-family:monospace;font-size:15px;letter-spacing:1px;" +
                  "padding:14px;background:#f5f5f5;border:1px solid #ddd;" +
                  "border-radius:8px;text-align:center;margin-bottom:16px;"),
              div()
                .withStyle("display:flex;gap:10px;justify-content:center;")
                .with(
                  button("Generate")
                    .attr("onclick", "newUuid()")
                    .withStyle("padding:8px 22px;font-size:14px;cursor:pointer;"),
                  button("Copy").withId("uuid-copy-btn")
                    .attr("onclick", "copyUuid()")
                    .withStyle("padding:8px 22px;font-size:14px;cursor:pointer;")
                )
            )
        ),

      // ── Modal JS ────────────────────────────────────────────────────────
      script(rawHtml(
        "function openUuidModal(){" +
        "  newUuid();" +
        "  document.getElementById('uuid-modal').style.display='flex';" +
        "}" +
        "function closeUuidModal(){" +
        "  document.getElementById('uuid-modal').style.display='none';" +
        "}" +
        "function newUuid(){" +
        "  document.getElementById('uuid-display').textContent=crypto.randomUUID();" +
        "  document.getElementById('uuid-copy-btn').textContent='Copy';" +
        "}" +
        "function copyUuid(){" +
        "  var uuid=document.getElementById('uuid-display').textContent;" +
        "  navigator.clipboard.writeText(uuid).then(function(){" +
        "    var btn=document.getElementById('uuid-copy-btn');" +
        "    btn.textContent='Copied!';" +
        "    setTimeout(function(){btn.textContent='Copy';},2000);" +
        "  });" +
        "}" +
        "document.addEventListener('keydown',function(e){" +
        "  if(e.key==='Escape')closeUuidModal();" +
        "});" +
        "document.getElementById('uuid-modal').addEventListener('click',function(e){" +
        "  if(e.target===this)closeUuidModal();" +
        "});" +
        "document.addEventListener('DOMContentLoaded',function(){" +
        "  var t=(new URLSearchParams(window.location.search)).get('token');" +
        "  if(!t)return;" +
        "  document.querySelectorAll('a[href]').forEach(function(a){" +
        "    var h=a.getAttribute('href');" +
        "    if(h&&h.startsWith('/admin/')){" +
        "      var u=new URL(a.href,location.origin);" +
        "      u.searchParams.set('token',t);" +
        "      a.href=u.toString();" +
        "    }" +
        "  });" +
        "  document.querySelectorAll('form').forEach(function(f){" +
        "    var action=f.getAttribute('action')||'';" +
        "    if(action.startsWith('/admin/')){" +
        "      var u=new URL(f.action,location.origin);" +
        "      u.searchParams.set('token',t);" +
        "      f.action=u.toString();" +
        "    }" +
        "  });" +
        "});"
      ))
    );
  }

  public static DomContent footer()
  {
    int year = java.time.LocalDate.now().getYear();
    return div()
      .withStyle(
        "max-width:1024px;margin:16px auto 40px auto;" +
        "text-align:center;font-size:11px;color:#aaa;")
      .withText("© " + year + " iPoxo IT GmbH — All rights reserved");
  }

  private static DomContent tile(String href, String label, String currentPath)
  {
    boolean active = href.equals(currentPath);
    return a(label).withHref(href).withStyle(
      "padding:4px 14px;border-radius:20px;font-size:12px;text-decoration:none;" +
      "border:1px solid " + (active ? "#444" : "#bbb") + ";" +
      "background:"       + (active ? "#333" : "#f0f0f0") + ";" +
      "color:"            + (active ? "#fff" : "#555") + ";"
    );
  }
}
