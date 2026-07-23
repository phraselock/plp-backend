package plp.ui;

//import j2html.tags.specialized.HtmlTag;
import io.javalin.http.Context;

import static j2html.TagCreator.*;

public class BESPage {

  public static String uiTest()
  {
    return document(
      html(
        head(
          title("WebAuthn Test"),
          link().withRel("stylesheet").withHref("/phraselock-idp/css/main.css")
        ),
      body()
        .withStyle("font-family: Arial, Helvetica, sans-serif;")
        .attr("onload", "init_ctap1lib(); init_ctap2lib();")
        .with(
          div()
            .withClass("round_boxes")
            .withStyle("padding:20px; margin:0 auto; margin-top:20px; width:980px; border:1px solid #c0c0c0;")
            .with(
              h1("WebAuthn Testseite"),
              button().withId("registerBtn").withText("Registrieren"),
              button().withId("loginBtn").withText("Login testen"),
              div().withId("output")
            )
        )
      )
    );
  }

  public static String besStart(Context ctx)
  {
    String mainTitle      = "BES Backend Testpage 2";
    String displayname    = "Jane Doe";
    String userid         = "jane.doe@yourcompany.com";

    return document(
      html(
        head(
          title(mainTitle),
          script().withSrc("/phraselock-idp/js/webauthn.js")
        ),
        body()
          .withStyle("font-family: Arial, Helvetica, sans-serif; background-color:#f5f5f5;")
          .attr("onload", "javascript:init_webauthlib(); ")
          .with(
            div() // zentrierter Container
              .withStyle(
                "max-width: 1024px;" +
                  "margin: 60px auto;" +
                  "padding: 30px;" +
                  "background: white;" +
                  "border: 0.5px solid #c0c0c0;" +
                  "border-radius: 12px;" +
                  "box-shadow: 0 2px 6px rgba(0,0,0,0.1);"
              )
              .with(
                h1(mainTitle)
                  .withStyle("text-align:center; margin-bottom:30px;"),

                div().withStyle("text-align:center;")
                  .with(

                    button("Registrieren")
                      .attr("onclick","javascript:WebAuthnLib.register();")
                      .withId("registerBtn")
                      .withStyle("padding:10px 20px; margin-right:10px;"),

                    button("Login testen")
                      .attr("onclick","javascript:WebAuthnLib.startLogin();")
                      .withId("loginBtn")
                      .withStyle("padding:10px 20px;")
                  ),

                hr().withStyle("margin:30px 0;"),

                label("Display-Name"),
                div().withId("displayname")
                  .withStyle(
                    "min-height:16px;" +
                      "padding:10px;" +
                      "margin-top:4px;"  +
                      "margin-bottom:15px;" +
                      "background:#fafafa;" +
                      "border:1px solid #ddd;" +
                      "border-radius:8px;"
                  )
                  .attr("contenteditable", "true")
                  .withText(displayname),

                label("User"),
                div().withId("user")
                  .withStyle(
                    "min-height:16px;" +
                      "padding:10px;" +
                      "margin-top:4px;"  +
                      "margin-bottom:15px;" +
                      "background:#fafafa;" +
                      "border:1px solid #ddd;" +
                      "border-radius:8px;"
                  )
                  .attr("contenteditable", "true")
                  .withText(userid),

                label("host / RP-ID"),
                div().withId("rpid")
                  .withStyle(
                    "min-height:16px;" +
                      "padding:10px;" +
                      "margin-top:4px;"  +
                      "margin-bottom:15px;" +
                      "background:#fafafa;" +
                      "border:1px solid #ddd;" +
                      "border-radius:8px;"
                  )
                  .attr("contenteditable", "true")
                  .withText(ctx.host().split(":")[0]),

                label("Output"),
                div().withId("output")
                  .withStyle(
                    "min-height:40px;" +
                      "padding:10px;" +
                      "margin-top:4px;"  +
                      "margin-bottom:15px;" +
                      "background:#fafafa;" +
                      "border:1px solid #ddd;" +
                      "border-radius:8px;"
                  )


              )
          )
      )
    );
  }



}
