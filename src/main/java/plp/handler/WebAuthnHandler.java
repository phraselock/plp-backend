package plp.handler;

import io.javalin.config.JavalinConfig;
import plp.ui.WebAuthn;
import plp.ui.WebAuthnPage;

/**
 * Registers all WebAuthn routes: the UI entry point and the FIDO2 protocol endpoints.
 */
public class WebAuthnHandler
{
  public void registerRoutes(JavalinConfig config)
  {
    config.routes.get("/phraselock-idp/", ctx ->
    {
      ctx.contentType("text/html; charset=UTF-8");
      ctx.result(WebAuthnPage.besStart(ctx));
    });

    config.routes.post("/phraselock-idp/webauthn/register/start",  ctx ->
    {
      ctx.contentType("application/json; charset=UTF-8");
      WebAuthn.registerStart(ctx);
    });

    config.routes.post("/phraselock-idp/webauthn/register/finish", ctx ->
    {
      ctx.contentType("application/json; charset=UTF-8");
      WebAuthn.registerFinish(ctx);
    });

    config.routes.post("/phraselock-idp/webauthn/login/options",   ctx ->
    {
      ctx.contentType("application/json; charset=UTF-8");
      WebAuthn.loginOptions(ctx);
    });

    config.routes.post("/phraselock-idp/webauthn/login/verify",    ctx ->
    {
      ctx.contentType("application/json; charset=UTF-8");
      WebAuthn.loginVerify(ctx);
    });
  }
}
