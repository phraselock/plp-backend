package plp.handler;

import io.javalin.config.JavalinConfig;
import plp.ui.WebAuthn;

/**
 * Handles FIDO2/WebAuthn credential service routes ( "/webauthn/*" ).
 * Covers the full registration and authentication flow.
 */
public class WebAuthnHandler {

  public void registerRoutes(JavalinConfig config) {
    config.routes.post("/webauthn/register/start",  ctx -> {
      ctx.contentType("application/json; charset=UTF-8");
      WebAuthn.registerStart(ctx);
    });

    config.routes.post("/webauthn/register/finish", ctx -> {
      ctx.contentType("application/json; charset=UTF-8");
      WebAuthn.registerFinish(ctx);
    });

    config.routes.post("/webauthn/login/options",   ctx -> {
      ctx.contentType("application/json; charset=UTF-8");
      WebAuthn.loginOptions(ctx);
    });

    config.routes.post("/webauthn/login/verify",    ctx -> {
      ctx.contentType("application/json; charset=UTF-8");
      WebAuthn.loginVerify(ctx);
    });
  }
}
