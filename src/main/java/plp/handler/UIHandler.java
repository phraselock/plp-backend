package plp.handler;

import io.javalin.config.JavalinConfig;
import plp.ui.BESPage;

/**
 * Handles UI routes ( "/" ).
 * Entry point for the user-facing web interface.
 */
public class UIHandler {

  public void registerRoutes(JavalinConfig config) {
    config.routes.get("/", ctx -> {
      ctx.contentType("text/html; charset=UTF-8");
      ctx.result(BESPage.besStart(ctx));
    });
  }
}
