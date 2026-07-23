package plp.provider;

/**
 * Represents the response BES returns to BridgeHandler.
 */
public record RestResponse(
  int    statusCode,
  String body        // JSON as string
)
{
  public static RestResponse ok(String body)
  {
    return new RestResponse(200, body);
  }

  public static RestResponse error(int statusCode, String message)
  {
    return new RestResponse(statusCode, "{\"error\":\"" + message + "\"}");
  }
}
