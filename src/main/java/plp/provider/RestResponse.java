package plp.provider;

/**
 * Repräsentiert die Antwort die BES an BridgeHandler zurückgibt.
 */
public record RestResponse(
  int    statusCode,
  String body        // JSON als String
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
