package plp.provider;

import java.util.Map;

/**
 * Repräsentiert einen eingehenden REST-Request den BridgeHandler an BES übergibt.
 */
public record RestRequest(
  String              method,
  String              path,
  Map<String, String> headers,
  String              body        // JSON als String, kann null sein
)
{}
