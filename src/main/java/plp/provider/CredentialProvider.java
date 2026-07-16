package plp.provider;

import java.util.List;
import java.util.Map;

/**
 * Abstraktion für eine Credential-Quelle (z.B. Psono, zukünftige Konnektoren).
 * BES registriert Provider und delegiert Credential-Anfragen an sie.
 */
public interface CredentialProvider
{
  /** Name des Providers — für Logging und Routing. */
  String getName();

  /** Liefert alle verfügbaren Credentials. */
  List<Map<String, Object>> fetchAllCredentials() throws Exception;

  /** Liefert ein einzelnes Credential anhand seiner ID. */
  Map<String, Object> fetchCredentialById(String id) throws Exception;
}
