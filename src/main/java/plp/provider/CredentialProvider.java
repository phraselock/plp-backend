package plp.provider;

import java.util.List;
import java.util.Map;

/**
 * Abstraction for a credential source (e.g. Psono, future connectors).
 * BES registers providers and delegates credential requests to them.
 */
public interface CredentialProvider
{
  /** Name of the provider — used for logging and routing. */
  String getName();

  /** Returns all available credentials. */
  List<Map<String, Object>> fetchAllCredentials() throws Exception;

  /** Returns a single credential by its ID. */
  Map<String, Object> fetchCredentialById(String id) throws Exception;
}
