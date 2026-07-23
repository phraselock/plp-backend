package plp.provider;

import com.ipoxo.plcore.lib.Log;
import plp.psono.PsonoConfig;
import plp.psono.PsonoResult;
import plp.psono.PsonoUnrestrictedClient;

import java.util.List;
import java.util.Map;

/**
 * CredentialProvider implementation for Psono CE.
 * Wraps PsonoUnrestrictedClient including session recycling and
 * transparent re-login on expired token (HTTP 401).
 */
public class PsonoProvider implements CredentialProvider
{
  private static final String TOKEN_EXPIRED_MARKER = "HTTP 401";

  private final PsonoUnrestrictedClient client;

  public PsonoProvider(PsonoConfig config)
  {
    this.client = new PsonoUnrestrictedClient(config);
  }

  @Override
  public String getName()
  {
    return "Psono";
  }

  @Override
  public List<Map<String, Object>> fetchAllCredentials() throws Exception
  {
    ensureLoggedIn();
    var result = client.fetchAllSecrets();

    if (result.isFailed() && isTokenExpired(result))
    {
      Log.i("[" + getName() + "] Token abgelaufen — Re-Login und erneuter Versuch");
      relogin();
      result = client.fetchAllSecrets();
    }

    if (result.isFailed())
      throw new RuntimeException(getName() + ": fetchAllCredentials failed: " + result.getMessage());

    return result.getValue();
  }

  @Override
  public Map<String, Object> fetchCredentialById(String id) throws Exception
  {
    ensureLoggedIn();
    var result = client.fetchSecretById(id);

    if (result.isFailed() && isTokenExpired(result))
    {
      Log.i("[" + getName() + "] Token abgelaufen — Re-Login und erneuter Versuch");
      relogin();
      result = client.fetchSecretById(id);
    }

    if (result.isFailed())
      throw new RuntimeException(getName() + ": fetchCredentialById failed: " + result.getMessage());

    return result.getValue();
  }

  /** Logs in if no session is active yet. */
  private void ensureLoggedIn()
  {
    if (client.getToken() != null) return;
    relogin();
  }

  /** Resets the session and logs in again. */
  private void relogin()
  {
    client.logout();
    var result = client.login();
    if (result.isFailed())
      throw new RuntimeException(getName() + ": Login failed: " + result.getMessage());
    Log.i("[" + getName() + "] Login erfolgreich");
  }

  /** Returns true if the error indicates an expired token (HTTP 401). */
  private boolean isTokenExpired(PsonoResult<?> result)
  {
    return result.getMessage() != null && result.getMessage().contains(TOKEN_EXPIRED_MARKER);
  }

  /** Resets the session — next call will re-login. */
  public void logout()
  {
    client.logout();
  }
}
