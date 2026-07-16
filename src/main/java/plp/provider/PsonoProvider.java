package plp.provider;

import com.ipoxo.plcore.lib.Log;
import plp.psono.PsonoConfig;
import plp.psono.PsonoResult;
import plp.psono.PsonoUnrestrictedClient;

import java.util.List;
import java.util.Map;

/**
 * CredentialProvider-Implementierung für Psono CE.
 * Kapselt PsonoUnrestrictedClient inkl. Session-Recycling und
 * transparentem Re-Login bei abgelaufenem Token (HTTP 401).
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

  /** Loggt ein falls noch keine Session aktiv. */
  private void ensureLoggedIn()
  {
    if (client.getToken() != null) return;
    relogin();
  }

  /** Setzt die Session zurück und loggt neu ein. */
  private void relogin()
  {
    client.logout();
    var result = client.login();
    if (result.isFailed())
      throw new RuntimeException(getName() + ": Login failed: " + result.getMessage());
    Log.i("[" + getName() + "] Login erfolgreich");
  }

  /** Prüft ob der Fehler auf einen abgelaufenen Token hindeutet (HTTP 401). */
  private boolean isTokenExpired(PsonoResult<?> result)
  {
    return result.getMessage() != null && result.getMessage().contains(TOKEN_EXPIRED_MARKER);
  }

  /** Setzt die Session zurück — nächster Aufruf loggt neu ein. */
  public void logout()
  {
    client.logout();
  }
}
