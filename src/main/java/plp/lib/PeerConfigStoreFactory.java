package plp.lib;

import com.ipoxo.plcore.lib.Log;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

public class PeerConfigStoreFactory
{
  private static volatile PeerConfigStore instance;

  public static PeerConfigStore getInstance()
  {
    if (instance == null)
    {
      synchronized (PeerConfigStoreFactory.class)
      {
        if (instance == null) instance = create();
      }
    }
    return instance;
  }

  private static PeerConfigStore create()
  {
    try
    {
      Properties props = new Properties();

      // 1. Bundled defaults
      try (InputStream in = PeerConfigStoreFactory.class.getResourceAsStream("/application.properties"))
      {
        if (in != null) props.load(in);
      }

      // 2. External file overrides (same location as application.properties next to JAR)
      Path external = ConfigPathResolver.resolve("application.properties", PeerConfigStoreFactory.class);
      if (Files.exists(external))
      {
        try (InputStream in = Files.newInputStream(external)) { props.load(in); }
      }

      String type = props.getProperty("peer.config.store", "redis");
      Log.i("[PeerConfigStore] Store type: " + type);

      return switch (type.toLowerCase())
      {
        case "sqlite" -> new SqlitePeerConfigStore();
        default       -> new RedisPeerConfigStore();
      };
    }
    catch (Exception e)
    {
      Log.e("[PeerConfigStore] Init failed, falling back to Redis: " + e.getMessage());
      return new RedisPeerConfigStore();
    }
  }
}
