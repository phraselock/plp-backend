package plp.lib;

import com.ipoxo.plcore.lib.Log;
import redis.clients.jedis.Jedis;

import java.util.Set;

public class Redis
{
  public static void writePeerConfig(String peer, String config)
  {
    try (Jedis jedis = new Jedis("localhost", 6379))
    {
      // Set
      jedis.sadd(peer, config);
    }
    catch (Exception e)
    {
      Log.e("[Redis] writePeerConfig: " + e.getMessage());
    }
  }

  public static Set<String> readPeerConfig(String peer)
  {
    try (Jedis jedis = new Jedis("localhost", 6379))
    {
      // Read
      Set<String> children = jedis.smembers(peer);
      return children;
    }
    catch (Exception e)
    {
      Log.e("[Redis] readPeerConfig: " + e.getMessage());
    }
    return null;
  }

}
