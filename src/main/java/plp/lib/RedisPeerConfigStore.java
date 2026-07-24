package plp.lib;

import com.ipoxo.plcore.lib.Log;
import redis.clients.jedis.Jedis;

import java.util.Set;

public class RedisPeerConfigStore implements PeerConfigStore
{
  @Override
  public void writePeerConfig(String peer, String config)
  {
    try (Jedis jedis = new Jedis("localhost", 6379))
    {
      jedis.sadd(peer, config);
    }
    catch (Exception e)
    {
      Log.e("[Redis] writePeerConfig: " + e.getMessage());
    }
  }

  @Override
  public Set<String> readPeerConfig(String peer)
  {
    try (Jedis jedis = new Jedis("localhost", 6379))
    {
      return jedis.smembers(peer);
    }
    catch (Exception e)
    {
      Log.e("[Redis] readPeerConfig: " + e.getMessage());
    }
    return null;
  }
}
