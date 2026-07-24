package plp.lib;

import java.util.Set;

public interface PeerConfigStore
{
  void writePeerConfig(String peer, String config);
  Set<String> readPeerConfig(String peer);
}
