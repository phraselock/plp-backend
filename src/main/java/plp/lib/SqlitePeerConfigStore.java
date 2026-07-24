package plp.lib;

import com.ipoxo.plcore.lib.Log;

import java.nio.file.Path;
import java.sql.*;
import java.util.Set;

public class SqlitePeerConfigStore implements PeerConfigStore
{
  private static final String DB_FILE = "peer-config.db";

  private final String dbUrl;

  public SqlitePeerConfigStore()
  {
    Path dbPath = ConfigPathResolver.resolve(DB_FILE, SqlitePeerConfigStore.class);
    dbUrl = "jdbc:sqlite:" + dbPath.toAbsolutePath();
    initTable();
    Log.i("[PeerConfigStore] SQLite: " + dbPath.toAbsolutePath());
  }

  private void initTable()
  {
    try (Connection conn = DriverManager.getConnection(dbUrl);
         Statement stmt = conn.createStatement())
    {
      stmt.execute(
        "CREATE TABLE IF NOT EXISTS peer_config " +
        "(peer TEXT PRIMARY KEY, config TEXT NOT NULL)");
    }
    catch (Exception e)
    {
      Log.e("[PeerConfigStore] initTable: " + e.getMessage());
    }
  }

  @Override
  public void writePeerConfig(String peer, String config)
  {
    try (Connection conn = DriverManager.getConnection(dbUrl);
         PreparedStatement ps = conn.prepareStatement(
           "INSERT INTO peer_config(peer, config) VALUES(?,?) " +
           "ON CONFLICT(peer) DO UPDATE SET config=excluded.config"))
    {
      ps.setString(1, peer);
      ps.setString(2, config);
      ps.executeUpdate();
    }
    catch (Exception e)
    {
      Log.e("[PeerConfigStore] writePeerConfig: " + e.getMessage());
    }
  }

  @Override
  public Set<String> readPeerConfig(String peer)
  {
    try (Connection conn = DriverManager.getConnection(dbUrl);
         PreparedStatement ps = conn.prepareStatement(
           "SELECT config FROM peer_config WHERE peer=?"))
    {
      ps.setString(1, peer);
      try (ResultSet rs = ps.executeQuery())
      {
        if (rs.next()) return Set.of(rs.getString("config"));
      }
    }
    catch (Exception e)
    {
      Log.e("[PeerConfigStore] readPeerConfig: " + e.getMessage());
    }
    return null;
  }
}
