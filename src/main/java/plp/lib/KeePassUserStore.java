package plp.lib;

import com.ipoxo.plcore.lib.Log;

import java.nio.file.Path;
import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class KeePassUserStore
{
  private static final String DB_FILE = "keepass-users.db";
  private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

  private final String dbUrl;

  private static KeePassUserStore instance;

  public static synchronized KeePassUserStore getInstance()
  {
    if (instance == null) instance = new KeePassUserStore();
    return instance;
  }

  public record User(int id, String name, String email, String qrLabel, String tags, String updatedAt) {}

  private KeePassUserStore()
  {
    Path dbPath = ConfigPathResolver.resolve(DB_FILE, KeePassUserStore.class);
    dbUrl = "jdbc:sqlite:" + dbPath.toAbsolutePath();
    initTable();
    Log.i("[KeePassUserStore] SQLite: " + dbPath.toAbsolutePath());
  }

  private void initTable()
  {
    try (Connection conn = DriverManager.getConnection(dbUrl);
         Statement stmt = conn.createStatement())
    {
      stmt.execute("""
        CREATE TABLE IF NOT EXISTS keepass_users (
          id         INTEGER PRIMARY KEY AUTOINCREMENT,
          name       TEXT NOT NULL,
          email      TEXT NOT NULL UNIQUE,
          qr_label   TEXT NOT NULL DEFAULT '',
          tags       TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )
      """);
    }
    catch (Exception e) { Log.e("[KeePassUserStore] initTable: " + e.getMessage()); }
  }

  /** Inserts or updates a user by email. Returns the row id, or -1 on error. */
  public int upsert(String name, String email, String qrLabel, String tags)
  {
    String now = LocalDateTime.now().format(FMT);
    try (Connection conn = DriverManager.getConnection(dbUrl))
    {
      try (PreparedStatement ps = conn.prepareStatement("""
        INSERT INTO keepass_users (name, email, qr_label, tags, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(email) DO UPDATE SET
          name       = excluded.name,
          qr_label   = excluded.qr_label,
          tags       = excluded.tags,
          updated_at = excluded.updated_at
      """))
      {
        ps.setString(1, name);
        ps.setString(2, email);
        ps.setString(3, qrLabel);
        ps.setString(4, tags);
        ps.setString(5, now);
        ps.setString(6, now);
        ps.executeUpdate();
      }
      try (PreparedStatement q = conn.prepareStatement(
          "SELECT id FROM keepass_users WHERE email = ?"))
      {
        q.setString(1, email);
        try (ResultSet rs = q.executeQuery())
        {
          if (rs.next()) return rs.getInt("id");
        }
      }
    }
    catch (Exception e) { Log.e("[KeePassUserStore] upsert: " + e.getMessage()); }
    return -1;
  }

  public List<User> findAll()
  {
    List<User> list = new ArrayList<>();
    try (Connection conn = DriverManager.getConnection(dbUrl);
         PreparedStatement ps = conn.prepareStatement(
           "SELECT id, name, email, qr_label, tags, updated_at FROM keepass_users ORDER BY name"))
    {
      try (ResultSet rs = ps.executeQuery())
      {
        while (rs.next())
          list.add(new User(rs.getInt("id"), rs.getString("name"), rs.getString("email"),
                            rs.getString("qr_label"), rs.getString("tags"), rs.getString("updated_at")));
      }
    }
    catch (Exception e) { Log.e("[KeePassUserStore] findAll: " + e.getMessage()); }
    return list;
  }

  public User findById(int id)
  {
    try (Connection conn = DriverManager.getConnection(dbUrl);
         PreparedStatement ps = conn.prepareStatement(
           "SELECT id, name, email, qr_label, tags, updated_at FROM keepass_users WHERE id = ?"))
    {
      ps.setInt(1, id);
      try (ResultSet rs = ps.executeQuery())
      {
        if (rs.next())
          return new User(rs.getInt("id"), rs.getString("name"), rs.getString("email"),
                          rs.getString("qr_label"), rs.getString("tags"), rs.getString("updated_at"));
      }
    }
    catch (Exception e) { Log.e("[KeePassUserStore] findById: " + e.getMessage()); }
    return null;
  }

  public void deleteById(int id)
  {
    try (Connection conn = DriverManager.getConnection(dbUrl);
         PreparedStatement ps = conn.prepareStatement("DELETE FROM keepass_users WHERE id = ?"))
    {
      ps.setInt(1, id);
      ps.executeUpdate();
    }
    catch (Exception e) { Log.e("[KeePassUserStore] deleteById: " + e.getMessage()); }
  }
}
