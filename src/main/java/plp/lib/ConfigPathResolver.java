package plp.lib;

import java.nio.file.Files;
import java.nio.file.Path;

public class ConfigPathResolver
{
  /**
   * Resolves a file path relative to the running JAR.
   *
   * Search order:
   *   1. Next to the JAR          — e.g. /opt/plp/mqtt.properties
   *   2. Parent of JAR directory  — e.g. PLPBackend/mqtt.properties (jpackage layout)
   *   3. Working directory        — fallback for dev / IDE runs
   */
  public static Path resolve(String filename, Class<?> anchor)
  {
    try
    {
      Path jarLocation = Path.of(
        anchor.getProtectionDomain().getCodeSource().getLocation().toURI());
      Path jarDir = Files.isDirectory(jarLocation) ? jarLocation : jarLocation.getParent();

      Path p = jarDir.resolve(filename);
      if (Files.exists(p)) return p;

      if (jarDir.getParent() != null)
      {
        p = jarDir.getParent().resolve(filename);
        if (Files.exists(p)) return p;
      }
    }
    catch (Exception ignored) {}

    return Path.of(filename);
  }
}
