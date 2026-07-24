package plp.backend;

import com.ipoxo.plcore.lib.Log;
import plp.handler.MqttService;
import plp.lib.DB;
import plp.processor.BESKeePass;
import plp.processor.BESPsono;

/*
  ./gradlew shadowJar
 */

public class Main {

  public static void main(String[] args) throws Exception {

    // Database
    DB.initDB();

    // Connect MQTT once — independent of providers
    MqttService mqtt = MqttService.getInstance();

    Runtime.getRuntime().addShutdownHook(new Thread(() ->
    {
      Log.i("[Shutdown] Stopping...");
      PLPApplication.stop();
      mqtt.disconnect();
      Log.i("[Shutdown] Done.");
    }, "shutdown"));

    if (PLPApplication.isKeePassEnabled())
    {
      Log.i("[Start] Launching KeePass Support");
      BESKeePass.getInstance().initialize(mqtt);
    }

    if (PLPApplication.isPsonoEnabled())
    {
      Log.i("[Start] Launching Psono Support");
      BESPsono.getInstance().initialize(mqtt);
    }

    mqtt.connect();

    PLPApplication.start();
  }
}
