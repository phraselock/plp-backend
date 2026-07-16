package plp.service;

import com.ipoxo.plcore.lib.Log;
import plp.handler.MqttService;
import plp.lib.DB;
// import plp.processor.MqttProcessor;  — ersetzt durch BES/inQueue
import plp.processor.BESKeePass;
import plp.processor.BESPsono;
import plp.provider.PsonoProvider;
import plp.psono.PsonoRestrictedClient;
import plp.psono.PsonoConfig;
import plp.psono.PsonoServerConfig;
import plp.psono.PsonoUnrestrictedClient;

import java.util.*;

/*
  ACHTUNG!!! Mit

  ./gradlew shadowJar

  wird erst das nötige .jar daraus
 */

public class Main {

  public static void main(String[] args) throws Exception {

    // Database
    DB.initDB();

    // MQTT verbinden (einmalig, unabhängig von Providern)
    MqttService mqtt = MqttService.getInstance();

    // Provider initialisieren — Topics werden per Callback registriert sobald Verbindung steht
    // Welche Backends laufen, wird über service.properties (bes.*.enabled) gesteuert
    if (PLPService.isPsonoEnabled())
    {
      Log.i("[Start] Launching Psono Support");
      BESPsono.getInstance().initialize(mqtt);
    }

    if (PLPService.isKeePassEnabled())
    {
      Log.i("[Start] Launching KeePass Support");
      BESKeePass.getInstance().initialize(mqtt);
    }
    mqtt.connect();

    PLPService.start();
  }
}
