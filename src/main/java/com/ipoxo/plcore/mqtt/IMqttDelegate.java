package com.ipoxo.plcore.mqtt;

public interface IMqttDelegate
{
  
  public default void mqttConnectionClosedOrError() {}
  public default void mqttStartMqttConnection() {}
  public default void mqttConnectionEstablished() {}
  public default void mqttSubscribtionComplet(short  mid) {}
  public default void mqttConnectionError(long error, String message) {}
  public default void mqttMessagePublished() {}
  public default void mqttMessagePublishedComplet(short  mid) {}
  public default void mqttSendAutoResponse(byte[] data) {}
  public default void mqttReceiveRawMessage(byte[] data) {}
  public default void mqttReceivePayload(byte[] topic, byte[] data,  short mid) {}
  
}
